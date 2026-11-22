# Can the DPoP private key be copied?

Nov 21, 2026 · @Sreenath

## Solution overview

Bind each session to a key that stays in the browser (DPoP, RFC 9449), so a bearer token copied from localStorage is useless on another machine. The bearer token and its Apigee validation stay exactly as they are today. The browser adds a signed proof header to every call, and the backend checks it against the key recorded for the session. The server never sees the private key.

1. The browser generates an ECDSA P-256 key pair with a non-extractable private key and stores it in IndexedDB.
2. At `/auth/exchange`, the browser sends the single-use Melio handoff token plus a DPoP proof (a signed JWT carrying the public key).
3. The API verifies the proof, consumes the handoff token, and issues the access token as it does today. It also records the key's thumbprint against the session id (`dpop:bind:{sid}` in Redis). If your token issuer can add a `cnf.jkt` claim, the thumbprint can live in the token instead.
4. Every API call keeps `Authorization: Bearer <token>`, which Apigee validates as today, and adds a fresh `DPoP` header carrying a proof bound to the method, URL and token hash.
5. The backend checks the proof signature, `htm`, `htu`, `iat` (within 60 seconds), `ath`, a single-use `jti`, and that the proof's key thumbprint equals the one bound to the token's session.
6. Renewal also requires a proof, and the session has an absolute lifetime so a stolen token cannot renew forever.
7. High-risk actions add a step-up confirmation (see below), because a bound key can still be used by someone controlling the same browser.

The Melio handoff token remains the root of trust: it is validated once, at exchange, and its subject and session id are carried into the access token.

## API changes 1: proof validator

One shared validator checks every DPoP proof, so `/auth/exchange`, renew and normal endpoints all use the same rules. This code is a sketch: check the `Microsoft.IdentityModel` calls against the package versions you use.

Configuration, with a mode so you can roll out in report-only first:

```csharp
public enum DpopMode { Off, Report, Enforce }

public sealed class DpopOptions
{
    public DpopMode Mode { get; set; } = DpopMode.Enforce;
    // Public URL clients sign, e.g. https://api.example.com (not the internal ACA host)
    public string PublicBaseUrl { get; set; } = "";
    public int ProofMaxAgeSeconds { get; set; } = 60;
    public int MaxSessionMinutes { get; set; } = 60;
}
```

The validator:

```csharp
public sealed record DpopResult(bool Ok, string? Jkt, string? Error);

public sealed class DpopProofValidator(IConnectionMultiplexer redis, IOptions<DpopOptions> opts)
{
    private static readonly JsonWebTokenHandler Handler = new();

    public async Task<DpopResult> ValidateAsync(
        string? proof, string method, string url, string? accessToken)
    {
        if (string.IsNullOrWhiteSpace(proof)) return Fail("missing_proof");

        JsonWebToken jwt;
        try { jwt = Handler.ReadJsonWebToken(proof); }
        catch { return Fail("malformed"); }

        if (jwt.Typ != "dpop+jwt" || jwt.Alg != SecurityAlgorithms.EcdsaSha256)
            return Fail("bad_header");

        if (!jwt.TryGetHeaderValue<JsonElement>("jwk", out var jwkEl)) return Fail("no_jwk");
        var jwk = new JsonWebKey(jwkEl.GetRawText());
        if (jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.HasPrivateKey) return Fail("bad_jwk");

        // Signature is checked with the public key carried in the proof itself
        var result = await Handler.ValidateTokenAsync(proof, new TokenValidationParameters
        {
            IssuerSigningKey = jwk,
            ValidTypes = ["dpop+jwt"],
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
        });
        if (!result.IsValid) return Fail("bad_signature");

        // Bound to this request
        if (!jwt.TryGetPayloadValue<string>("htm", out var htm) || htm != method) return Fail("htm");
        if (!jwt.TryGetPayloadValue<string>("htu", out var htu) || htu != url) return Fail("htu");

        // Fresh
        if (!jwt.TryGetPayloadValue<long>("iat", out var iat)) return Fail("iat");
        var age = Math.Abs((DateTimeOffset.UtcNow - DateTimeOffset.FromUnixTimeSeconds(iat)).TotalSeconds);
        if (age > opts.Value.ProofMaxAgeSeconds) return Fail("stale");

        // Bound to this access token (absent only at /auth/exchange)
        if (accessToken is not null)
        {
            var ath = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
            if (!jwt.TryGetPayloadValue<string>("ath", out var claimed) || claimed != ath) return Fail("ath");
        }

        var jkt = Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint());

        // Replay: each proof id is usable once
        if (!jwt.TryGetPayloadValue<string>("jti", out var jti) || string.IsNullOrEmpty(jti)) return Fail("jti");
        var fresh = await redis.GetDatabase().StringSetAsync(
            $"dpop:jti:{jkt}:{jti}", "1", TimeSpan.FromSeconds(opts.Value.ProofMaxAgeSeconds * 2), When.NotExists);
        if (!fresh) return Fail("replay");

        return new DpopResult(true, jkt, null);
    }

    private static DpopResult Fail(string e) => new(false, null, e);
}
```

Register it with `builder.Services.Configure<DpopOptions>(builder.Configuration.GetSection("Dpop"))` and `AddSingleton<DpopProofValidator>()`. Compare `htu` against `PublicBaseUrl + request path` (no query string), never `Request.Host`, because Apigee, Front Door or the container app ingress can change the host.

## API changes 2: exchange and renew

The binding is created at `/auth/exchange` and stored on the server against the session id, so the access token and the Apigee validation stay exactly as they are today. Alternative: if your token issuer can add a `cnf` claim holding the key thumbprint, bind inside the token instead and skip the Redis store.

Exchange: verify the proof first, consume the handoff token once, then bind.

```csharp
public sealed class ExchangeEndpoint(
    DpopProofValidator dpop,
    SessionKeyBinding bindings,
    IHandoffTokenStore handoffs,   // Redis SET NX on the handoff jti
    IAccessTokenIssuer issuer,     // your existing issuance (Ping or your own service)
    IOptions<DpopOptions> opts) : Endpoint<ExchangeRequest, ExchangeResponse>
{
    public override void Configure() { Post("/auth/exchange"); AllowAnonymous(); }

    public override async Task HandleAsync(ExchangeRequest req, CancellationToken ct)
    {
        var url = opts.Value.PublicBaseUrl + HttpContext.Request.Path;
        var proof = HttpContext.Request.Headers["DPoP"].ToString();

        var check = await dpop.ValidateAsync(proof, "POST", url, accessToken: null);
        if (!check.Ok) { await SendUnauthorizedAsync(ct); return; }

        var handoff = await handoffs.ConsumeAsync(req.HandoffToken, ct); // null if invalid or already used
        if (handoff is null) { await SendUnauthorizedAsync(ct); return; }

        // Record the key BEFORE the token reaches the browser; the first bind wins
        if (!await bindings.BindAsync(handoff.SessionId, check.Jkt!))
        { await SendUnauthorizedAsync(ct); return; }

        var token = issuer.Issue(new AccessTokenSpec(
            Subject: handoff.Subject,
            SessionId: handoff.SessionId,
            SessionStart: DateTimeOffset.UtcNow,   // becomes sst, caps total session life
            Lifetime: TimeSpan.FromMinutes(10)));

        await SendAsync(new ExchangeResponse(token, "Bearer", 600), cancellation: ct);
    }
}
```

The binding store. The first bind for a session wins and a second attempt is refused, so a thief cannot swap in their own key later:

```csharp
public sealed class SessionKeyBinding(IConnectionMultiplexer redis, IOptions<DpopOptions> opts)
{
    private static string Key(string sid) => $"dpop:bind:{sid}";

    public Task<bool> BindAsync(string sid, string jkt) =>
        redis.GetDatabase().StringSetAsync(Key(sid), jkt,
            TimeSpan.FromMinutes(opts.Value.MaxSessionMinutes + 10), When.NotExists);

    public async Task<string?> GetAsync(string sid) =>
        (string?)await redis.GetDatabase().StringGetAsync(Key(sid));
}
```

In the issuer, keep your existing claims and make sure the token carries a session id and a session start. The binding is keyed on `sid`, so it must be the same value on every renewed token. If your tokens have no `sid` yet, add one at issuance:

```csharp
var claims = new Dictionary<string, object>
{
    ["sub"] = spec.Subject,
    ["sid"] = spec.SessionId,                           // the key binding is looked up by this
    ["sst"] = spec.SessionStart.ToUnixTimeSeconds(),    // session start, caps total lifetime
};
// Optional, only if you also want the binding inside the token:
// claims["cnf"] = new Dictionary<string, string> { ["jkt"] = jkt };
```

Renew: a protected endpoint. The pre-processor (next section) has already checked the proof against the key bound to this session, so only the key holder can renew. The binding is stored under the same `sid`, so it carries over to the renewed token. Renewal only has to enforce the session cap.

```csharp
public sealed class RenewEndpoint(IAccessTokenIssuer issuer, IOptions<DpopOptions> opts)
    : EndpointWithoutRequest<ExchangeResponse>
{
    public override void Configure() => Post("/auth/renew");

    public override async Task HandleAsync(CancellationToken ct)
    {
        var sst = DateTimeOffset.FromUnixTimeSeconds(long.Parse(User.FindFirstValue("sst")!));
        if (DateTimeOffset.UtcNow - sst > TimeSpan.FromMinutes(opts.Value.MaxSessionMinutes))
        { await SendUnauthorizedAsync(ct); return; }   // user must come back through Melio

        var token = issuer.Issue(new AccessTokenSpec(
            User.FindFirstValue("sub")!, User.FindFirstValue("sid")!, sst, TimeSpan.FromMinutes(10)));

        await SendAsync(new ExchangeResponse(token, "Bearer", 600), cancellation: ct);
    }
}
```

`sst` is carried forward unchanged, which is what makes the absolute cap work. Renewal never extends it.

## API changes 3: enforcing on every endpoint

A global pre-processor runs the validator on every authenticated request, so you do not add it endpoint by endpoint. Nothing changes in the bearer handling: Apigee validates the Bearer token as it does today, and the backend keeps its existing JWT settings, so you do not need to teach it a new authorization scheme.

The global pre-processor (FastEndpoints `IGlobalPreProcessor`):

```csharp
public sealed class DpopPreProcessor(
    DpopProofValidator dpop,
    SessionKeyBinding bindings,
    IOptions<DpopOptions> opts,
    ILogger<DpopPreProcessor> log) : IGlobalPreProcessor
{
    public async Task PreProcessAsync(IPreProcessorContext ctx, CancellationToken ct)
    {
        var http = ctx.HttpContext;
        var mode = opts.Value.Mode;
        if (mode == DpopMode.Off) return;
        if (http.User.Identity?.IsAuthenticated != true) return;   // anonymous endpoints (exchange has its own check)

        var reason = await CheckAsync(http);
        if (reason is null) return;

        log.LogWarning("DPoP check failed: {Reason} sub={Sub} path={Path} ip={Ip}",
            reason, http.User.FindFirstValue("sub"), http.Request.Path, http.Connection.RemoteIpAddress);

        if (mode == DpopMode.Enforce) await http.Response.SendUnauthorizedAsync(ct);
    }

    private async Task<string?> CheckAsync(HttpContext http)
    {
        var auth = http.Request.Headers.Authorization.ToString();
        if (!auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return "no_bearer";
        var token = auth[7..].Trim();

        // Which key is this session bound to?
        var sid = http.User.FindFirstValue("sid");
        if (sid is null) return "no_sid";
        var boundJkt = await bindings.GetAsync(sid);
        if (boundJkt is null) return "session_not_bound";

        var url = opts.Value.PublicBaseUrl + http.Request.Path;   // no query string
        var r = await dpop.ValidateAsync(http.Request.Headers["DPoP"], http.Request.Method, url, token);
        if (!r.Ok) return r.Error;

        return r.Jkt == boundJkt ? null : "key_mismatch";
        // If the token also carries cnf.jkt, compare it here too.
    }
}
```

Register it with `app.UseFastEndpoints(c => c.Endpoints.Configurator = ep => ep.PreProcessor<DpopPreProcessor>(Order.Before))`, or the global-processor option your FastEndpoints version provides. `Report` mode logs failures without blocking, which is how you find broken clients before turning on `Enforce`.

Keep your existing ownership check (the business user must own the AllData account) as a second gate. DPoP proves who is calling; the ownership check proves they are allowed to change this account. Log `sub`, key thumbprint, IP and user agent on category updates so a token used from a second device stands out.

## TypeScript changes 1: key and proof

The browser creates a non-extractable key pair, keeps it in IndexedDB, and signs a proof per request. Create a fresh key pair for every new session (every Melio handoff), so an old key never outlives its token. Both frames share the key because IndexedDB is per origin.

This module uses `idb-keyval` to store the `CryptoKey` objects (they survive structured cloning). Check the sketch against your build before shipping.

```ts
// dpop.ts
import { get, set, del } from "idb-keyval";

const KEY_ID = "cfc-dpop-keypair";

const b64url = (data: ArrayBuffer | string): string => {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : new Uint8Array(data);
  let s = "";
  bytes.forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

/** Call at the start of every new session (before /auth/exchange). */
export async function createKeyPair(): Promise<CryptoKeyPair> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,          // private key is non-extractable; the public key is always exportable
    ["sign"],
  );
  await set(KEY_ID, pair);
  return pair;
}

export async function getKeyPair(): Promise<CryptoKeyPair> {
  return (await get<CryptoKeyPair>(KEY_ID)) ?? (await createKeyPair());
}

export async function clearKeyPair(): Promise<void> {
  await del(KEY_ID);
}

/** Only the required members, so the server's thumbprint matches. */
async function publicJwk(pair: CryptoKeyPair) {
  const { kty, crv, x, y } = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return { kty, crv, x, y };
}

/** Build a DPoP proof for one request. accessToken is omitted at /auth/exchange. */
export async function buildProof(
  method: string,
  url: string,
  accessToken?: string,
): Promise<string> {
  const pair = await getKeyPair();
  const cleanUrl = url.split(/[?#]/)[0];            // htu has no query string or fragment

  const header = { typ: "dpop+jwt", alg: "ES256", jwk: await publicJwk(pair) };
  const payload: Record<string, unknown> = {
    htm: method.toUpperCase(),
    htu: cleanUrl,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
  };
  if (accessToken) {
    const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(accessToken));
    payload.ath = b64url(hash);
  }

  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  // WebCrypto returns the raw r||s form that JWS ES256 requires
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    pair.privateKey,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${b64url(sig)}`;
}
```

The `htu` you sign must equal the server's `PublicBaseUrl + path`, so build requests from the same public base URL the API expects.

## TypeScript changes 2: API client and renewal

Every API call goes through one wrapper that attaches the token and a fresh proof, and renewal uses the same wrapper so it also proves key possession. Keep the access token in memory rather than localStorage. It is less critical now that a copied token is useless without the key, but there is no reason to leave it lying in storage.

```ts
// tokenStore.ts: in-memory token, shared between same-origin frames
const channel = new BroadcastChannel("cfc-token");
let accessToken: string | undefined;

channel.onmessage = (e) => { accessToken = e.data?.token; };

export const getToken = () => accessToken;
export function setToken(token: string | undefined) {
  accessToken = token;
  channel.postMessage({ token });   // keeps the other frame in sync
}
```

```ts
// apiClient.ts
import { buildProof, createKeyPair, clearKeyPair } from "./dpop";
import { getToken, setToken } from "./tokenStore";

const API = import.meta.env.VITE_API_BASE_URL;   // must equal the server's Dpop:PublicBaseUrl

/** Called once per session with the single-use handoff token from Melio. */
export async function exchangeHandoff(handoffToken: string) {
  await createKeyPair();                           // fresh key for a fresh session
  const url = `${API}/auth/exchange`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      DPoP: await buildProof("POST", url),           // no ath: there is no access token yet
    },
    body: JSON.stringify({ handoffToken }),
  });
  if (!res.ok) throw new Error(`exchange failed: ${res.status}`);
  setToken((await res.json()).accessToken);
}

async function send(path: string, init: RequestInit = {}): Promise<Response> {
  const url = `${API}${path}`;
  const token = getToken();
  if (!token) throw new Error("no session");
  const method = (init.method ?? "GET").toUpperCase();
  return fetch(url, {
    ...init,
    method,
    headers: {
      ...init.headers,
      Authorization: `Bearer ${token}`,
      DPoP: await buildProof(method, url, token),   // new proof every call, never reused
    },
  });
}

export async function renew(): Promise<boolean> {
  const res = await send("/auth/renew", { method: "POST" });
  if (!res.ok) return false;                        // session cap reached: back to Melio
  setToken((await res.json()).accessToken);
  return true;
}

export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  let res = await send(path, init);
  if (res.status === 401 && (await renew())) res = await send(path, init);   // retry once
  if (res.status === 401) { setToken(undefined); await clearKeyPair(); }     // session over
  return res;
}
```

Use it for the category update like any other call:

```ts
await apiFetch("/alldata/accounts/123/category", {
  method: "PUT",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ category: "Supplies" }),
});
```

Two points for your existing frame handoff. First, the frame that owns refresh keeps calling `renew()` on its timer and publishes the new token through `setToken`, replacing the localStorage write. Second, the frame that navigates to AllData loses its JavaScript, but the key pair stays in IndexedDB, so the returning frame can still sign. Renewal needs a token that has not yet expired, so the owning frame must keep renewing while the other frame is away. If the token does expire during the trip, renewal fails with 401 and the user has to re-enter through Melio, which is why your handoff-ownership design matters.

## Step-up, dev config and Postman

Step-up covers the case DPoP cannot: someone using user 1's logged-in browser. For high-risk actions, require a confirmation that the other person cannot produce from that browser. Whether Melio can supply a fresh, single-use confirmation is an open question (see the last section); a passkey (WebAuthn) prompt is the alternative.

Shape of the check, assuming a short-lived step-up token minted by a fresh Melio confirmation and bound to the same key:

```csharp
// On a high-risk endpoint, after DPoP has passed
var stepUp = HttpContext.Request.Headers["X-Step-Up"].ToString();
if (!await stepUps.ValidateAndConsumeAsync(stepUp,
        subject: User.FindFirstValue("sub")!,
        jkt: boundJkt,                       // same key as the access token
        scope: "alldata:update-category"))   // single use, about 2 minutes
{
    await SendAsync(new { error = "step_up_required" }, 403, ct);
    return;
}
```

```ts
// client: on 403 step_up_required, run the confirmation flow, then retry with the header
const stepUp = await requestStepUp("alldata:update-category");   // Melio re-confirm or passkey
await apiFetch(path, { ...init, headers: { ...init.headers, "X-Step-Up": stepUp } });
```

Tier it so normal use stays smooth:

| Action | Protection |
| --- | --- |
| Reads | Token + DPoP |
| Update category | Token + DPoP + owner check |
| Higher-risk changes | All of the above + step-up |

Dev and Postman: set `Dpop:Mode` in Azure App Configuration. `Off` is allowed only in local development, `Report` is for shared test environments while you find broken clients, and `Enforce` is for UAT and production. Add a startup guard so it cannot be left off by mistake:

```csharp
var dpop = builder.Configuration.GetSection("Dpop").Get<DpopOptions>() ?? new();
if (dpop.Mode == DpopMode.Off && !builder.Environment.IsDevelopment())
    throw new InvalidOperationException("Dpop:Mode=Off is only allowed in Development.");
```

The mode comes from configuration, never from a request header or query parameter, so a caller cannot switch it off. Do not skip DPoP just because a call did not come through Apigee. A thief can call the backend directly, so that exemption would remove the protection unless the backend is reachable only from Apigee.

For realistic testing in Postman, a pre-request script generates a key pair once (stored in environment variables), signs a proof for each request, and sets the `DPoP` header. The `Authorization: Bearer` header stays as it is today. Call `/auth/exchange` from the same Postman environment first so the session binds to that script's key. A token taken from a browser session will not work in Postman, which is the intended behavior. Proofs expire in about 60 seconds, and each `jti` is single-use, so the script must sign a new one for every send.

## Rollout and open questions

Roll out in four steps, with `Report` mode first so nothing breaks for real users.

| Step | Change | Done when |
| --- | --- | --- |
| 1 | Make the handoff token single-use; record the key thumbprint against the session at exchange; make sure tokens carry `sid` and `sst`; add the validator and pre-processor in `Report` mode | Logs show proofs validating for real traffic |
| 2 | Ship the TypeScript changes: fresh key per session, `apiFetch` sending the proof beside the existing Bearer header, in-memory token | No `session_not_bound` or `htu` failures in the logs |
| 3 | Switch `Dpop:Mode` to `Enforce` in UAT, then production; enforce the renew session cap | Copying a token to another browser returns 401 |
| 4 | Add step-up on the higher-risk endpoints; add audit logging and second-device alerts | Step-up flow works end to end |

Open questions to settle before step 1:

- Do your tokens already carry a stable session id that survives renewal? If not, add `sid` (and `sst`) at issuance.
- Where is the key recorded at exchange? It must be written in the same call that releases the token to the browser, or a thief could bind their own key first. If your token issuer can add a `cnf` claim, binding inside the token works too.
- Does Apigee pass the `DPoP` header through and leave the URL unchanged? If it rewrites host or path, set `Dpop:PublicBaseUrl` to the URL the client signs and verify the match.
- Can Melio supply a fresh single-use confirmation for step-up, or should you use passkeys?
- Which endpoints count as higher-risk?
- Does anything besides the browser SPA call these APIs (scripts, partners, mobile)? Each needs a DPoP-capable client or its own path.

Industry context: Okta offers DPoP to all its customers, and Google now supports it for OAuth refresh tokens, while keeping its access tokens as bearer tokens for performance. I found no adoption numbers, so treat DPoP as an established standard rather than proven ubiquity.

Sources: [Okta announces DPoP support](https://okta.com/blog/2023/06/a-leap-forward-in-token-security-okta-adds-support-for-dpop), [Google DPoP support for OAuth](https://developers.googleblog.com/announcing-dpop-support-for-google-oauth-securing-refresh-tokens/), [Chrome Device Bound Session Credentials](https://blog.google/security/protecting-cookies-with-device-bound-session-credentials/).

## Short answer

Mostly yes, with limits: browser APIs cannot copy a non-extractable private key, but anyone with access to the same browser session can still use it to sign. "Cannot be copied" is not the same as "cannot be used."

## What it protects against

With `extractable: false`, calling `crypto.subtle.exportKey("jwk", privateKey)` throws an error, and so do `wrapKey` and similar calls. This holds for any JavaScript on the page. Only the public key can be exported, and that is safe to expose.

Your scenario, where user 2 copies the token from localStorage and uses it on their own machine, is blocked: they get the token but nothing to sign proofs with.

## What it does not protect against

- **Using the key in place.** Any script in the same origin can read the `CryptoKey` object from IndexedDB and call `crypto.subtle.sign(...)` with it. That includes an XSS payload, and anyone typing in the DevTools console of user 1's logged-in browser. They cannot take the key away, but they can make it sign while they have access. The nonce-based CSP reduces the XSS risk.
- **Reading the browser profile from disk.** The key lives in the browser's profile storage and is not guaranteed to be hardware-bound, so someone with OS-level access or malware on user 1's machine may be able to recover it. This is unverified per browser, so do not treat the on-disk case as safe.
- **A shared browser or device.** If user 2 can sit at user 1's session, the key travels with that session.

## What this means for the design

DPoP with a non-extractable key stops remote token theft and replay, which is the "copy the token from localStorage and use it elsewhere" case. It does not stop someone who controls user 1's browser, physically or remotely.

For sensitive actions, add a step-up confirmation that user 2 cannot get: a fresh Melio handoff or a passkey (WebAuthn) prompt. A passkey's private key lives in the device's secure hardware and needs a user gesture (biometric or PIN) each time, so it is much harder to use silently.

A practical split: DPoP on every request, plus a passkey or Melio re-confirmation only for the actions you consider high-risk.
