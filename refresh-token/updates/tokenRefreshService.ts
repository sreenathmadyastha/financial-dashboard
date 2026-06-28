/**
 * tokenRefreshService.ts
 *
 * Resilient token refresh scheduler for the Insights SPA.
 *
 * Flow:
 *  1. UI calls POST /api/token-exchange with the product token.
 *  2. The response contains both the API token AND all scheduling config
 *     (TokenExpirationSeconds, RefreshBeforeSeconds, HardStopBeforeSeconds,
 *     MaxRetries, RetryBackoffMs) — no separate config fetch needed.
 *  3. UI passes the token + config directly to tokenRefreshService.init().
 *  4. On each successful refresh, the new token's exp claim is used to
 *     reschedule — the config values remain constant for the session.
 *
 * If a page reload occurs, the UI may call GET /auth/token-refresh-config
 * to recover the config (same shape) without repeating the full exchange.
 * That is handled outside this service — callers pass the config in either way.
 *
 * Retry behaviour:
 *  - First attempt fires refreshBeforeSeconds before expiry.
 *  - On failure, retries with exponential backoff (retryBackoffMs * 2^attempt).
 *  - Hard stop: if fewer than hardStopBeforeSeconds remain, abort immediately
 *    rather than risk the call arriving after expiry.
 *  - After maxRetries exhausted → onAuthFailure (force re-login).
 */

// ── Types ──────────────────────────────────────────────────────────────────────

/**
 * Scheduling and retry config — matches the shape returned by both
 * POST /api/token-exchange and GET /auth/token-refresh-config.
 */
export interface TokenRefreshConfig {
  /** Token lifetime in seconds (from corporate API's ExpiresIn minutes, converted). */
  tokenExpirationSeconds: number;
  /** Fire first refresh attempt this many seconds before expiry. */
  refreshBeforeSeconds: number;
  /** Abort retries if fewer than this many seconds remain on the token. */
  hardStopBeforeSeconds: number;
  /** Max refresh attempts before forcing re-authentication. */
  maxRetries: number;
  /** Base backoff in ms between retries (exponential: base * 2^attempt). */
  retryBackoffMs: number;
}

export interface TokenExchangeResponse {
  apiToken: string;
  tokenExpirationSeconds: number;
  refreshBeforeSeconds: number;
  hardStopBeforeSeconds: number;
  maxRetries: number;
  retryBackoffMs: number;
}

export interface TokenRefreshServiceOptions {
  /** URL for the refresh endpoint (default: /auth/refresh). */
  refreshUrl?: string;
  /** URL for recovering config after a page reload (default: /auth/token-refresh-config). */
  configUrl?: string;
  onTokenRefreshed?: (newToken: string) => void;
  onAuthFailure?: () => void;
  // Injected in tests to avoid real network / clock dependencies
  fetchFn?: typeof fetch;
  nowFn?: () => number;
  setTimeoutFn?: typeof setTimeout;
  clearTimeoutFn?: typeof clearTimeout;
}

// Safe fallback if the config cannot be recovered after a page reload.
// Matches the API defaults so behaviour is consistent.
export const FALLBACK_CONFIG: TokenRefreshConfig = {
  tokenExpirationSeconds: 600,
  refreshBeforeSeconds:   60,
  hardStopBeforeSeconds:  20,
  maxRetries:             3,
  retryBackoffMs:         2000,
};

// ── Factory ───────────────────────────────────────────────────────────────────

export function createTokenRefreshService(options: TokenRefreshServiceOptions = {}) {
  const {
    refreshUrl = '/auth/refresh',
    configUrl  = '/auth/token-refresh-config',
    onTokenRefreshed = () => {},
    onAuthFailure    = () => { window.location.href = '/login'; },
    fetchFn          = fetch.bind(window),
    nowFn            = () => Date.now(),
    setTimeoutFn     = setTimeout,
    clearTimeoutFn   = clearTimeout,
  } = options;

  let config: TokenRefreshConfig = { ...FALLBACK_CONFIG };
  let schedulerHandle: ReturnType<typeof setTimeout> | null = null;

  // ── Public API ───────────────────────────────────────────────────────────

  /**
   * Primary init path — called immediately after token-exchange succeeds.
   * Config is already known from the exchange response; no extra fetch needed.
   *
   * @param apiToken  The API token returned by /api/token-exchange.
   * @param cfg       The scheduling config from the same response.
   */
  function initWithConfig(apiToken: string, cfg: TokenRefreshConfig): void {
    config = cfg;
    scheduleRefreshFromToken(apiToken);
  }

  /**
   * Page-reload path — called when the token is already in storage but config
   * needs to be re-fetched from GET /auth/token-refresh-config.
   * Falls back to FALLBACK_CONFIG if the endpoint is unavailable.
   *
   * @param storedToken  The token recovered from session/local storage.
   */
  async function initFromStorage(storedToken: string): Promise<void> {
    config = await fetchConfig();
    scheduleRefreshFromToken(storedToken);
  }

  /**
   * Tear down the scheduler (e.g. on logout).
   */
  function destroy(): void {
    if (schedulerHandle !== null) {
      clearTimeoutFn(schedulerHandle);
      schedulerHandle = null;
    }
  }

  // ── Internal ─────────────────────────────────────────────────────────────

  async function fetchConfig(): Promise<TokenRefreshConfig> {
    try {
      const res = await fetchFn(configUrl);
      if (!res.ok) throw new Error(`Config fetch returned HTTP ${res.status}`);
      return (await res.json()) as TokenRefreshConfig;
    } catch (err) {
      console.warn(
        '[TokenRefresh] Could not recover config from API — using fallback defaults.', err
      );
      return { ...FALLBACK_CONFIG };
    }
  }

  function scheduleRefreshFromToken(token: string): void {
    const exp = getExpFromToken(token);
    if (exp === null) {
      console.error('[TokenRefresh] Could not parse exp from token. Forcing re-auth.');
      onAuthFailure();
      return;
    }

    const expiresInMs = exp * 1000 - nowFn();
    const rawDelayMs  = expiresInMs - config.refreshBeforeSeconds * 1000;

    // Floor at 5s — prevents a tight immediate-fire loop if the token is already close to expiry.
    const delayMs = Math.max(5_000, rawDelayMs);

    if (schedulerHandle !== null) clearTimeoutFn(schedulerHandle);

    console.debug(
      `[TokenRefresh] Scheduling refresh in ${(delayMs / 1000).toFixed(1)}s ` +
      `(token expires in ${(expiresInMs / 1000).toFixed(1)}s, ` +
      `refreshBefore=${config.refreshBeforeSeconds}s)`
    );

    schedulerHandle = setTimeoutFn(() => attemptRefresh(exp, 0), delayMs);
  }

  async function attemptRefresh(exp: number, attempt: number): Promise<void> {
    const secondsRemaining = exp - nowFn() / 1000;

    // Hard stop — too close to expiry to risk the call arriving after the token dies.
    if (secondsRemaining < config.hardStopBeforeSeconds) {
      console.error(
        `[TokenRefresh] Hard stop — ${secondsRemaining.toFixed(1)}s remaining, ` +
        `threshold ${config.hardStopBeforeSeconds}s. Forcing re-auth.`
      );
      onAuthFailure();
      return;
    }

    console.debug(
      `[TokenRefresh] Attempt ${attempt + 1}/${config.maxRetries + 1}, ` +
      `${secondsRemaining.toFixed(0)}s remaining`
    );

    try {
      const res = await fetchFn(refreshUrl, { method: 'POST' });
      if (!res.ok) throw new Error(`Refresh returned HTTP ${res.status}`);

      const { token: newToken } = (await res.json()) as { token: string };

      onTokenRefreshed(newToken);
      // Reschedule using the NEW token's exp — corporate API may issue a different lifetime.
      scheduleRefreshFromToken(newToken);

    } catch (err) {
      if (attempt < config.maxRetries) {
        const backoffMs = config.retryBackoffMs * Math.pow(2, attempt);
        console.warn(
          `[TokenRefresh] Attempt ${attempt + 1} failed, ${secondsRemaining.toFixed(0)}s remaining. ` +
          `Retrying in ${backoffMs}ms.`, err
        );
        schedulerHandle = setTimeoutFn(() => attemptRefresh(exp, attempt + 1), backoffMs);
      } else {
        console.error('[TokenRefresh] All retries exhausted. Forcing re-auth.', err);
        onAuthFailure();
      }
    }
  }

  function getExpFromToken(token: string): number | null {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return typeof payload.exp === 'number' ? payload.exp : null;
    } catch {
      return null;
    }
  }

  return { initWithConfig, initFromStorage, destroy };
}
