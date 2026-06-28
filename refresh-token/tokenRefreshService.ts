/**
 * tokenRefreshService.ts
 *
 * Resilient token refresh scheduler for the Insights SPA.
 *
 * Design:
 *  - On init, fetches behavioral config from the API (refreshBefore, hardStop, retries, backoff).
 *  - On each new token (login or successful refresh), reads the JWT exp claim and schedules
 *    the next refresh attempt dynamically — never relies on a hardcoded TTL.
 *  - Retry loop aborts early (hard stop) if fewer than hardStopBeforeSeconds remain,
 *    protecting against near-expiry calls that would arrive after the token is already dead.
 *  - Exponential backoff between attempts.
 *  - On exhaustion → calls onAuthFailure (force re-login).
 */

export interface TokenRefreshConfig {
  refreshBeforeSeconds: number;   // when to fire first attempt (e.g. 60s before exp)
  hardStopBeforeSeconds: number;  // abort retries below this remaining window (e.g. 20s)
  maxRetries: number;             // attempts before giving up
  retryBackoffMs: number;         // base delay for exponential backoff (e.g. 2000)
}

// Safe defaults used while the config fetch is in flight,
// or if the endpoint is temporarily unavailable.
const FALLBACK_CONFIG: TokenRefreshConfig = {
  refreshBeforeSeconds: 60,
  hardStopBeforeSeconds: 20,
  maxRetries: 3,
  retryBackoffMs: 2000,
};

export interface TokenRefreshServiceOptions {
  configUrl?: string;
  refreshUrl?: string;
  onTokenRefreshed?: (newToken: string) => void;
  onAuthFailure?: () => void;
  // Injected in tests to replace fetch / setTimeout / Date.now
  fetchFn?: typeof fetch;
  nowFn?: () => number;
  setTimeoutFn?: typeof setTimeout;
  clearTimeoutFn?: typeof clearTimeout;
}

export function createTokenRefreshService(options: TokenRefreshServiceOptions = {}) {
  const {
    configUrl = '/auth/token-refresh-config',
    refreshUrl = '/auth/refresh',
    onTokenRefreshed = () => {},
    onAuthFailure = () => { window.location.href = '/login'; },
    fetchFn = fetch.bind(window),
    nowFn = () => Date.now(),
    setTimeoutFn = setTimeout,
    clearTimeoutFn = clearTimeout,
  } = options;

  let config: TokenRefreshConfig = { ...FALLBACK_CONFIG };
  let schedulerHandle: ReturnType<typeof setTimeout> | null = null;

  // ── Public API ────────────────────────────────────────────────────────────

  /**
   * Call once after the user authenticates.
   * Fetches config from the API, then arms the scheduler against the current token.
   */
  async function init(initialToken: string): Promise<void> {
    config = await fetchConfig();
    scheduleRefreshFromToken(initialToken);
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

  // ── Internal ──────────────────────────────────────────────────────────────

  async function fetchConfig(): Promise<TokenRefreshConfig> {
    try {
      const res = await fetchFn(configUrl);
      if (!res.ok) throw new Error(`Config fetch returned HTTP ${res.status}`);
      return (await res.json()) as TokenRefreshConfig;
    } catch (err) {
      console.warn('[TokenRefresh] Could not load config from API — using fallback defaults.', err);
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
    const rawDelayMs = expiresInMs - config.refreshBeforeSeconds * 1000;

    // Never fire sooner than 5 seconds out — avoids a tight loop if exp is very close.
    const delayMs = Math.max(5_000, rawDelayMs);

    if (schedulerHandle !== null) clearTimeoutFn(schedulerHandle);

    console.debug(
      `[TokenRefresh] Scheduling refresh in ${(delayMs / 1000).toFixed(1)}s ` +
      `(token expires in ${(expiresInMs / 1000).toFixed(1)}s)`
    );

    schedulerHandle = setTimeoutFn(
      () => attemptRefresh(exp, 0),
      delayMs
    );
  }

  async function attemptRefresh(exp: number, attempt: number): Promise<void> {
    const secondsRemaining = exp - nowFn() / 1000;

    // Hard stop — too close to expiry to safely make the call.
    if (secondsRemaining < config.hardStopBeforeSeconds) {
      console.error(
        `[TokenRefresh] Hard stop triggered — only ${secondsRemaining.toFixed(1)}s remaining ` +
        `(threshold: ${config.hardStopBeforeSeconds}s). Forcing re-auth.`
      );
      onAuthFailure();
      return;
    }

    console.debug(
      `[TokenRefresh] Attempt ${attempt + 1}/${config.maxRetries + 1}, ` +
      `${secondsRemaining.toFixed(0)}s remaining on token`
    );

    try {
      const res = await fetchFn(refreshUrl, { method: 'POST' });
      if (!res.ok) throw new Error(`Refresh returned HTTP ${res.status}`);

      const { token: newToken } = (await res.json()) as { token: string };

      onTokenRefreshed(newToken);
      scheduleRefreshFromToken(newToken); // reschedule using the NEW token's exp
    } catch (err) {
      if (attempt < config.maxRetries) {
        const backoffMs = config.retryBackoffMs * Math.pow(2, attempt);
        console.warn(
          `[TokenRefresh] Attempt ${attempt + 1} failed. ` +
          `${secondsRemaining.toFixed(0)}s remaining. Retrying in ${backoffMs}ms.`,
          err
        );
        schedulerHandle = setTimeoutFn(
          () => attemptRefresh(exp, attempt + 1),
          backoffMs
        );
      } else {
        console.error('[TokenRefresh] All retries exhausted. Forcing re-auth.', err);
        onAuthFailure();
      }
    }
  }

  function getExpFromToken(token: string): number | null {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      if (typeof payload.exp !== 'number') return null;
      return payload.exp;
    } catch {
      return null;
    }
  }

  return { init, destroy };
}
