/**
 * tokenRefreshService.test.ts
 *
 * Uses fake timers and mocked fetch to test scheduling, retry, hard stop,
 * and config fallback behaviour without any real network or clock dependency.
 */

import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';
import { createTokenRefreshService, type TokenRefreshConfig } from '../src/tokenRefreshService';

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Builds a minimal JWT with the given exp (Unix seconds). */
function makeToken(expUnixSecs: number): string {
  const payload = btoa(JSON.stringify({ sub: 'user1', exp: expUnixSecs }));
  return `header.${payload}.signature`;
}

/** Flushes all pending microtasks (Promise chains). */
async function flushMicrotasks(): Promise<void> {
  await new Promise(resolve => setTimeout(resolve, 0));
}

const DEFAULT_CONFIG: TokenRefreshConfig = {
  refreshBeforeSeconds: 60,
  hardStopBeforeSeconds: 20,
  maxRetries: 3,
  retryBackoffMs: 2000,
};

// ── Test setup ────────────────────────────────────────────────────────────────

describe('tokenRefreshService', () => {
  let fetchMock: Mock;
  let onTokenRefreshed: Mock;
  let onAuthFailure: Mock;

  // Fixed "now" = Unix 1_000_000s. Token exp = now + 600s.
  const NOW_UNIX = 1_000_000;
  const NOW_MS = NOW_UNIX * 1000;
  const TOKEN_EXP = NOW_UNIX + 600;  // expires in 600s

  beforeEach(() => {
    vi.useFakeTimers();
    fetchMock = vi.fn();
    onTokenRefreshed = vi.fn();
    onAuthFailure = vi.fn();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  function makeService(configOverride?: Partial<TokenRefreshConfig>) {
    const cfg: TokenRefreshConfig = { ...DEFAULT_CONFIG, ...configOverride };

    // Config fetch returns the merged config
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => cfg,
    });

    return createTokenRefreshService({
      fetchFn: fetchMock,
      nowFn: () => NOW_MS,
      setTimeoutFn: setTimeout,
      clearTimeoutFn: clearTimeout,
      onTokenRefreshed,
      onAuthFailure,
    });
  }

  // ── Config loading ────────────────────────────────────────────────────────

  describe('config loading', () => {
    it('fetches config from API on init', async () => {
      const svc = makeService();
      await svc.init(makeToken(TOKEN_EXP));

      expect(fetchMock).toHaveBeenCalledWith('/auth/token-refresh-config');
    });

    it('uses fallback config when API fetch fails', async () => {
      fetchMock.mockRejectedValueOnce(new Error('network error'));

      // Fresh service — no pre-loaded config mock
      const svc = createTokenRefreshService({
        fetchFn: fetchMock,
        nowFn: () => NOW_MS,
        setTimeoutFn: setTimeout,
        clearTimeoutFn: clearTimeout,
        onTokenRefreshed,
        onAuthFailure,
      });

      // Should not throw; falls back to defaults
      await expect(svc.init(makeToken(TOKEN_EXP))).resolves.not.toThrow();
    });

    it('uses fallback when config endpoint returns non-OK', async () => {
      fetchMock.mockResolvedValueOnce({ ok: false, status: 503 });

      const svc = createTokenRefreshService({
        fetchFn: fetchMock,
        nowFn: () => NOW_MS,
        setTimeoutFn: setTimeout,
        clearTimeoutFn: clearTimeout,
        onTokenRefreshed,
        onAuthFailure,
      });

      await expect(svc.init(makeToken(TOKEN_EXP))).resolves.not.toThrow();
    });
  });

  // ── Scheduling ────────────────────────────────────────────────────────────

  describe('scheduling', () => {
    it('fires refresh at (exp - refreshBefore) from now', async () => {
      const svc = makeService({ refreshBeforeSeconds: 60 });

      // Successful refresh response
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ token: makeToken(NOW_UNIX + 600) }),
      });

      await svc.init(makeToken(TOKEN_EXP));

      // Before the scheduled time — no refresh call yet
      vi.advanceTimersByTime(539_000); // 539s — just before the 540s mark
      await flushMicrotasks();
      expect(fetchMock).toHaveBeenCalledTimes(1); // only the config call

      // Advance past the threshold
      vi.advanceTimersByTime(2_000); // now at 541s
      await flushMicrotasks();
      expect(fetchMock).toHaveBeenCalledWith('/auth/refresh', { method: 'POST' });
    });

    it('reschedules using the new token exp after a successful refresh', async () => {
      const svc = makeService({ refreshBeforeSeconds: 60 });

      const newExp = NOW_UNIX + 600;
      const newToken = makeToken(newExp);

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ token: newToken }),
      });

      await svc.init(makeToken(TOKEN_EXP));

      vi.advanceTimersByTime(541_000);
      await flushMicrotasks();

      expect(onTokenRefreshed).toHaveBeenCalledWith(newToken);
    });

    it('calls onAuthFailure for a token with no exp claim', async () => {
      const svc = makeService();
      const badToken = `header.${btoa(JSON.stringify({ sub: 'user1' }))}.sig`; // no exp

      await svc.init(badToken);
      await flushMicrotasks();

      expect(onAuthFailure).toHaveBeenCalledTimes(1);
    });
  });

  // ── Retry logic ───────────────────────────────────────────────────────────

  describe('retry logic', () => {
    it('retries with exponential backoff on failure', async () => {
      const svc = makeService({ maxRetries: 3, retryBackoffMs: 2000 });

      // All refresh attempts fail
      fetchMock.mockRejectedValue(new Error('503'));

      await svc.init(makeToken(TOKEN_EXP));

      // Trigger first attempt
      vi.advanceTimersByTime(541_000);
      await flushMicrotasks();

      // Retry 1 after 2s
      vi.advanceTimersByTime(2_000);
      await flushMicrotasks();

      // Retry 2 after 4s
      vi.advanceTimersByTime(4_000);
      await flushMicrotasks();

      // Retry 3 after 8s
      vi.advanceTimersByTime(8_000);
      await flushMicrotasks();

      // 1 config + 4 refresh attempts (attempt 0 + 3 retries)
      const refreshCalls = fetchMock.mock.calls.filter(
        ([url]) => url === '/auth/refresh'
      );
      expect(refreshCalls).toHaveLength(4);
    });

    it('calls onAuthFailure after max retries are exhausted', async () => {
      const svc = makeService({ maxRetries: 3, retryBackoffMs: 1000 });
      fetchMock.mockRejectedValue(new Error('down'));

      await svc.init(makeToken(TOKEN_EXP));

      vi.advanceTimersByTime(541_000);
      await flushMicrotasks();

      vi.advanceTimersByTime(1_000);  await flushMicrotasks(); // retry 1
      vi.advanceTimersByTime(2_000);  await flushMicrotasks(); // retry 2
      vi.advanceTimersByTime(4_000);  await flushMicrotasks(); // retry 3

      expect(onAuthFailure).toHaveBeenCalledTimes(1);
    });

    it('succeeds on a later retry and does not call onAuthFailure', async () => {
      const svc = makeService({ maxRetries: 3, retryBackoffMs: 1000 });

      const newToken = makeToken(NOW_UNIX + 600);

      fetchMock
        .mockRejectedValueOnce(new Error('attempt 0 fails'))
        .mockRejectedValueOnce(new Error('attempt 1 fails'))
        .mockResolvedValueOnce({           // attempt 2 succeeds
          ok: true,
          json: async () => ({ token: newToken }),
        });

      await svc.init(makeToken(TOKEN_EXP));

      vi.advanceTimersByTime(541_000); await flushMicrotasks(); // attempt 0
      vi.advanceTimersByTime(1_000);   await flushMicrotasks(); // retry 1
      vi.advanceTimersByTime(2_000);   await flushMicrotasks(); // retry 2 → success

      expect(onTokenRefreshed).toHaveBeenCalledWith(newToken);
      expect(onAuthFailure).not.toHaveBeenCalled();
    });
  });

  // ── Hard stop ─────────────────────────────────────────────────────────────

  describe('hard stop', () => {
    it('aborts retry immediately if seconds remaining falls below hardStopBeforeSeconds', async () => {
      // Token expires in 25s from now — exactly at the hard stop boundary
      const nearExpToken = makeToken(NOW_UNIX + 25);

      // Config: hardStop=20, refreshBefore=60 → rawDelay would be negative → clamped to 5s
      const svc = makeService({ hardStopBeforeSeconds: 20, refreshBeforeSeconds: 60 });
      fetchMock.mockRejectedValue(new Error('always fails'));

      await svc.init(nearExpToken);

      // Advance 5s (minimum clamp fires the scheduler)
      vi.advanceTimersByTime(5_000);
      await flushMicrotasks();

      // 25 - 5 = 20s remaining — exactly at the hard stop threshold.
      // The service should abort rather than attempt.
      expect(onAuthFailure).toHaveBeenCalledTimes(1);
    });

    it('does not abort if plenty of time remains', async () => {
      const svc = makeService({ hardStopBeforeSeconds: 20, refreshBeforeSeconds: 60 });

      const newToken = makeToken(NOW_UNIX + 600);
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ token: newToken }),
      });

      await svc.init(makeToken(TOKEN_EXP)); // 600s left

      vi.advanceTimersByTime(541_000); // 540s → attempt fires with 60s still remaining
      await flushMicrotasks();

      expect(onAuthFailure).not.toHaveBeenCalled();
      expect(onTokenRefreshed).toHaveBeenCalledWith(newToken);
    });
  });

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  describe('destroy', () => {
    it('cancels the pending scheduler on destroy', async () => {
      const svc = makeService();
      await svc.init(makeToken(TOKEN_EXP));

      svc.destroy();

      // Advance past where the refresh would have fired
      vi.advanceTimersByTime(600_000);
      await flushMicrotasks();

      // Only the config call — no refresh attempt
      const refreshCalls = fetchMock.mock.calls.filter(
        ([url]) => url === '/auth/refresh'
      );
      expect(refreshCalls).toHaveLength(0);
    });
  });
});
