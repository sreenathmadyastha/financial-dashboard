# Resilient Token Refresh — Integration Guide

## Files

```
api/
  Models/TokenRefreshConfig.cs              — Response record
  Endpoints/TokenRefreshConfigEndpoint.cs   — GET /auth/token-refresh-config
  appsettings.TokenRefresh.json             — Config values (merge into your appsettings.json)
  Tests/TokenRefreshConfigEndpointTests.cs  — xUnit tests

ui/
  src/tokenRefreshService.ts                — Scheduler + retry service
  tests/tokenRefreshService.test.ts         — Vitest tests
```

---

## 1 — API setup

### Merge into appsettings.json

```json
{
  "Auth": {
    "TokenRefresh": {
      "RefreshBeforeSeconds": 60,
      "HardStopBeforeSeconds": 20,
      "MaxRetries": 3,
      "RetryBackoffMs": 2000
    }
  }
}
```

The endpoint is registered automatically by FastEndpoints assembly scanning — no
additional registration needed.

### Run API tests

```bash
dotnet test --filter "TokenRefreshConfig"
```

---

## 2 — UI integration

### Wire up in your app entry point (e.g. after OIDC callback)

```typescript
import { createTokenRefreshService } from './tokenRefreshService';

const tokenRefresh = createTokenRefreshService({
  onTokenRefreshed: (newToken) => {
    // store in your auth context / Axios interceptor / wherever you keep the token
    authStore.setToken(newToken);
  },
  onAuthFailure: () => {
    // force re-login
    window.location.href = '/login';
  },
});

// Call this once you have the initial token (after login)
await tokenRefresh.init(authStore.getToken());

// Call on logout
tokenRefresh.destroy();
```

### Run UI tests

```bash
cd ui
npm install
npm test
```

---

## 3 — Tuning guide

| Scenario | Change |
|---|---|
| Corporate token API is slow (>5s p99) | Increase `RefreshBeforeSeconds` to 90 |
| Near-expiry failures in Dynatrace | Increase `HardStopBeforeSeconds` to 30 |
| Flaky network — retries exhausting too fast | Increase `RetryBackoffMs` to 3000 |
| Token API fully down — want more attempts | Increase `MaxRetries` to 5 |

All values live in Azure App Configuration — no redeployment required.

### Invariant to always maintain

```
(MaxRetries retries at RetryBackoffMs base) < (RefreshBeforeSeconds - HardStopBeforeSeconds) * 1000

Default check: (2000 + 4000 + 8000) = 14000ms < (60 - 20) * 1000 = 40000ms ✓
```

The API test `RetryBudget_FitsWithin_RefreshWindow` enforces this automatically.
