# Apigee health check and fallback for BFF API DR

Oct 3, 2026 · @Sreenath

## Purpose and request path

Apigee sends BFF API calls to the East region and falls back to Central when East fails its health check; this guide covers the target server, load balancer and health monitor settings that do it.

The request path is users, then Azure Front Door, then the frontend container apps (East and Central), then Apigee, then the BFF API container apps (East and Central). Front Door handles frontend region failover and Apigee handles BFF region failover, so the two tiers fail over independently. A frontend in one region can therefore call the BFF in the other.

&#91;embedded content: request path · two tiers, each with its own failover\]

Front Door chooses between the frontend apps, and Apigee chooses between the BFF APIs, so a Central frontend can call East's BFF.

Scope: only the Apigee-to-BFF hop. Data tier DR (Cosmos DB, Redis) and Apigee's own DR are separate pieces of work.

## Step 1: define one target server per region

Create two target servers in each Apigee environment, one per BFF region, so the proxy refers to names and each environment can point at different hosts. Apigee's documented name rule is alphanumeric only, so the names below have no hyphens.

```xml
<TargetServer name="bffeast">
  <Host>bff-east.yourdomain.com</Host>
  <Port>443</Port>
  <IsEnabled>true</IsEnabled>
  <SSLInfo>
    <Enabled>true</Enabled>
  </SSLInfo>
</TargetServer>
```

Create `bffcentral` the same way with the Central hostname.

- `Host`: each BFF's ingress hostname, ideally a custom domain with a certificate that matches it.
- `SSLInfo`: one-way TLS as shown; add a truststore if the certificate comes from a private CA.
- `IsEnabled`: setting this to false is a quick way to simulate a regional outage during testing.

## Step 2: configure the target endpoint

The target endpoint lists both servers, marks Central as the fallback, and adds a health monitor that polls your existing health route.

```xml
<TargetEndpoint name="default">
  <HTTPTargetConnection>
    <LoadBalancer>
      <Algorithm>RoundRobin</Algorithm>
      <Server name="bffeast"/>
      <Server name="bffcentral">
        <IsFallback>true</IsFallback>
      </Server>
      <MaxFailures>3</MaxFailures>
      <ServerUnhealthyResponse>
        <ResponseCode>502</ResponseCode>
        <ResponseCode>503</ResponseCode>
        <ResponseCode>504</ResponseCode>
      </ServerUnhealthyResponse>
    </LoadBalancer>
    <Path>/your-bff-base-path</Path>
    <HealthMonitor>
      <IsEnabled>true</IsEnabled>
      <IntervalInSec>10</IntervalInSec>
      <HTTPMonitor>
        <Request>
          <IsSSL>true</IsSSL>
          <ConnectTimeoutInSec>5</ConnectTimeoutInSec>
          <SocketReadTimeoutInSec>10</SocketReadTimeoutInSec>
          <Port>443</Port>
          <Verb>GET</Verb>
          <Path>/your-health-route</Path>
        </Request>
        <SuccessResponse>
          <ResponseCode>200</ResponseCode>
        </SuccessResponse>
      </HTTPMonitor>
    </HealthMonitor>
  </HTTPTargetConnection>
</TargetEndpoint>
```

Replace the two path placeholders with the real BFF base path and health route. The monitor's `Path` cannot contain variables.

## How it behaves

While East is healthy, all traffic goes to East; Central receives traffic only when every non-fallback server is marked unavailable, and only one server per load balancer can be the fallback.

A server is removed from rotation in two ways:

- **Failed live requests:** the load balancer counts connection failures and the response codes listed in `ServerUnhealthyResponse`, and removes the server after `MaxFailures` failures.
- **Active polling:** the health monitor calls the health route on the configured interval and marks the server down when the check fails.

`MaxFailures` must be above zero. Its default is 0, which means a server is never removed from rotation, and the health monitor requires a value above zero.

When East's health check passes again, the monitor puts it back into rotation automatically, so failback needs no manual step.

## Settings to decide

The values in Step 2 are starting points; tune them against your recovery time target.

| Setting | Starting value | What to consider |
| --- | --- | --- |
| `MaxFailures` | 3 | Must be above 0. Higher values tolerate blips but slow passive failover. |
| `ServerUnhealthyResponse` | 502, 503, 504 | 500 is left out on purpose: if the BFF returns 500 for ordinary application errors, a few could pull East out of rotation. |
| `IntervalInSec` | 10 | Sets how fast active checks detect a failure. |
| `ConnectTimeoutInSec` / `SocketReadTimeoutInSec` | 5 / 10 | Add to detection time when the target is slow rather than down. |
| `RetryEnabled` | true (default) | A failed attempt can be retried on another server; check whether any non-idempotent calls are affected. |

How many consecutive failed checks mark a server down is not stated in the documentation I could load, so measure it in a test instead of assuming it.

## Health endpoint requirements

The existing BFF health route works as the monitor's target if it meets these conditions:

- **No JWT required:** the monitor calls the BFF directly from Apigee's runtime, not through the proxy, so the Ping JWT check does not run. Keep the route unauthenticated and restrict it by network. The `Header` element can send a static value, but it is stored in plain configuration, so avoid putting secrets there.
- **200 only when the region can serve traffic:** return a non-200 status, or time out, when it cannot.
- **Regional dependencies only:** include Cosmos DB and Redis for that region, but not global ones. If a shared dependency such as Ping is in the check, both regions fail together, East and Central are both marked down, and failover cannot help.
- **Fast and cheap:** Apigee will call it every few seconds, on top of any other probes.

## Optional: keep traffic in the same region

With the Step 2 setup, Central frontends also call East's BFF whenever East is healthy. To keep each frontend on its own region's BFF, create two target endpoints with different fallbacks and choose between them with route rules.

The frontend sends a header such as `x-region` that Apigee checks:

```xml
<RouteRule name="central">
  <Condition>request.header.x-region = "central"</Condition>
  <TargetEndpoint>central-first</TargetEndpoint>
</RouteRule>
<RouteRule name="default">
  <TargetEndpoint>east-first</TargetEndpoint>
</RouteRule>
```

The conditional rule comes first and the default rule last. In `central-first`, list `bffcentral` as the normal server and `bffeast` as the fallback; in `east-first`, the reverse.

## Deploy and test

1. Create both target servers in each Apigee environment, then deploy the proxy.
2. Confirm calls land on East. Apigee's debug trace shows the selected target, and the load balancer sets flow variables such as `loadbalancing.targetserver` (check the docs for the current list).
3. Take East down in a controlled way, either by setting its target server's `IsEnabled` to false or by stopping East's BFF, and confirm traffic moves to Central.
4. Bring East back and confirm the monitor returns it to rotation. Watch for flapping and raise the failure thresholds if traffic bounces.
5. Break only the health route and confirm failover happens even though the app is otherwise running.

## Open items and sources

The XML follows the schema in Apigee's load balancing documentation, which I could load only for Apigee Edge; a community answer confirms Apigee X supports the same health monitor. Check element support, such as `IsSSL`, and any Apigee X-specific options against the current Apigee X reference before rollout. A third-party example also used `UseTargetServerSSLInfo` in the monitor request; it is not confirmed and is left out.

Sources:

- [Load balancing across backend servers (Apigee documentation)](https://docs.apigee.com/api-platform/deploy/load-balancing-across-backend-servers)
- [Health Monitoring with Apigee X (Google Cloud community)](https://www.googlecloudcommunity.com/gc/Apigee/Health-Monitoring-with-Apigee-X/m-p/662964)
- [How to configure Apigee target server load balancing across multiple backends (OneUptime)](https://oneuptime.com/blog/post/2026-02-17-how-to-configure-apigee-target-server-load-balancing-across-multiple-backends/view)
