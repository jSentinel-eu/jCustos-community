# Running jCustos behind a reverse proxy

Status: 00.84.00 · JS-SEC-061 · CWE-348 (Use of Less Trusted Source)

Behind a reverse proxy the connection peer the application sees is the proxy,
not the client. Everything jCustos keys on the client address — brute-force
throttling (`LoginAttemptContext.clientAddress`), abuse detection, login rate
limits in the demos and the `clientAddress` field of audit lines — therefore
depends on how the client address is recovered. Done wrong, an Internet client
chooses its own address and with it the throttle bucket of any other user.

## What the framework does since 00.84.00

Every adapter resolves the client address through the `ClientAddressResolver`
SPI (`eu.jsentinel.jcustos.net`) instead of calling `getRemoteAddr()` itself:

| Adapter | Entry point | Feeds |
|---|---|---|
| Vaadin | `VaadinClientAddress.current()` (used by `LoginView`) | `SessionContext.clientAddress`, login throttles in the demos |
| REST | `RestClientAddress.resolve(request)`, `RestAccessContextFactory` attribute `clientAddress` | authorisation context, audit route |
| Standalone (CLI) | — | no network, no client address |

The default resolver, `DefaultClientAddressResolver`, returns the connection
peer and consults **no** header. That is correct when clients connect directly,
and it is the safe choice when the topology is unknown: behind a proxy all
clients collapse into the proxy's bucket, but nobody can pick another bucket.

`TrustedProxyClientAddressResolver` honours `X-Forwarded-For` **only** when the
connection peer is one of the configured trusted proxies (addresses or CIDR
ranges, IPv4 and IPv6). It reads the header from the right, skips entries that
are themselves trusted proxies and returns the first address outside the trusted
set — the address the proxy appended. Whatever a client sent in its own
`X-Forwarded-For` sits further left and is never reached. RFC 7239 `Forwarded`,
`X-Real-IP`, `X-Client-IP` and similar headers are ignored regardless of the
peer. An untrusted peer, or a proxy that appended something that is not an IP
literal, yields the peer address and a single `WARN` per resolver instance.

## Choosing a topology

Two set-ups are supported. Pick exactly one; combining them double-translates
the address.

### Topology A — jCustos resolver with trusted peers (recommended)

The servlet container keeps reporting the proxy as the peer; jCustos recovers
the client from `X-Forwarded-For` because it knows which peers to trust.

DX bootstrap (Vaadin, REST or both):

```java
VaadinSecurity.bootstrap()
    .clientAddress(ClientAddressResolver.trustedProxies("127.0.0.1", "::1"))
    // ...
    .install();
```

Without the DX builder, register the resolver programmatically or through
`META-INF/services/eu.jsentinel.jcustos.net.ClientAddressResolver`:

```java
JCustosServiceResolver.setClientAddressResolver(
    ClientAddressResolver.trustedProxies("10.0.0.0/8"));
```

Nothing has to be changed on the proxy beyond what it does anyway: Caddy,
nginx and HAProxy append the peer they saw to `X-Forwarded-For`. If several
proxies are chained, list all of them (or their range) — the resolver walks the
chain from the right.

### Topology B — Jetty `ForwardedRequestCustomizer` with stripped headers

Jetty rewrites `getRemoteAddr()` itself when `ForwardedRequestCustomizer` is
installed on the connector. jCustos then sees the translated address through
the default resolver and nothing needs configuring on the jCustos side.

The customizer honours more than `X-Forwarded-For`: RFC 7239 `Forwarded`,
`X-Forwarded-Server`, `X-Forwarded-Port` and `X-Proxied-Https` are evaluated
too, and a proxy that does not rewrite those lets the client forge them. The
proxy **must** therefore strip them. Caddy fragment for the reverse-proxy block:

```caddyfile
reverse_proxy 127.0.0.1:8080 {
    header_up -Forwarded
    header_up -X-Proxied-Https
    header_up -X-Forwarded-Server
    header_up -X-Forwarded-Port
}
```

Also restrict the customizer to the proxy with its forwarded-header trust
settings where the Jetty version offers them, and make sure the connector is
not reachable from anywhere but the proxy (bind to loopback).

### What not to do

- Do not install the Jetty customizer **and** configure trusted peers: the
  customizer already replaced the peer with the client, so the resolver would
  treat the client as an untrusted peer and log a warning on every start.
- Do not trust `0.0.0.0/0` or `::/0`. That accepts `X-Forwarded-For` from every
  client and reintroduces the forgery the SPI exists to prevent.
- Do not read `X-Real-IP` or `Forwarded` in application code. If a deployment
  only provides those, configure the proxy to emit `X-Forwarded-For` as well.

## Verifying a deployment

With the trusted-peer resolver active, a request carrying a forged header from
an untrusted peer must still be keyed on the peer:

```
curl -H 'X-Forwarded-For: 198.51.100.9' https://app.example/login
```

Audit lines (`LoginFailed`, `LoginSucceeded`, `SessionCreated`) and the
one-time warning `Client address taken from the connection peer …` show which
address the framework used. Behind the configured proxy the audit line carries
the client's public address; a direct connection to the connector carries the
connecting host.

## Related

- `FEATURES.md` — SPI table entry `ClientAddressResolver`.
- `RELEASE-NOTES-00.84.00.md` — section "Client address behind a reverse proxy
  (R2, JS-SEC-061, CWE-348)".
- Session cookie attributes and other embedded-Jetty deployment settings are
  covered by the deployment guide added with R9 of 00.84.00.
