# Running jCustos behind a reverse proxy

Status: 00.84.00 · JS-SEC-061, JS-SEC-113 · CWE-348 (Use of Less Trusted Source)

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
| Vaadin | `VaadinClientAddress.current()` (used by `LoginView`) | `SessionContext.clientAddress`, the login-attempt policy `LoginView` runs (JS-SEC-124) |
| REST | `RestClientAddress.resolve(request)`, `RestAccessContextFactory` attribute `clientAddress` | authorisation context, audit route |
| Standalone (CLI) | — | no network, no client address; a standalone server that knows its peer passes it to `StandaloneLoginFlow.login(credentials, username, clientAddress)`, which feeds the login-attempt policy and its address counter |

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

Caddy and nginx (`proxy_add_x_forwarded_for`) need nothing beyond what they do
anyway: they merge the peer they saw into the existing `X-Forwarded-For` value,
so the application receives one line whose last entry is the proxy's. If
several proxies are chained, list all of them (or their range) — the resolver
walks the chain from the right.

HAProxy needs one line of configuration; see the next section.

### Several `X-Forwarded-For` lines (HAProxy `option forwardfor`)

HTTP allows a header to arrive on more than one line. HAProxy's
`option forwardfor` does not merge: it **adds its own `X-Forwarded-For` line
after** whatever the client sent. A client that sends

```
X-Forwarded-For: 10.66.66.66
```

reaches the application as

```
X-Forwarded-For: 10.66.66.66
X-Forwarded-For: 203.0.113.50
```

The resolver is only correct when it sees **both** lines: read from the right,
the proxy's entry `203.0.113.50` wins and the client's line is never reached.
An adapter that hands on only the first line turns this upside down — the
forged value becomes the client address, with everything that hangs on it:
throttle buckets, audit lines and `ipAllowList` policies (JS-SEC-113).

What jCustos does since 00.84.00:

- The Vaadin adapter always read every line (`getHeaders(name)`).
- The REST adapter resolves through `RestRequest.headerValues(name)`, which
  returns one entry per header line. `RestRequest.headers()` stays
  single-valued; its contract now says that repeated list headers are joined
  with `", "` (RFC 9110 §5.3) and that a repeated `Authorization`, `X-Api-Key`
  or `Cookie` is rejected with `400`. `RestHeaderLines` (`jCustos-rest`)
  implements both for an adapter.

What the integration has to check:

- **Your `RestRequest` adapter.** If it is built from a multi-valued header
  structure (JDK `HttpExchange`, servlet request), it must not reduce a header
  to `values.get(0)`. Either override `headerValues(name)` to return all lines,
  or build `headers()` with `RestHeaderLines.joined(lines)` — the default
  `headerValues` then sees the joined value. Adapters written against a release
  before 00.84.00, including copies of the demo `Router`, keep the first line
  and are affected.
- **The proxy, as an immediate and independent measure.** Let HAProxy replace
  the header instead of adding to it, so that a client-supplied value never
  reaches the application at all:

  ```haproxy
  # instead of: option forwardfor
  http-request set-header X-Forwarded-For %[src]
  ```

  This is the recommended HAProxy configuration whatever the adapter does. If
  HAProxy sits behind another trusted proxy whose chain must be preserved,
  delete the client's lines at the outermost proxy and use `option forwardfor`
  only on the inner ones.

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

Repeat the check **through the proxy** with a forged header. The address the
framework records must be the one the proxy saw, never `198.51.100.9`:

```
curl -H 'X-Forwarded-For: 198.51.100.9' https://app.example/api/whoami
```

If the forged value shows up, the proxy adds a separate header line and the
REST adapter in use drops it — see "Several `X-Forwarded-For` lines" above.
A request with two `Authorization` lines must be answered with `400`:

```
curl -H 'Authorization: Bearer a' -H 'Authorization: Bearer b' https://app.example/api/whoami
```

## Related

- [reverse-proxy-embedded-jetty.md](reverse-proxy-embedded-jetty.md) — embedded Jetty 12 behind the
  proxy: session cookie attributes, server banner, `@ClientCallable`, request id, address limit,
  origin guard.
- `FEATURES.md` — SPI table entry `ClientAddressResolver`.
- `RELEASE-NOTES-00.84.00.md` — section "Client address behind a reverse proxy
  (R2, JS-SEC-061, CWE-348)".
- Session cookie attributes: `docs/dx/5-minute-setup-vaadin.md`, section 3
  ("Session cookie"); every Vaadin demo's `web.xml` sets an application-specific
  name, `HttpOnly`, `Secure` and `SameSite=Lax`.
