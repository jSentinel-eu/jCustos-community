# 5-Minute Setup — REST

V00.73 fluent bootstrap for the REST adapter. The V00.72 carve-out is
gone: `.audit(...)`, `.policies(...)`, `.roles(...)` and
`.credentials(...)` are real. `.sessions(...)` on REST consumes
`SessionPolicy` / `JCustosVersionStore` / `SubjectIdResolver`, and
since 00.84.00 `.storeBacked(...)` as well: the store is handed to the
REST filters, which refuse a session whose record was revoked
(JS-SEC-131, see "Session store and revocation" below).

```xml
<dependency>
  <groupId>eu.jsentinel</groupId>
  <artifactId>jCustos-rest</artifactId>
  <version>${jcustos.version}</version>
</dependency>
<dependency>
  <groupId>eu.jsentinel</groupId>
  <artifactId>jCustos-dx-rest</artifactId>
  <version>${jcustos.version}</version>
</dependency>
<dependency>
  <groupId>eu.jsentinel</groupId>
  <artifactId>jCustos-autoservice-annotations</artifactId>
  <version>${jcustos.version}</version>
</dependency>
```

```xml
<annotationProcessorPaths>
  <path>
    <groupId>eu.jsentinel</groupId>
    <artifactId>jCustos-autoservice-processor</artifactId>
    <version>${jcustos.version}</version>
  </path>
  <path>
    <groupId>eu.jsentinel</groupId>
    <artifactId>jCustos-autoservice-annotations</artifactId>
    <version>${jcustos.version}</version>
  </path>
</annotationProcessorPaths>
```

```java
@JCustosAutoService(AuthenticationService.class)
public final class TokenAuth implements AuthenticationService<Token, User> { /* ... */ }

@JCustosAutoService(AuthorizationService.class)
public final class Authz implements AuthorizationService<User> { /* ... */ }

@JCustosAutoService(RestSubjectResolver.class)
public final class HeaderResolver implements RestSubjectResolver { /* ... */ }
```

```java
import eu.jsentinel.jcustos.dx.rest.bootstrap.RestSecurity;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;

var runtime = RestSecurity.bootstrap()
    .mode(JCustosBootstrapMode.PRODUCTION)
    .audit(a -> a.logging().ringBuffer(256))
    .policies(p -> p.register(myDocumentPolicy()))
    .install();
System.out.println(runtime.log());
```

Handlers stay as before — the resolver and decision mapper auto-defaults
to `HttpStatusDecisionMapper` and a generic-strings error body strategy.
Every 401 of the three REST filters is rendered through that mapper,
with a `WWW-Authenticate: Bearer` challenge (`SessionStale` for a
drifted session) and an audit event (JS-SEC-086). A 401 your own
handler writes — a failed login, say — should go through
`RestDecisionContext.mapperOrDefault()` too, so it carries the same challenge and body.

## Adapter checklist (00.84.00)

- **Every header line.** Build `RestRequest.headers()` with
  `RestHeaderLines.joined(lines)`, override `headerValues(name)` with
  `RestHeaderLines.values(lines, name)`, and call
  `RestHeaderLines.rejectDuplicates(lines, response)` before any filter
  runs: a repeated `Authorization`, `X-Api-Key` or `Cookie` is a `400`
  (JS-SEC-113).
- **Handler class.** Call
  `authorizeAndHandle(request, response, handler, method, handlerClass)`;
  the overloads without the handler class cannot see the restriction of
  a class whose method is inherited (JS-SEC-114).
- **Session reference.** Name a session by `SessionRef.of(token)` in
  audit events, session records and admin views — never by the token
  (JS-SEC-117).
- **Login protocol.** Every allowed `beforeAttempt` is followed by
  exactly one of `confirmSuccess`, `recordFailure` or `abandonAttempt`;
  a verification the KDF limiter shed (`CredentialVerificationUnavailableException`)
  is answered with 503 or 429 and counts nothing (JS-SEC-123, -126).
  Login throttling is on by default (JS-SEC-124).
- **Deny-by-default.** `.denyByDefault(true)` and `@PublicRoute` on the
  public handlers; `STRICT` requires it, and a `LogoutService`
  (`.logout(...)`).

`demo-jcustos-rest` (and the `jcustos-rest` skill) shows all of it on a
JDK `HttpServer`.

## Optional sub-builders

| Sub-builder | REST behaviour |
|---|---|
| `.audit(...)` | Full — composes `LoggingAuditSink`, `RingBufferAuditSink`, `StoreBackedJCustosAuditService` as in Vaadin |
| `.policies(...)` | Full — registers policies and resource resolvers into `PolicyRegistry` |
| `.roles(...)` | `.hierarchy(...)` only (V00.73 deliberately keeps `RolePermissionMapping` out) |
| `.credentials(...)` | `.passwordHasher(...)` wires the legacy `PasswordHasher` slot; `.hashing(...)`, `.modern()` and `.pbkdf2Defaults()` wire the V00.71 pipeline into `JCustosServiceResolver.credentialHashingService()` (00.84.00, JS-SEC-073). `.pepper(...)`, `.credentialStore(...)`, `.passwordChange(...)` and `.passwordReset(...)` are recorded only and reported as `dx/credential-<entry>-recorded-not-wired` (WARNING; STRICT → ERROR) — compose the pepper into `.hashing(PasswordHashingServices.defaults(policy, limiter, pepper))` and hand the rest to your own wiring. `.modern()` requires `jCustos-crypto-bc` |
| `.sessions(...)` | `SessionPolicy` / `JCustosVersionStore` / `SubjectIdResolver`; `.storeBacked(...)` publishes the store to `RestSessionRevocation` (00.84.00, JS-SEC-131) |

## Session store and revocation (00.84.00)

With `.sessions(s -> s.storeBacked(store))` and a resolver that
implements `RestSubjectResolver.resolveSessionId`, the three REST
filters — authentication, authorisation and the version filter — look
up the session record before the handler runs. A record with the status `REVOKED`, or one that was seen
on an earlier request and is gone, ends the session: 401 through the
decision mapper and a `SessionInvalidated` audit event with the reason
`Revoked`. Save the record at login under a non-secret key —
`SessionId.of(SessionRef.of(token))` — never under the token itself.
Several nodes revoke by status, or switch on
`RestSessionRevocation.requireRecord(true)`.

## STRICT mode

`mode(STRICT)` breaks on the three V00.72-to-V00.73 promotions
(`secure-route/unknown-policy`,
`session-management-view-without-session-store`,
`security-version-without-subject-id-resolver`) plus every new V00.73
sub-builder validation code (`audit/missing-service`,
`sessions/missing-store`, `credentials/modern-without-bc`, …).
Since 00.84.00 it also refuses to boot without `.denyByDefault(true)`
(`authorization/allow-by-omission`), without an audit service
(`audit/noop-fallback`) and without a `LogoutService`
(`logout/missing-service`). Services registered through
`META-INF/services` count: the bootstrap lists them as
`spi-registered` instead of reporting `missing-authentication-service`.

## Programmatic health (V00.74.10)

For a minimal `/health` REST handler, use the V00.74.10 tooling methods
on the `runtime` returned by `install()` — no JSON library on the
classpath required, the encoder is internal:

```java
import com.svenruppert.dependencies.core.net.HttpStatus;
import com.svenruppert.dependencies.core.net.MediaType;

public final class HealthHandler implements RestHandler {
  private final JCustosRuntime runtime;
  public HealthHandler(JCustosRuntime runtime) {
    this.runtime = runtime;
  }
  @Override public void handle(RestRequest req, RestResponse resp) {
    var health = runtime.healthCheck();
    resp.setStatusCode(health.hasErrors()
        ? HttpStatus.SERVICE_UNAVAILABLE
        : HttpStatus.OK);
    resp.setContentType(MediaType.APPLICATION_JSON);
    resp.write(runtime.toJson());
  }
}
```

`runtime.summary()` is the single-line companion for boot banners;
`runtime.toMap()` returns the same data as `toJson()` but as an
unmodifiable, insertion-ordered `Map<String, Object>` so you can route
through any serialiser already on your classpath. All four methods
are marked `@ExperimentalJCustosApi` until V00.76.

## Persistence pair (V00.74.20)

When the REST service should persist audit / sessions / application
domain data, open a `JCustosStoragePair` at startup and feed its
framework half into the bootstrap:

```java
JCustosStoragePair pair = JCustosStorageFactory.openAt(Path.of("data"));
Runtime.getRuntime().addShutdownHook(new Thread(pair::close, "jcustos-pair-close"));

RestSecurity.bootstrap()
    .audit(a    -> a.storeBacked(pair.framework().auditEventStore()))
    .sessions(s -> s.storeBacked(pair.framework().sessionStore()))
    .install();

// pair.app() holds the application's own EmbeddedStorageManager —
// use pair.app().root() / setRoot(…) / store(…) for domain data.
```

The pair's two-phase `close()` shuts app first, framework second; the
framework close-attempt always runs so its lock file is released
even if app shutdown throws.

## JWT validation (V00.76)

Add `jCustos-jwt` to the classpath and wire `.jwt(...)` to validate inbound
JWT bearer tokens against a JWKS endpoint. The DX layer never compiles against a
JOSE library — it discovers the Nimbus `JwtValidatorFactory` via `ServiceLoader`:

```java
RestSecurity.bootstrap()
    .mode(SecurityBootstrapMode.PRODUCTION)
    .jwt(j -> j
        .jwksUri(URI.create("https://idp.example/.well-known/jwks.json"))
        .algorithmProfile(AlgorithmProfile.STRICT_MODERN)  // RS256/PS256/ES256/EdDSA
        .issuer("https://idp.example/")                    // exact-match iss
        .audience("api.example")                           // any-match aud
        .clockSkew(Duration.ofSeconds(30)))                // exp/nbf leeway
    .install();
```

A `RestSubjectResolver` then validates the token via the resolver SPI:

```java
JwtValidator validator = JCustosServiceResolver.findJwtValidator().orElseThrow();
return new BearerTokenExtractor().extract(req)
    .flatMap(raw -> validator.validate(raw).toOptional())
    .map(validated -> {
      TokenCredentialStores.current().bind(OidcAccessToken.fromValidated(raw, validated));
      return toSubject(validated);
    });
```

Notes:

- the algorithm **allow-list is mandatory** — pass `.algorithmProfile(...)` or
  `.algorithmAllowList(...)`, or STRICT/PRODUCTION reject the bootstrap
  (`jwt/no-algorithm-allow-list`). HMAC and `alg: none` are never accepted.
- a fully pre-built validator is the alternative to the `.jwksUri` path:
  `.jwt(j -> j.validator(myValidator))` (the two are mutually exclusive).
- the JWKS client caches by `Cache-Control: max-age` (default 5 min), refreshes
  once on a `kid` miss (single-flight), and negative-caches endpoint failures.
  Since 00.84.00 it drops the key set after 24 hours without a successful fetch
  (`jwks/stale-keys-dropped`), skips keys that may not verify signatures (`use`
  other than `sig`, `key_ops` without `verify`) and RSA keys below 2048 bit
  (JS-SEC-149).
- a non-`https` JWKS URI is a STRICT error (`jwks/uri-not-https`).

See `demo-rest`'s `/api/jwt/demo` route for an end-to-end example.
