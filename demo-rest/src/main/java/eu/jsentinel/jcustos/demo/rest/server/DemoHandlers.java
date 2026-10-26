/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.jsentinel.jcustos.demo.rest.server;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.annotations.RequiresAnyPermission;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPolicy;
import eu.jsentinel.jcustos.demo.rest.domain.DemoOwnedDocument;
import eu.jsentinel.jcustos.demo.rest.domain.DemoOwnedDocumentStore;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.credential.abuse.AbuseAttemptContext;
import eu.jsentinel.jcustos.credential.abuse.AbuseAttemptType;
import eu.jsentinel.jcustos.credential.abuse.AbuseDecision;
import eu.jsentinel.jcustos.credential.abuse.AbuseDetectionService;
import eu.jsentinel.jcustos.credential.abuse.AbuseLimitsPolicy;
import eu.jsentinel.jcustos.credential.abuse.AttemptOutcome;
import eu.jsentinel.jcustos.credential.abuse.InMemoryAbuseDetectionService;
import eu.jsentinel.jcustos.credential.compromised.CheckFailurePolicy;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordChecker;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordPolicy;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordResult;
import eu.jsentinel.jcustos.credential.compromised.LocalBlocklistCompromisedPasswordChecker;
import eu.jsentinel.jcustos.credential.compromised.NoOpCompromisedPasswordChecker;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.logout.LogoutScope;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.NoopLoginAttemptPolicy;
import eu.jsentinel.jcustos.demo.rest.domain.DemoDocument;
import eu.jsentinel.jcustos.demo.rest.domain.DemoDocumentStore;
import eu.jsentinel.jcustos.demo.rest.domain.DemoRole;
import eu.jsentinel.jcustos.demo.rest.domain.DemoUser;
import eu.jsentinel.jcustos.demo.rest.domain.DemoUserStore;
import eu.jsentinel.jcustos.demo.rest.shared.DemoEndpoints;
import eu.jsentinel.jcustos.authorization.api.operations.SecuredOperationDescriptor;
import eu.jsentinel.jcustos.demo.rest.shared.DemoJson;
import eu.jsentinel.jcustos.jwt.api.JwtValidator;
import eu.jsentinel.jcustos.jwt.api.ValidatedJwt;
import eu.jsentinel.jcustos.rest.BearerTokenExtractor;
import eu.jsentinel.jcustos.rest.BodyRestRequest;
import eu.jsentinel.jcustos.rest.RestClientAddress;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestResponse;
import eu.jsentinel.jcustos.accountlifecycle.PasswordResetService;
import eu.jsentinel.jcustos.accountlifecycle.PasswordResetTokenRecord;
import eu.jsentinel.jcustos.authentication.ApiKeyRecord;
import eu.jsentinel.jcustos.authentication.ApiKeyStore;
import eu.jsentinel.jcustos.authentication.TokenService;
import eu.jsentinel.jcustos.credential.token.TokenHasher;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.ratelimiting.RateLimitDecision;
import eu.jsentinel.jcustos.ratelimiting.RateLimitKey;
import eu.jsentinel.jcustos.ratelimiting.RateLimitPolicy;
import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.JCustosVersionStore;

import java.time.Duration;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Demo REST handlers. Permission-protected handlers carry
 * {@link RequiresPermission} so that {@code RestAuthorizationFilter} can
 * enforce them. Authenticated-only endpoints are handled by the router.
 */
public final class DemoHandlers {

  private final DemoUserStore userStore;
  private final DemoTokenStore tokenStore;
  private final DemoDocumentStore documents;
  private final DemoOperationRegistry registry;
  private final DemoSubjectResolver subjectResolver;
  private final LoginAttemptPolicy loginAttemptPolicy;
  private final AbuseDetectionService abuseDetection;
  private final CompromisedPasswordChecker compromisedChecker;
  private final CompromisedPasswordPolicy compromisedPolicy;
  private final JCustosVersionStore securityVersionStore;
  private final PasswordResetService passwordResetService;
  private final RateLimitPolicy loginRateLimit;
  private final ApiKeyStore apiKeyStore;
  private final TokenHasher apiKeyHasher;
  private final TokenService tokenService;
  /**
   * Pure data accessor for the Policy-DSL example — the policy
   * machinery does the authorization, this field only feeds the
   * inspect-handler with the response body. Stays nullable so the
   * eight-argument constructor (used by tests) still compiles.
   */
  private DemoOwnedDocumentStore ownedDocumentStore;

  public DemoHandlers(
      DemoUserStore userStore,
      DemoTokenStore tokenStore,
      DemoDocumentStore documents,
      DemoOperationRegistry registry,
      DemoSubjectResolver subjectResolver) {
    this(userStore, tokenStore, documents, registry, subjectResolver,
        NoopLoginAttemptPolicy.INSTANCE);
  }

  public DemoHandlers(
      DemoUserStore userStore,
      DemoTokenStore tokenStore,
      DemoDocumentStore documents,
      DemoOperationRegistry registry,
      DemoSubjectResolver subjectResolver,
      LoginAttemptPolicy loginAttemptPolicy) {
    this(userStore, tokenStore, documents, registry, subjectResolver,
        loginAttemptPolicy,
        defaultAbuseDetection(),
        defaultCompromisedChecker(),
        CompromisedPasswordPolicy.defaults());
  }

  /**
   * Wires {@code DemoHandlers} with a shared
   * {@link JCustosVersionStore} so role mutations bump versions
   * against the same instance that the
   * {@link eu.jsentinel.jcustos.rest.RestJCustosVersionFilter}
   * checks against.
   */
  public DemoHandlers(
      DemoUserStore userStore,
      DemoTokenStore tokenStore,
      DemoDocumentStore documents,
      DemoOperationRegistry registry,
      DemoSubjectResolver subjectResolver,
      LoginAttemptPolicy loginAttemptPolicy,
      JCustosVersionStore securityVersionStore) {
    this(userStore, tokenStore, documents, registry, subjectResolver,
        loginAttemptPolicy, securityVersionStore, null);
  }

  /**
   * Wires {@code DemoHandlers} with both the shared
   * {@link JCustosVersionStore} <em>and</em> the Phase-7a
   * {@link PasswordResetService}. Pass {@code null} for
   * {@code passwordResetService} to leave the password-reset
   * endpoints disabled (they will return 503).
   */
  public DemoHandlers(
      DemoUserStore userStore,
      DemoTokenStore tokenStore,
      DemoDocumentStore documents,
      DemoOperationRegistry registry,
      DemoSubjectResolver subjectResolver,
      LoginAttemptPolicy loginAttemptPolicy,
      JCustosVersionStore securityVersionStore,
      PasswordResetService passwordResetService) {
    this(userStore, tokenStore, documents, registry, subjectResolver,
        loginAttemptPolicy,
        defaultAbuseDetection(),
        defaultCompromisedChecker(),
        CompromisedPasswordPolicy.defaults(),
        securityVersionStore,
        passwordResetService);
  }

  /**
   * Full constructor including the V00.70 Phase-7c per-IP login
   * {@link RateLimitPolicy}. Pass {@code null} to leave the
   * additional rate-limit layer off (the per-username
   * {@link LoginAttemptPolicy} still applies).
   */
  public DemoHandlers(
      DemoUserStore userStore,
      DemoTokenStore tokenStore,
      DemoDocumentStore documents,
      DemoOperationRegistry registry,
      DemoSubjectResolver subjectResolver,
      LoginAttemptPolicy loginAttemptPolicy,
      JCustosVersionStore securityVersionStore,
      PasswordResetService passwordResetService,
      RateLimitPolicy loginRateLimit) {
    this(userStore, tokenStore, documents, registry, subjectResolver,
        loginAttemptPolicy,
        defaultAbuseDetection(),
        defaultCompromisedChecker(),
        CompromisedPasswordPolicy.defaults(),
        securityVersionStore,
        passwordResetService,
        loginRateLimit,
        null,
        null,
        null);
  }

  /**
   * Full constructor including the V00.70 Phase-7b API-key admin
   * endpoints. Pass {@code null} for {@code apiKeyStore} /
   * {@code apiKeyHasher} to leave the admin endpoints disabled
   * (they will return 503).
   */
  public DemoHandlers(
      DemoUserStore userStore,
      DemoTokenStore tokenStore,
      DemoDocumentStore documents,
      DemoOperationRegistry registry,
      DemoSubjectResolver subjectResolver,
      LoginAttemptPolicy loginAttemptPolicy,
      JCustosVersionStore securityVersionStore,
      PasswordResetService passwordResetService,
      RateLimitPolicy loginRateLimit,
      ApiKeyStore apiKeyStore,
      TokenHasher apiKeyHasher) {
    this(userStore, tokenStore, documents, registry, subjectResolver,
        loginAttemptPolicy, securityVersionStore, passwordResetService,
        loginRateLimit, apiKeyStore, apiKeyHasher, null);
  }

  /**
   * Full constructor including the V00.70 Phase-7b
   * {@link TokenService} for rotating refresh tokens.
   */
  public DemoHandlers(
      DemoUserStore userStore,
      DemoTokenStore tokenStore,
      DemoDocumentStore documents,
      DemoOperationRegistry registry,
      DemoSubjectResolver subjectResolver,
      LoginAttemptPolicy loginAttemptPolicy,
      JCustosVersionStore securityVersionStore,
      PasswordResetService passwordResetService,
      RateLimitPolicy loginRateLimit,
      ApiKeyStore apiKeyStore,
      TokenHasher apiKeyHasher,
      TokenService tokenService) {
    this(userStore, tokenStore, documents, registry, subjectResolver,
        loginAttemptPolicy,
        defaultAbuseDetection(),
        defaultCompromisedChecker(),
        CompromisedPasswordPolicy.defaults(),
        securityVersionStore,
        passwordResetService,
        loginRateLimit,
        apiKeyStore,
        apiKeyHasher,
        tokenService);
  }

  public DemoHandlers(
      DemoUserStore userStore,
      DemoTokenStore tokenStore,
      DemoDocumentStore documents,
      DemoOperationRegistry registry,
      DemoSubjectResolver subjectResolver,
      LoginAttemptPolicy loginAttemptPolicy,
      AbuseDetectionService abuseDetection,
      CompromisedPasswordChecker compromisedChecker,
      CompromisedPasswordPolicy compromisedPolicy) {
    this(userStore, tokenStore, documents, registry, subjectResolver,
        loginAttemptPolicy, abuseDetection, compromisedChecker, compromisedPolicy,
        new InMemoryJCustosVersionStore());
  }

  public DemoHandlers(
      DemoUserStore userStore,
      DemoTokenStore tokenStore,
      DemoDocumentStore documents,
      DemoOperationRegistry registry,
      DemoSubjectResolver subjectResolver,
      LoginAttemptPolicy loginAttemptPolicy,
      AbuseDetectionService abuseDetection,
      CompromisedPasswordChecker compromisedChecker,
      CompromisedPasswordPolicy compromisedPolicy,
      JCustosVersionStore securityVersionStore) {
    this(userStore, tokenStore, documents, registry, subjectResolver,
        loginAttemptPolicy, abuseDetection, compromisedChecker,
        compromisedPolicy, securityVersionStore, null);
  }

  public DemoHandlers(
      DemoUserStore userStore,
      DemoTokenStore tokenStore,
      DemoDocumentStore documents,
      DemoOperationRegistry registry,
      DemoSubjectResolver subjectResolver,
      LoginAttemptPolicy loginAttemptPolicy,
      AbuseDetectionService abuseDetection,
      CompromisedPasswordChecker compromisedChecker,
      CompromisedPasswordPolicy compromisedPolicy,
      JCustosVersionStore securityVersionStore,
      PasswordResetService passwordResetService) {
    this(userStore, tokenStore, documents, registry, subjectResolver,
        loginAttemptPolicy, abuseDetection, compromisedChecker,
        compromisedPolicy, securityVersionStore, passwordResetService, null,
        null, null, null);
  }

  public DemoHandlers(
      DemoUserStore userStore,
      DemoTokenStore tokenStore,
      DemoDocumentStore documents,
      DemoOperationRegistry registry,
      DemoSubjectResolver subjectResolver,
      LoginAttemptPolicy loginAttemptPolicy,
      AbuseDetectionService abuseDetection,
      CompromisedPasswordChecker compromisedChecker,
      CompromisedPasswordPolicy compromisedPolicy,
      JCustosVersionStore securityVersionStore,
      PasswordResetService passwordResetService,
      RateLimitPolicy loginRateLimit,
      ApiKeyStore apiKeyStore,
      TokenHasher apiKeyHasher,
      TokenService tokenService) {
    this.userStore = userStore;
    this.tokenStore = tokenStore;
    this.documents = documents;
    this.registry = registry;
    this.subjectResolver = subjectResolver;
    this.loginAttemptPolicy = Objects.requireNonNull(loginAttemptPolicy, "loginAttemptPolicy");
    this.abuseDetection = Objects.requireNonNull(abuseDetection, "abuseDetection");
    this.compromisedChecker = Objects.requireNonNull(compromisedChecker, "compromisedChecker");
    this.compromisedPolicy = Objects.requireNonNull(compromisedPolicy, "compromisedPolicy");
    this.securityVersionStore = Objects.requireNonNull(securityVersionStore,
        "securityVersionStore");
    this.passwordResetService = passwordResetService;
    this.loginRateLimit = loginRateLimit;
    this.apiKeyStore = apiKeyStore;
    this.apiKeyHasher = apiKeyHasher;
    this.tokenService = tokenService;
  }

  /** Test seam — exposes the wired store so integration tests can bump. */
  public JCustosVersionStore securityVersionStore() {
    return securityVersionStore;
  }

  /**
   * Server-side setter for the {@link DemoOwnedDocumentStore} that
   * backs the {@code /api/owned-documents/{id}} endpoint. Used by
   * {@link DemoRestServer} to inject the singleton store after
   * constructor wiring without growing yet another overload.
   */
  public void setOwnedDocumentStore(DemoOwnedDocumentStore store) {
    this.ownedDocumentStore = store;
  }

  /**
   * V00.70 Policy-DSL example —
   * {@code GET /api/owned-documents/{id}}. The handler itself only
   * resolves the document and returns it; authorization is owned by
   * {@code @RequiresPolicy("document.owner-or-admin")} on the
   * declared element. {@link DemoHttpRouter} threads the
   * {@code ResourceRef} into the {@code AccessContext.attributes()}
   * map so the {@code RequiresPolicyEvaluator} can resolve owner /
   * admin paths through {@link DemoOwnedDocumentResolver}.
   */
  @RequiresPolicy(DemoPolicies.DOCUMENT_OWNER_OR_ADMIN)
  public void inspectOwnedDocument(RestRequest request, RestResponse response) {
    if (ownedDocumentStore == null) {
      writeError(response, HttpStatus.SERVICE_UNAVAILABLE);
      return;
    }
    String path = request.path();
    String prefix = eu.jsentinel.jcustos.demo.rest.shared.DemoEndpoints.OWNED_DOCUMENT_BY_ID;
    if (!path.startsWith(prefix) || path.length() <= prefix.length()) {
      writeError(response, HttpStatus.NOT_FOUND);
      return;
    }
    String id = path.substring(prefix.length());
    Optional<DemoOwnedDocument> doc;
    try {
      doc = ownedDocumentStore.findById(Long.parseLong(id));
    } catch (NumberFormatException e) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    if (doc.isEmpty()) {
      writeError(response, HttpStatus.NOT_FOUND);
      return;
    }
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("id", doc.get().id());
    payload.put("title", doc.get().title());
    payload.put("ownerId", doc.get().ownerId());
    response.status(HttpStatus.OK.code());
    response.body(DemoJson.encode(payload));
  }

  /**
   * Demo-grade abuse detector. Defaults to the V00.71 in-memory
   * sliding-window service, sharing audit through the resolved
   * {@link JCustosAuditService}.
   */
  private static AbuseDetectionService defaultAbuseDetection() {
    JCustosAuditService audit = JCustosServiceResolver.securityAuditService();
    return new InMemoryAbuseDetectionService(
        AbuseLimitsPolicy.defaults(), audit);
  }

  /**
   * Demo-grade compromised-password checker. Ships with a short
   * blocklist of obviously-bad entries that the user-create flow
   * rejects up-front. Operators upgrading to {@code security-credentials-hibp}
   * swap this for a {@code HaveIBeenPwnedCompromisedPasswordChecker}.
   */
  private static CompromisedPasswordChecker defaultCompromisedChecker() {
    return new LocalBlocklistCompromisedPasswordChecker(
        List.of(
            "password", "password1", "password123",
            "qwerty", "qwerty123", "letmein",
            "admin", "admin123", "administrator",
            "welcome", "welcome1",
            "12345678", "123456789", "abc12345",
            "iloveyou", "monkey", "dragon",
            "hunter2", "trustno1"));
  }

  public void login(RestRequest request, RestResponse response) {
    Map<String, Object> body;
    try {
      body = DemoJson.decodeObject(requireBody(request));
    } catch (RuntimeException e) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    Object usernameValue = body.get("username");
    Object passwordValue = body.get("password");
    if (!(usernameValue instanceof String username) || !(passwordValue instanceof String password)) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }

    // JS-SEC-061 (CWE-348): resolved through the registered ClientAddressResolver.
    String clientAddress = RestClientAddress.resolve(request).orElse(null);

    // V00.70 Phase-7c per-IP rate limit — refuses with 429 + Retry-After
    // before the per-username brute-force policy. Configured for an order
    // of magnitude more attempts than the brute-force window: it catches
    // distributed credential stuffing rather than single-user lockouts.
    if (loginRateLimit != null) {
      RateLimitKey key = new RateLimitKey(TenantId.DEFAULT,
          "login:ip:" + (clientAddress == null ? "unknown" : clientAddress));
      RateLimitDecision decision = loginRateLimit.tryAcquire(key);
      if (decision instanceof RateLimitDecision.Throttled throttled) {
        response.header("Retry-After",
            Long.toString(Math.max(1L, throttled.retryAfter().toSeconds())));
        writeError(response, HttpStatus.TOO_MANY_REQUESTS);
        return;
      }
    }

    LoginAttemptContext attempt = LoginAttemptContext.now(username, clientAddress, null);
    AbuseAttemptContext abuseContext = new AbuseAttemptContext(
        AbuseAttemptType.LOGIN,
        Optional.of(username),
        Optional.ofNullable(clientAddress),
        TenantId.DEFAULT,
        Instant.now(Clock.systemUTC()));

    AbuseDecision abuseDecision = abuseDetection.evaluate(abuseContext);
    if (abuseDecision instanceof AbuseDecision.Block block) {
      response.header("Retry-After",
          Long.toString(Math.max(1L, block.retryAfter().toSeconds())));
      writeError(response, HttpStatus.TOO_MANY_REQUESTS);
      return;
    }

    LoginAttemptDecision decision = loginAttemptPolicy.beforeAttempt(attempt);
    if (decision instanceof LoginAttemptDecision.LockedOut lockout) {
      response.header("Retry-After",
          Long.toString(Math.max(1L, lockout.remaining().toSeconds())));
      writeError(response, HttpStatus.TOO_MANY_REQUESTS);
      return;
    }

    Optional<DemoUser> user = userStore.authenticate(username, password);
    if (user.isEmpty()) {
      loginAttemptPolicy.recordFailure(attempt);
      abuseDetection.recordOutcome(abuseContext, AttemptOutcome.FAILURE);
      writeError(response, HttpStatus.UNAUTHORIZED);
      return;
    }
    loginAttemptPolicy.recordSuccess(attempt);
    abuseDetection.recordOutcome(abuseContext, AttemptOutcome.SUCCESS);
    DemoUser u = user.get();
    JCustosVersion snapshot = securityVersionStore.current(
        new JCustosVersionKey(TenantId.DEFAULT, SubjectId.of(u.username())));
    String token = tokenStore.issue(u, snapshot);
    auditLoginSucceeded(u.username(), clientAddress, token);
    JCustosSubject subject = subjectResolver
        .resolveSubject(withAuth(request, token))
        .orElseThrow();
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("token", token);
    payload.put("displayName", u.displayName());
    payload.put("roles", subject.roles().stream().map(r -> r.value()).sorted().toList());
    payload.put("permissions",
        subject.permissions().stream().map(p -> p.value()).sorted().toList());
    response.status(HttpStatus.OK.code());
    response.body(DemoJson.encode(payload));
  }

  private static void auditLoginSucceeded(String username, String clientAddress, String token) {
    JCustosAuditService sink = JCustosServiceResolver.securityAuditService();
    try {
      sink.publish(new LoginSucceeded(
          Instant.now(Clock.systemUTC()), username, clientAddress, token));
    } catch (RuntimeException ignored) {
      // never block a successful login because the audit sink failed
    }
  }

  public void me(RestRequest request, RestResponse response) {
    JCustosSubject subject = subjectResolver.resolveSubject(request).orElseThrow();
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("subjectId", subject.subjectId());
    payload.put("displayName", subject.displayName());
    payload.put("roles", subject.roles().stream().map(r -> r.value()).sorted().toList());
    payload.put("permissions",
        subject.permissions().stream().map(p -> p.value()).sorted().toList());
    response.status(HttpStatus.OK.code());
    response.body(DemoJson.encode(payload));
  }

  /**
   * V00.76 — validate an inbound JWT bearer token against the configured
   * {@link JwtValidator} (wired via {@code .jwt(...)} bootstrap, resolved at
   * runtime through {@code JCustosServiceResolver}). On success returns the
   * issuer / subject / algorithm; on a missing validator, or a missing or
   * invalid token, it returns 401. The raw token is never echoed.
   */
  public void jwtDemo(RestRequest request, RestResponse response) {
    Optional<JwtValidator> validator = JCustosServiceResolver.findJwtValidator();
    Optional<String> bearer = new BearerTokenExtractor().extract(request);
    if (validator.isEmpty() || bearer.isEmpty()) {
      response.status(HttpStatus.UNAUTHORIZED.code());
      response.body("Unauthorized");
      return;
    }
    Optional<ValidatedJwt> validated = validator.get().validate(bearer.get()).toOptional();
    if (validated.isEmpty()) {
      response.status(HttpStatus.UNAUTHORIZED.code());
      response.body("Unauthorized");
      return;
    }
    ValidatedJwt jwt = validated.get();
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("issuer", jwt.issuer().orElse(null));
    payload.put("subject", jwt.subject().orElse(null));
    payload.put("algorithm", jwt.header().alg());
    response.status(HttpStatus.OK.code());
    response.body(DemoJson.encode(payload));
  }

  public void operations(RestRequest request, RestResponse response) {
    JCustosSubject subject = subjectResolver.resolveSubject(request).orElseThrow();
    List<Map<String, Object>> ops = registry.visibleFor(subject).stream()
        .map(DemoHandlers::descriptorToJson)
        .toList();
    response.status(HttpStatus.OK.code());
    response.body(DemoJson.encode(Map.of("operations", ops)));
  }

  public void logout(RestRequest request, RestResponse response) {
    Optional<String> token = DemoSubjectResolver.extractToken(request);
    Optional<DemoUser> user = token.flatMap(tokenStore::resolve);
    token.ifPresent(tokenStore::revoke);
    user.ifPresent(u -> JCustosServiceResolver.logoutService()
        .logout(SubjectId.of(u.username()), LogoutScope.CurrentSession));
    response.status(HttpStatus.OK.code());
    response.body(DemoJson.encode(Map.of("status", "logged-out")));
  }

  /**
   * V00.70 Phase-7b — mints a long-lived API key.
   * <p>
   * Body: {@code {"name":"…", "subjectId":"…", "scopes":[…]}}.
   * Returns {@code {"plainKey":"…","keyHash":"…","name":"…",
   * "subjectId":"…","scopes":[…],"createdAt":"…"}} — the plain key
   * is shown exactly once; only its hash is persisted. Clients pass
   * the plain value via {@code X-Api-Key} on subsequent requests.
   * Requires {@code admin:roles}.
   */
  @RequiresPermission("admin:roles")
  public void createApiKey(RestRequest request, RestResponse response) {
    if (apiKeyStore == null || apiKeyHasher == null) {
      writeError(response, HttpStatus.SERVICE_UNAVAILABLE);
      return;
    }
    Map<String, Object> body;
    try {
      body = DemoJson.decodeObject(requireBody(request));
    } catch (RuntimeException e) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    Object nameValue = body.get("name");
    Object subjectValue = body.get("subjectId");
    Object scopesValue = body.get("scopes");
    if (!(nameValue instanceof String name) || name.isBlank()
        || !(subjectValue instanceof String subjectId) || subjectId.isBlank()
        || !(scopesValue instanceof List<?> rawScopes) || rawScopes.isEmpty()) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    Set<PermissionName> scopes = new LinkedHashSet<>();
    for (Object scope : rawScopes) {
      if (!(scope instanceof String s) || s.isBlank()) {
        writeError(response, HttpStatus.BAD_REQUEST);
        return;
      }
      scopes.add(new PermissionName(s));
    }

    String plainKey = generateApiKey();
    String keyHash = apiKeyHasher.hash(plainKey.toCharArray());
    Instant now = Instant.now(Clock.systemUTC());
    ApiKeyRecord record = new ApiKeyRecord(
        keyHash, TenantId.DEFAULT, SubjectId.of(subjectId), name,
        Set.copyOf(scopes), now,
        Optional.empty(), Optional.empty(), Optional.empty());
    apiKeyStore.save(record);

    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("plainKey", plainKey);
    payload.put("keyHash", keyHash);
    payload.put("name", name);
    payload.put("subjectId", subjectId);
    payload.put("scopes", scopes.stream().map(PermissionName::value).sorted().toList());
    payload.put("createdAt", now.toString());
    response.status(HttpStatus.CREATED.code());
    response.body(DemoJson.encode(payload));
  }

  /**
   * V00.70 Phase-7b — revokes an API key. Body
   * {@code {"keyHash":"…"}}. Idempotent: revoking an
   * already-revoked key still returns 200. Requires
   * {@code admin:roles}.
   */
  @RequiresPermission("admin:roles")
  public void revokeApiKey(RestRequest request, RestResponse response) {
    if (apiKeyStore == null) {
      writeError(response, HttpStatus.SERVICE_UNAVAILABLE);
      return;
    }
    Map<String, Object> body;
    try {
      body = DemoJson.decodeObject(requireBody(request));
    } catch (RuntimeException e) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    Object hashValue = body.get("keyHash");
    if (!(hashValue instanceof String keyHash) || keyHash.isBlank()) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    if (apiKeyStore.findByHash(keyHash).isEmpty()) {
      writeError(response, HttpStatus.NOT_FOUND);
      return;
    }
    apiKeyStore.revoke(keyHash, Instant.now(Clock.systemUTC()));
    response.status(HttpStatus.OK.code());
    response.body(DemoJson.encode(Map.of("keyHash", keyHash, "revoked", true)));
  }

  /**
   * V00.70 Phase-7b — issues a fresh
   * {@link TokenService.TokenPair} for the supplied subject id.
   * Body: {@code {"subjectId":"…"}}. Demo-only: unauthenticated;
   * production would couple this to a credential challenge.
   */
  public void issueTokenPair(RestRequest request, RestResponse response) {
    if (tokenService == null) {
      writeError(response, HttpStatus.SERVICE_UNAVAILABLE);
      return;
    }
    Map<String, Object> body;
    try {
      body = DemoJson.decodeObject(requireBody(request));
    } catch (RuntimeException e) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    Object subjectValue = body.get("subjectId");
    if (!(subjectValue instanceof String subjectId) || subjectId.isBlank()) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    TokenService.TokenPair pair = tokenService.issue(SubjectId.of(subjectId));
    response.status(HttpStatus.OK.code());
    response.body(DemoJson.encode(tokenPairToJson(pair)));
  }

  /**
   * V00.70 Phase-7b — rotates a refresh token. Body
   * {@code {"refreshToken":"…"}}. On success returns a fresh pair
   * + 200; on every failure mode (unknown, replayed, revoked,
   * expired) returns 401 + {@code WWW-Authenticate: TokenRotated}.
   */
  public void rotateTokenPair(RestRequest request, RestResponse response) {
    if (tokenService == null) {
      writeError(response, HttpStatus.SERVICE_UNAVAILABLE);
      return;
    }
    Map<String, Object> body;
    try {
      body = DemoJson.decodeObject(requireBody(request));
    } catch (RuntimeException e) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    Object refreshValue = body.get("refreshToken");
    if (!(refreshValue instanceof String refreshToken) || refreshToken.isBlank()) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    Optional<TokenService.TokenPair> rotated = tokenService.rotate(refreshToken);
    if (rotated.isEmpty()) {
      response.header("WWW-Authenticate", "TokenRotated");
      writeError(response, HttpStatus.UNAUTHORIZED);
      return;
    }
    response.status(HttpStatus.OK.code());
    response.body(DemoJson.encode(tokenPairToJson(rotated.get())));
  }

  /**
   * V00.70 Phase-7b — revokes a still-active refresh token.
   * Idempotent: revoking an unknown / already-revoked / replaced
   * token returns 200 with {@code revoked:false}.
   */
  public void revokeTokenPair(RestRequest request, RestResponse response) {
    if (tokenService == null) {
      writeError(response, HttpStatus.SERVICE_UNAVAILABLE);
      return;
    }
    Map<String, Object> body;
    try {
      body = DemoJson.decodeObject(requireBody(request));
    } catch (RuntimeException e) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    Object refreshValue = body.get("refreshToken");
    if (!(refreshValue instanceof String refreshToken) || refreshToken.isBlank()) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    boolean revoked = tokenService.revoke(refreshToken);
    response.status(HttpStatus.OK.code());
    response.body(DemoJson.encode(Map.of("revoked", revoked)));
  }

  private static Map<String, Object> tokenPairToJson(TokenService.TokenPair pair) {
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("subjectId", pair.subjectId().value());
    payload.put("accessToken", pair.accessToken());
    payload.put("accessExpiresAt", pair.accessExpiresAt().toString());
    payload.put("refreshToken", pair.refreshToken());
    payload.put("refreshExpiresAt", pair.refreshExpiresAt().toString());
    return payload;
  }

  /**
   * Generates a fresh 32-byte plain API key, hex-encoded
   * ({@code 64 chars}). Demo-only — production deployments would
   * sample from {@code SecureRandom} into a more compact alphabet
   * (URL-safe base64 etc) and might prefix a key-version segment
   * for rotation.
   */
  private static String generateApiKey() {
    byte[] bytes = new byte[32];
    new java.security.SecureRandom().nextBytes(bytes);
    return java.util.HexFormat.of().formatHex(bytes);
  }

  /**
   * V00.70 Phase-7a account-lifecycle — request a single-use
   * password-reset token for a known subject. Demo-only: returns
   * the token in the JSON response so integration tests can pick
   * it up; production wiring would never echo the token and rely
   * on {@link eu.jsentinel.jcustos.accountlifecycle.JCustosNotificationSender}
   * to deliver it out-of-band.
   * <p>
   * Unauthenticated endpoint (anyone can request a reset for any
   * subject id), but the underlying {@link PasswordResetService}
   * publishes a {@code PasswordResetRequested} audit event so
   * operators can detect enumeration / abuse.
   */
  public void requestPasswordReset(RestRequest request, RestResponse response) {
    if (passwordResetService == null) {
      writeError(response, HttpStatus.SERVICE_UNAVAILABLE);
      return;
    }
    Map<String, Object> body;
    try {
      body = DemoJson.decodeObject(requireBody(request));
    } catch (RuntimeException e) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    Object subjectValue = body.get("subjectId");
    if (!(subjectValue instanceof String subjectId) || subjectId.isBlank()) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    PasswordResetService.IssuedToken issued = passwordResetService.request(
        SubjectId.of(subjectId), Duration.ofMinutes(15));
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("subjectId", subjectId);
    payload.put("token", issued.plainToken());
    payload.put("expiresAt", issued.record().expiresAt().toString());
    response.status(HttpStatus.OK.code());
    response.body(DemoJson.encode(payload));
  }

  /**
   * V00.70 Phase-7a account-lifecycle — consume a previously
   * issued password-reset token. Returns 200 with the resolved
   * subjectId on success, 404 when the token is unknown / expired
   * / wrong tenant, 410 when the token has already been consumed.
   */
  public void consumePasswordReset(RestRequest request, RestResponse response) {
    if (passwordResetService == null) {
      writeError(response, HttpStatus.SERVICE_UNAVAILABLE);
      return;
    }
    Map<String, Object> body;
    try {
      body = DemoJson.decodeObject(requireBody(request));
    } catch (RuntimeException e) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    Object tokenValue = body.get("token");
    if (!(tokenValue instanceof String token) || token.isBlank()) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    // First check validity — distinguishes "unknown" from "already
    // consumed" since consume() is idempotent on the unknown branch.
    Optional<PasswordResetTokenRecord> live = passwordResetService.validate(token);
    if (live.isEmpty()) {
      // Could be unknown, expired, or already consumed. The store
      // intentionally hides which to deny an enumeration oracle —
      // we still differentiate consume-twice via the consume call.
      Optional<PasswordResetTokenRecord> consumed = passwordResetService.consume(token);
      if (consumed.isEmpty()) {
        writeError(response, HttpStatus.NOT_FOUND);
        return;
      }
      // Race — became valid then consumed between validate + consume.
      Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("subjectId", consumed.get().subjectId().value());
      response.status(HttpStatus.OK.code());
      response.body(DemoJson.encode(payload));
      return;
    }
    Optional<PasswordResetTokenRecord> consumed = passwordResetService.consume(token);
    if (consumed.isEmpty()) {
      // Already consumed between our validate() and our consume() —
      // surface 410 Gone so the caller can distinguish from "unknown".
      writeError(response, HttpStatus.GONE);
      return;
    }
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("subjectId", consumed.get().subjectId().value());
    response.status(HttpStatus.OK.code());
    response.body(DemoJson.encode(payload));
  }

  /**
   * Combined documents inspector — exposes a JSON summary to any
   * subject with <em>either</em> {@code document:read} or
   * {@code document:create}. Demonstrates the V00.70 OR-semantics
   * {@code @RequiresAnyPermission} evaluator (vs the all-of
   * {@code @RequiresAllPermissions} / single-permission
   * {@code @RequiresPermission}).
   */
  @RequiresAnyPermission({"document:read", "document:create"})
  public void inspectDocuments(RestRequest request, RestResponse response) {
    response.status(HttpStatus.OK.code());
    response.body(DemoJson.encode(Map.of(
        "documentCount", documents.list().size(),
        "permissions", List.of("document:read", "document:create"),
        "semantics", "ANY")));
  }

  @RequiresPermission("document:read")
  public void listDocuments(RestRequest request, RestResponse response) {
    List<Map<String, Object>> docs = documents.list().stream()
        .map(DemoHandlers::documentToJson)
        .toList();
    response.status(HttpStatus.OK.code());
    response.body(DemoJson.encode(Map.of("documents", docs)));
  }

  @RequiresPermission("document:create")
  public void createDocument(RestRequest request, RestResponse response) {
    Map<String, Object> body;
    try {
      body = DemoJson.decodeObject(requireBody(request));
    } catch (RuntimeException e) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    Object titleValue = body.get("title");
    if (!(titleValue instanceof String title) || title.isBlank()) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    DemoDocument created = documents.create(title);
    response.status(HttpStatus.CREATED.code());
    response.body(DemoJson.encode(documentToJson(created)));
  }

  @RequiresPermission("document:delete")
  public void deleteDocument(RestRequest request, RestResponse response) {
    String path = request.path();
    String prefix = DemoEndpoints.DOCUMENT_BY_ID;
    if (!path.startsWith(prefix)) {
      writeError(response, HttpStatus.NOT_FOUND);
      return;
    }
    long id;
    try {
      id = Long.parseLong(path.substring(prefix.length()));
    } catch (NumberFormatException e) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    if (!documents.delete(id)) {
      writeError(response, HttpStatus.NOT_FOUND);
      return;
    }
    response.status(HttpStatus.NO_CONTENT.code());
    response.body("");
  }

  @RequiresPermission("admin:access")
  public void adminStatus(RestRequest request, RestResponse response) {
    response.status(HttpStatus.OK.code());
    response.body(DemoJson.encode(Map.of("status", "ok", "message", "Admin endpoint executed.")));
  }

  /**
   * Returns every registered user with {@code username}, {@code displayName}
   * and current {@code role}. Backs the rest-client Role-Admin view.
   */
  @RequiresPermission("admin:roles")
  public void listUsers(RestRequest request, RestResponse response) {
    List<Map<String, Object>> users = userStore.listAll().stream()
        .map(DemoHandlers::userToJson)
        .toList();
    response.status(HttpStatus.OK.code());
    response.body(DemoJson.encode(Map.of("users", users)));
  }

  /**
   * Replaces the role of {@code /api/admin/users/{username}}. Body shape:
   * {@code {"role":"ROLE_EDITOR"}}. Returns the updated user; emits
   * {@code RoleRevoked} (old role) + {@code RoleAssigned} (new role) audit
   * events when a real change is applied.
   */
  @RequiresPermission("admin:roles")
  public void setUserRole(RestRequest request, RestResponse response) {
    String path = request.path();
    String prefix = DemoEndpoints.ADMIN_USER_BY_NAME;
    if (!path.startsWith(prefix) || path.length() <= prefix.length()) {
      writeError(response, HttpStatus.NOT_FOUND);
      return;
    }
    String username = path.substring(prefix.length());

    Map<String, Object> body;
    try {
      body = DemoJson.decodeObject(requireBody(request));
    } catch (RuntimeException e) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    Object roleValue = body.get("role");
    if (!(roleValue instanceof String roleName)) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    DemoRole role;
    try {
      role = DemoRole.valueOf(roleName);
    } catch (IllegalArgumentException e) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }

    boolean changed = userStore.setRole(username, role);
    Optional<DemoUser> updated = userStore.listAll().stream()
        .filter(u -> u.username().equals(username))
        .findFirst();
    if (updated.isEmpty()) {
      writeError(response, HttpStatus.NOT_FOUND);
      return;
    }
    if (changed) {
      bumpJCustosVersion(username);
    }
    Map<String, Object> payload = new LinkedHashMap<>(userToJson(updated.get()));
    payload.put("changed", changed);
    response.status(HttpStatus.OK.code());
    response.body(DemoJson.encode(payload));
  }

  /**
   * Bumps {@code username}'s {@link JCustosVersion} so any
   * already-issued tokens drift on the next request and
   * {@link eu.jsentinel.jcustos.rest.RestJCustosVersionFilter}
   * refuses them with {@code 401 + WWW-Authenticate: SessionStale}.
   */
  private void bumpJCustosVersion(String username) {
    securityVersionStore.increment(new JCustosVersionKey(
        TenantId.DEFAULT, SubjectId.of(username)));
  }

  private static Map<String, Object> userToJson(DemoUser user) {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("username", user.username());
    map.put("displayName", user.displayName());
    map.put("role", user.role().name());
    return map;
  }

  /**
   * Creates a new user. Body shape:
   * {@code {"username","password","displayName?","role"}}.
   * Returns {@code 201} + the new user JSON, {@code 409} if the username
   * already exists, {@code 400} for malformed body or unknown role.
   * Emits {@link eu.jsentinel.jcustos.audit.UserCreated}.
   */
  @RequiresPermission("admin:roles")
  public void createUser(RestRequest request, RestResponse response) {
    Map<String, Object> body;
    try {
      body = DemoJson.decodeObject(requireBody(request));
    } catch (RuntimeException e) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    Object usernameValue = body.get("username");
    Object passwordValue = body.get("password");
    Object roleValue = body.get("role");
    Object displayNameValue = body.get("displayName");
    if (!(usernameValue instanceof String username) || username.isBlank()
        || !(passwordValue instanceof String password) || password.isEmpty()
        || !(roleValue instanceof String roleName)) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    DemoRole role;
    try {
      role = DemoRole.valueOf(roleName);
    } catch (IllegalArgumentException e) {
      writeError(response, HttpStatus.BAD_REQUEST);
      return;
    }
    String displayName = displayNameValue instanceof String s && !s.isBlank() ? s : username;

    if (compromisedPolicy.checkOnSetOrChange()
        && !(compromisedChecker instanceof NoOpCompromisedPasswordChecker)) {
      CompromisedPasswordResult check = compromisedChecker.check(
          SecretValue.ofString(password));
      if (check instanceof CompromisedPasswordResult.Pwned) {
        // Generic perimeter message — CWE-209: do not echo which
        // dictionary or count matched.
        writeError(response, HttpStatus.BAD_REQUEST);
        return;
      }
      if (check instanceof CompromisedPasswordResult.CheckFailed
          && compromisedPolicy.onFailure() == CheckFailurePolicy.BLOCK) {
        writeError(response, HttpStatus.SERVICE_UNAVAILABLE);
        return;
      }
    }

    DemoUser created;
    try {
      created = userStore.create(username, password, displayName, role);
    } catch (IllegalStateException duplicate) {
      writeError(response, HttpStatus.CONFLICT);
      return;
    }
    response.status(HttpStatus.CREATED.code());
    response.body(DemoJson.encode(userToJson(created)));
  }

  /**
   * Removes the user identified by {@code /api/admin/users/{username}}.
   * Returns {@code 204} on success, {@code 404} if unknown.
   * Emits {@link eu.jsentinel.jcustos.audit.UserDeleted}.
   */
  @RequiresPermission("admin:roles")
  public void deleteUser(RestRequest request, RestResponse response) {
    String path = request.path();
    String prefix = DemoEndpoints.ADMIN_USER_BY_NAME;
    if (!path.startsWith(prefix) || path.length() <= prefix.length()) {
      writeError(response, HttpStatus.NOT_FOUND);
      return;
    }
    String username = path.substring(prefix.length());
    if (!userStore.deleteUser(username)) {
      writeError(response, HttpStatus.NOT_FOUND);
      return;
    }
    bumpJCustosVersion(username);
    response.status(HttpStatus.NO_CONTENT.code());
    response.body("");
  }

  /**
   * Returns the recent audit events from the backend's
   * {@code RingBufferAuditSink}. Optional query parameters:
   * <ul>
   *   <li>{@code type} — exact {@code AuditEvent} subtype short name
   *       (e.g. {@code LoginSucceeded}, {@code AccessDenied})</li>
   *   <li>{@code subject} — exact subject id / username</li>
   * </ul>
   * Newest first. Symmetric to the Vaadin {@code /audit}-route.
   */
  @RequiresPermission("audit:read")
  public void auditEvents(RestRequest request, RestResponse response) {
    String typeParam = request.queryParameters().get("type");
    String subjectParam = request.queryParameters().get("subject");
    if (subjectParam != null && subjectParam.isBlank()) {
      subjectParam = null;
    }

    AuditQuery query = new AuditQuery(
        Set.of(),
        subjectParam,
        null, null, 0);

    List<AuditEvent> all = JCustosServiceResolver.securityAuditService().query(query);
    List<AuditEvent> filtered = typeParam == null || typeParam.isBlank()
        ? all
        : all.stream()
            .filter(e -> e.getClass().getSimpleName().equals(typeParam))
            .toList();

    // newest first
    List<Map<String, Object>> events = new ArrayList<>(filtered.size());
    for (int i = filtered.size() - 1; i >= 0; i--) {
      events.add(auditEventToJson(filtered.get(i)));
    }

    response.status(HttpStatus.OK.code());
    response.body(DemoJson.encode(Map.of("events", events)));
  }

  private static Map<String, Object> auditEventToJson(AuditEvent event) {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("type", event.getClass().getSimpleName());
    map.put("timestamp", event.timestamp().toString());
    switch (event) {
      case LoginSucceeded e -> {
        map.put("username", e.username());
        map.put("clientAddress", e.clientAddress());
        map.put("sessionId", e.sessionId());
      }
      case eu.jsentinel.jcustos.audit.LoginFailed e -> {
        map.put("username", e.username());
        map.put("clientAddress", e.clientAddress());
        map.put("reason", e.reason());
      }
      case eu.jsentinel.jcustos.audit.LogoutPerformed e -> {
        map.put("subjectId", e.subjectId());
        map.put("sessionId", e.sessionId());
        map.put("scope", e.scope().name());
      }
      case eu.jsentinel.jcustos.audit.AccessGranted e -> {
        map.put("subjectId", e.subjectId());
        map.put("route", e.route());
      }
      case eu.jsentinel.jcustos.audit.AccessDenied e -> {
        map.put("subjectId", e.subjectId());
        map.put("route", e.route());
        map.put("reason", e.reason());
      }
      case eu.jsentinel.jcustos.audit.ActionDenied e -> {
        map.put("subjectId", e.subjectId());
        map.put("action", e.action());
      }
      case eu.jsentinel.jcustos.audit.BruteForceLimitReached e -> {
        map.put("username", e.username());
        map.put("clientAddress", e.clientAddress());
        map.put("failedAttempts", e.failedAttempts());
        map.put("lockoutSeconds", e.lockoutDuration().toSeconds());
      }
      case eu.jsentinel.jcustos.audit.SessionCreated e -> {
        map.put("subjectId", e.subjectId());
        map.put("sessionId", e.sessionId());
      }
      case eu.jsentinel.jcustos.audit.SessionExpired e -> {
        map.put("subjectId", e.subjectId());
        map.put("sessionId", e.sessionId());
        map.put("reason", e.reason());
      }
      case eu.jsentinel.jcustos.audit.SessionInvalidated e -> {
        map.put("subjectId", e.subjectId());
        map.put("sessionId", e.sessionId());
        map.put("reason", e.reason());
      }
      case eu.jsentinel.jcustos.audit.RoleAssigned e -> {
        map.put("subjectId", e.subjectId());
        map.put("role", e.role());
        map.put("assignedBy", e.assignedBy());
      }
      case eu.jsentinel.jcustos.audit.RoleRevoked e -> {
        map.put("subjectId", e.subjectId());
        map.put("role", e.role());
        map.put("revokedBy", e.revokedBy());
      }
      case eu.jsentinel.jcustos.audit.BootstrapAdminCreated e -> {
        map.put("username", e.username());
        map.put("clientAddress", e.clientAddress());
      }
      case eu.jsentinel.jcustos.audit.BootstrapTokenRejected e -> {
        map.put("reason", e.reason());
        map.put("clientAddress", e.clientAddress());
      }
      case eu.jsentinel.jcustos.audit.UserCreated e -> {
        map.put("username", e.username());
        map.put("role", e.role());
        map.put("createdBy", e.createdBy());
      }
      case eu.jsentinel.jcustos.audit.UserDeleted e -> {
        map.put("username", e.username());
        map.put("deletedBy", e.deletedBy());
      }
      case eu.jsentinel.jcustos.audit.PolicyEvaluated e -> {
        map.put("subjectId", e.subjectId());
        map.put("policyName", e.policyName());
        map.put("decision", e.decision());
        map.put("reason", e.reason());
      }
      case eu.jsentinel.jcustos.audit.StepUpChallenged e -> {
        map.put("subjectId", e.subjectId());
        map.put("route", e.route());
        map.put("method", e.method());
        map.put("reason", e.reason());
      }
      case eu.jsentinel.jcustos.audit.SessionStale e -> {
        map.put("subjectId", e.subjectId());
        map.put("sessionId", e.sessionId());
        map.put("route", e.route());
        map.put("snapshotVersion", e.snapshotVersion());
        map.put("currentVersion", e.currentVersion());
      }
      case eu.jsentinel.jcustos.audit.PasswordResetRequested e -> {
        map.put("subjectId", e.subjectId());
        map.put("tokenHash", e.tokenHash());
      }
      case eu.jsentinel.jcustos.audit.PasswordResetCompleted e -> {
        map.put("subjectId", e.subjectId());
        map.put("tokenHash", e.tokenHash());
      }
      case eu.jsentinel.jcustos.audit.EmailVerificationRequested e -> {
        map.put("subjectId", e.subjectId());
        map.put("email", e.email());
        map.put("tokenHash", e.tokenHash());
      }
      case eu.jsentinel.jcustos.audit.EmailVerified e -> {
        map.put("subjectId", e.subjectId());
        map.put("email", e.email());
        map.put("tokenHash", e.tokenHash());
      }
      case eu.jsentinel.jcustos.audit.ApiKeyUsed e -> {
        map.put("subjectId", e.subjectId());
        map.put("keyName", e.keyName());
        map.put("keyHash", e.keyHash());
      }
      case eu.jsentinel.jcustos.audit.ApiKeyDenied e -> {
        map.put("subjectId", e.subjectId());
        map.put("keyHash", e.keyHash());
        map.put("reason", e.reason());
      }
      case eu.jsentinel.jcustos.audit.TokenRotated e -> {
        map.put("subjectId", e.subjectId());
        map.put("oldHash", e.oldHash());
        map.put("newHash", e.newHash());
      }
      case eu.jsentinel.jcustos.audit.RateLimitExceeded e -> {
        map.put("scope", e.scope());
        map.put("subjectId", e.subjectId());
        map.put("limit", e.limit());
        map.put("windowSeconds", e.window().toSeconds());
        map.put("eventsInWindow", e.eventsInWindow());
      }
      case eu.jsentinel.jcustos.audit.CredentialVerificationSucceeded e -> {
        map.put("username", e.username());
        map.put("clientAddress", e.clientAddress());
        map.put("algorithm", e.algorithm());
        map.put("providerId", e.providerId());
        map.put("policyVersion", e.policyVersion());
        map.put("pepperKeyIdPresent", e.pepperKeyIdPresent());
        map.put("rehashRequired", e.rehashRequired());
      }
      case eu.jsentinel.jcustos.audit.CredentialVerificationFailed e -> {
        map.put("username", e.username());
        map.put("clientAddress", e.clientAddress());
        map.put("internalAuditEventType", e.internalAuditEventType().name());
      }
      case eu.jsentinel.jcustos.audit.CredentialRehashed e -> {
        map.put("username", e.username());
        map.put("fromAlgorithm", e.fromAlgorithm());
        map.put("toAlgorithm", e.toAlgorithm());
        map.put("reason", e.reason().name());
        map.put("targetPolicyVersion", e.targetPolicyVersion());
      }
      case eu.jsentinel.jcustos.audit.CredentialStatusChanged e -> {
        map.put("username", e.username());
        map.put("fromStatus", e.fromStatus().name());
        map.put("toStatus", e.toStatus().name());
        map.put("reason", e.reason());
      }
    }
    return map;
  }

  private static Map<String, Object> documentToJson(DemoDocument doc) {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("id", doc.id());
    map.put("title", doc.title());
    return map;
  }

  private static Map<String, Object> descriptorToJson(SecuredOperationDescriptor descriptor) {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("id", descriptor.id());
    map.put("label", descriptor.label());
    map.put("description", descriptor.description());
    map.put("method", descriptor.attributes().get(DemoOperationRegistry.ATTR_HTTP_METHOD));
    map.put("path", descriptor.attributes().get(DemoOperationRegistry.ATTR_HTTP_PATH));
    return map;
  }

  private static void writeError(RestResponse response, int status, String message) {
    response.status(status);
    response.body(message);
  }

  /**
   * Typed convenience overload — body defaults to the
   * {@link HttpStatus#reason() RFC reason phrase}, status to
   * {@link HttpStatus#code() the numeric code}. Preferred for new
   * code per the {@code HttpStatus} discipline.
   */
  private static void writeError(RestResponse response, HttpStatus status) {
    response.status(status.code());
    response.body(status.reason());
  }

  private static String requireBody(RestRequest request) {
    if (request instanceof BodyRestRequest body) return body.bodyAsUtf8();
    throw new IllegalArgumentException("body required");
  }

  private static RestRequest withAuth(RestRequest request, String token) {
    Map<String, String> headers = new LinkedHashMap<>(request.headers());
    headers.put("Authorization", "Bearer " + token);
    byte[] body = request instanceof BodyRestRequest existing ? existing.bodyBytes() : new byte[0];
    return new DemoHttpRequest(
        request.method(),
        request.path(),
        headers,
        request.queryParameters(),
        body);
  }
}
