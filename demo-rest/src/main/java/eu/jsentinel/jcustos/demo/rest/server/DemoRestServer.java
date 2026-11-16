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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.accountlifecycle.InMemoryPasswordResetTokenStore;
import eu.jsentinel.jcustos.accountlifecycle.LoggingNotificationSender;
import eu.jsentinel.jcustos.accountlifecycle.PasswordResetService;
import eu.jsentinel.jcustos.authentication.ApiKeyAuthenticationService;
import eu.jsentinel.jcustos.authentication.ApiKeyStore;
import eu.jsentinel.jcustos.authentication.InMemoryApiKeyStore;
import eu.jsentinel.jcustos.authentication.InMemoryRefreshTokenStore;
import eu.jsentinel.jcustos.authentication.TokenService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptConfiguration;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.token.Sha256TokenHasher;
import eu.jsentinel.jcustos.dx.rest.bootstrap.RestSecurity;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.ratelimiting.InMemoryRateLimitPolicy;
import eu.jsentinel.jcustos.ratelimiting.InMemoryRateLimitStore;
import eu.jsentinel.jcustos.ratelimiting.RateLimitPolicy;

import java.time.Duration;
import eu.jsentinel.jcustos.logout.SubjectClearingLogoutService;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.bootstrap.BootstrapConfiguration;
import eu.jsentinel.jcustos.bootstrap.BootstrapMode;
import eu.jsentinel.jcustos.bootstrap.BootstrapStartup;
import eu.jsentinel.jcustos.bootstrap.BootstrapStateService;
import eu.jsentinel.jcustos.bootstrap.BootstrapTokenGenerator;
import eu.jsentinel.jcustos.bootstrap.BootstrapTokenOutput;
import eu.jsentinel.jcustos.bootstrap.BootstrapTokenStore;
import eu.jsentinel.jcustos.bootstrap.ConsoleBootstrapTokenOutput;
import eu.jsentinel.jcustos.bootstrap.FileBootstrapTokenOutput;
import eu.jsentinel.jcustos.bootstrap.FileBootstrapTokenStore;
import eu.jsentinel.jcustos.bootstrap.InMemoryBootstrapTokenStore;
import eu.jsentinel.jcustos.bootstrap.InitialAdminBootstrapService;
import eu.jsentinel.jcustos.bootstrap.MinimumLengthPasswordPolicy;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.demo.rest.domain.DemoDocumentStore;
import eu.jsentinel.jcustos.demo.rest.domain.DemoOwnedDocumentStore;
import eu.jsentinel.jcustos.demo.rest.domain.DemoRolePermissionMapping;
import eu.jsentinel.jcustos.demo.rest.domain.DemoUser;
import eu.jsentinel.jcustos.demo.rest.domain.DemoUserStore;
import eu.jsentinel.jcustos.demo.rest.shared.DemoEndpoints;
import eu.jsentinel.jcustos.policy.impl.InMemoryPolicyRegistry;
import eu.jsentinel.jcustos.policy.impl.InMemoryResourceResolverRegistry;
import eu.jsentinel.jcustos.policy.spi.PolicyRegistry;
import eu.jsentinel.jcustos.policy.spi.ResourceResolverRegistry;
import eu.jsentinel.jcustos.rest.RestJCustosVersionFilter;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer;
import eu.jsentinel.jcustos.session.JCustosVersionStore;
import eu.jsentinel.jcustos.session.InMemorySessionStore;
import eu.jsentinel.jcustos.session.SessionStore;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.util.Optional;

/**
 * Demo REST server using only JDK APIs ({@link HttpServer}).
 * <p>
 * Demo-only — token handling, password storage, and user persistence are
 * intentionally simple. Production systems must use a real authentication
 * subsystem.
 * <p>
 * Bootstrap mode is controlled by system properties — see
 * {@link DemoBootstrapEnvironment}.
 * <p>
 * JS-SEC-137 (CWE-1188, CWE-798, CWE-319): the server listens on the loopback interface
 * only, and it creates no account with a fixed password unless the development switch
 * {@value DemoUserStore#INSECURE_SEED_ACCOUNTS_PROPERTY} is set (the overloads without a
 * {@code insecureSeedAccounts} argument read it; tests pass it explicitly). Without the
 * switch the first administrator comes from the bootstrap flow, and bootstrap mode
 * {@code DISABLED} - which has no other source of an administrator - refuses to start.
 * <p>
 * JS-SEC-131 (CWE-613): the bootstrap publishes an in-memory {@link SessionStore}; every
 * login is recorded there under its session reference, and a record set to
 * {@code REVOKED} ends the session on its next request.
 */
public final class DemoRestServer {

  /** Demo subjects are keyed on their user name - the key the version store is bumped on. */
  private static final SubjectIdResolver<DemoUser> DEMO_SUBJECT_IDS =
      user -> SubjectId.of(user.username());

  private final HttpServer httpServer;
  private final int port;
  private final RestSubjectResolver subjectResolver;
  private final SessionStore sessionStore;

  private DemoRestServer(HttpServer httpServer, int port,
                         RestSubjectResolver subjectResolver, SessionStore sessionStore) {
    this.httpServer = httpServer;
    this.port = port;
    this.subjectResolver = subjectResolver;
    this.sessionStore = sessionStore;
  }

  public static DemoRestServer start(int port) throws IOException {
    return start(port, DemoBootstrapEnvironment.fromEnvironment());
  }

  public static DemoRestServer start(int port, BootstrapConfiguration bootstrapConfig) throws IOException {
    return start(port, bootstrapConfig, DemoUserStore.insecureSeedAccountsRequested());
  }

  /**
   * @param insecureSeedAccounts {@code true} creates the fixed-password demo accounts
   *                             (development and tests only, JS-SEC-137)
   */
  public static DemoRestServer start(int port,
                                     BootstrapConfiguration bootstrapConfig,
                                     boolean insecureSeedAccounts) throws IOException {
    return start(port, bootstrapConfig, new InMemoryLoginAttemptPolicy(),
        defaultBootstrapAttemptPolicy(), insecureSeedAccounts);
  }

  public static DemoRestServer start(int port,
                                     BootstrapConfiguration bootstrapConfig,
                                     LoginAttemptPolicy loginAttemptPolicy) throws IOException {
    return start(port, bootstrapConfig, loginAttemptPolicy, defaultBootstrapAttemptPolicy(),
        DemoUserStore.insecureSeedAccountsRequested());
  }

  public static DemoRestServer start(int port,
                                     BootstrapConfiguration bootstrapConfig,
                                     LoginAttemptPolicy loginAttemptPolicy,
                                     LoginAttemptPolicy bootstrapAttemptPolicy) throws IOException {
    return start(port, bootstrapConfig, loginAttemptPolicy, bootstrapAttemptPolicy,
        DemoUserStore.insecureSeedAccountsRequested());
  }

  /**
   * Full wiring.
   *
   * @param insecureSeedAccounts {@code true} creates the fixed-password demo accounts
   *                             {@code editor}, {@code viewer} and - in bootstrap mode
   *                             {@code DISABLED} - {@code admin} (development and tests
   *                             only, JS-SEC-137)
   * @throws IllegalStateException when bootstrap mode {@code DISABLED} is requested
   *                               without the seed accounts: nothing could create an
   *                               administrator
   */
  public static DemoRestServer start(int port,
                                     BootstrapConfiguration bootstrapConfig,
                                     LoginAttemptPolicy loginAttemptPolicy,
                                     LoginAttemptPolicy bootstrapAttemptPolicy,
                                     boolean insecureSeedAccounts) throws IOException {
    boolean bootstrapMode = bootstrapConfig.mode() != BootstrapMode.DISABLED;
    if (!bootstrapMode && !insecureSeedAccounts) {
      // JS-SEC-137 (CWE-798): DISABLED used to create admin/admin silently.
      throw new IllegalStateException("Bootstrap mode DISABLED leaves the demo without an "
          + "administrator. Use bootstrap mode TRANSIENT_CONSOLE or PERSISTENT_FILE "
          + "(security.bootstrap.mode / SECURITY_BOOTSTRAP_MODE) to create the first "
          + "administrator, or - for a throw-away local instance only - set -D"
          + DemoUserStore.INSECURE_SEED_ACCOUNTS_PROPERTY + "=true.");
    }
    DemoUserStore.InsecureSeed seed = !insecureSeedAccounts
        ? DemoUserStore.InsecureSeed.NONE
        : bootstrapMode
            ? DemoUserStore.InsecureSeed.DEMO_ACCOUNTS
            : DemoUserStore.InsecureSeed.DEMO_ACCOUNTS_AND_ADMINISTRATOR;
    PasswordHashingService hashingService =
        PasswordHashingServices.defaults();
    DemoUserStore users = new DemoUserStore(hashingService, seed);
    // JS-SEC-131: the store the REST filters consult on every request; the token store
    // records each login in it under the session reference.
    SessionStore sessionStore = new InMemorySessionStore();
    DemoTokenStore tokens = new DemoTokenStore(Clock.systemUTC(), sessionStore);
    DemoDocumentStore documents = new DemoDocumentStore();
    DemoRolePermissionMapping mapping = new DemoRolePermissionMapping();
    // V00.70 Phase-7b API keys — the resolver checks X-Api-Key
    // ahead of the Bearer token (scopes win over session perms).
    ApiKeyStore apiKeyStore = new InMemoryApiKeyStore();
    Sha256TokenHasher apiKeyHasher = new Sha256TokenHasher();
    ApiKeyAuthenticationService apiKeyAuth = new ApiKeyAuthenticationService(
        apiKeyStore, apiKeyHasher,
        JCustosServiceResolver.securityAuditService());
    DemoSubjectResolver resolver = new DemoSubjectResolver(
        tokens, mapping, apiKeyAuth);
    DemoOperationRegistry registry = new DemoOperationRegistry();
    JCustosVersionStore versionStore = new InMemoryJCustosVersionStore();
    // PasswordResetService requires a *deterministic* hasher so the
    // token-hash → record lookup actually matches. The SPI-resolved
    // PasswordHasher (PBKDF2 / Argon2id) is salted by design and would
    // produce a different hash every call — wrong tool for this job.
    PasswordResetService passwordResetService = new PasswordResetService(
        new InMemoryPasswordResetTokenStore(),
        new Sha256TokenHasher(),
        JCustosServiceResolver.securityAuditService(),
        new LoggingNotificationSender());
    // V00.70 Phase-7c per-IP login rate limiting — 200 attempts per minute.
    // Sits ahead of the per-username brute-force window so distributed
    // credential stuffing surfaces as 429 + Retry-After before the
    // per-username lockout even sees the request. The threshold is
    // deliberately high enough that the integration-test fixture (which
    // logs in as multiple demo users from the same loopback IP within a
    // minute) does not trip the limit; tests that need to exercise the
    // 429 path construct a dedicated InMemoryRateLimitPolicy with a
    // smaller limit (see DemoLoginRateLimitTest).
    RateLimitPolicy loginRateLimit = new InMemoryRateLimitPolicy(
        new InMemoryRateLimitStore(),
        JCustosServiceResolver.securityAuditService(),
        200,
        Duration.ofMinutes(1));
    // V00.70 Phase-7b — rotating refresh tokens. Uses the same
    // Sha256TokenHasher as API keys (deterministic lookup) and a
    // dedicated InMemoryRefreshTokenStore.
    TokenService tokenService = new TokenService(
        new InMemoryRefreshTokenStore(),
        apiKeyHasher,
        JCustosServiceResolver.securityAuditService());
    DemoHandlers handlers = new DemoHandlers(
        users, tokens, documents, registry, resolver, loginAttemptPolicy,
        versionStore, passwordResetService, loginRateLimit,
        apiKeyStore, apiKeyHasher, tokenService);

    // V00.70 Policy-DSL example — register the document.owner-or-admin
    // policy and the matching ResourceResolver, then inject the
    // owned-documents store into the handlers so the inspect handler
    // can serve the JSON body after the policy has cleared.
    DemoOwnedDocumentStore ownedDocumentStore = new DemoOwnedDocumentStore();
    handlers.setOwnedDocumentStore(ownedDocumentStore);
    PolicyRegistry policyRegistry = new InMemoryPolicyRegistry();
    ResourceResolverRegistry resourceRegistry = new InMemoryResourceResolverRegistry();

    // V00.73 fluent bootstrap. Replaces the V00.71 JCustosServiceResolver
    // direct-set calls for PolicyRegistry / ResourceResolverRegistry /
    // JCustosVersionStore and surfaces the V00.71 password-hashing pipeline.
    //
    // .audit(...) is intentionally NOT used here: ApiKeyAuthenticationService,
    // TokenService and the demo's PasswordResetService capture
    // JCustosServiceResolver.securityAuditService() at construction time
    // (lines above), so replacing the audit service at install() would
    // leave those references pointing at the previous instance. Demos
    // that have full control over construction order — like demo-vaadin
    // and demo-standalone — can use .audit(...) freely.
    // Logout fans out to the token store: a session named by its reference is revoked
    // there. Registered through the bootstrap so install() knows a LogoutService exists
    // (logout/missing-service, JS-SEC-124).
    SubjectClearingLogoutService<DemoUser> logoutService = new SubjectClearingLogoutService<>(
        NoopSubjectStore.INSTANCE, DemoUser.class, tokens, null);
    logoutService.addListener((subjectId, sessionId, scope) -> {
      if (sessionId != null) {
        tokens.revokeSession(sessionId);
      }
    });

    JCustosRuntime runtime =
        RestSecurity.bootstrap()
            .mode(JCustosBootstrapMode.DEVELOPMENT)
            .subjectResolver(resolver)
            .credentials(c -> c.hashing(hashingService))
            .sessions(s -> s
                .securityVersion(versionStore)
                .subjectIdResolver(DEMO_SUBJECT_IDS)
                .storeBacked(sessionStore))
            .logout(logoutService)
            .policies(p -> p
                .registry(policyRegistry)
                .resourceRegistry(resourceRegistry)
                .register(DemoPolicies.documentOwnerOrAdmin())
                .resourceResolver(new DemoOwnedDocumentResolver(ownedDocumentStore)))
            .install();
    HasLogger.staticLogger().info("{}", runtime.log());

    JCustosVersionEnforcer versionEnforcer = new JCustosVersionEnforcer(
        versionStore, JCustosServiceResolver.securityAuditService());
    RestJCustosVersionFilter versionFilter = new RestJCustosVersionFilter(
        resolver, versionEnforcer);

    DemoAdministratorAccountStore adminStore = new DemoAdministratorAccountStore(users);
    BootstrapStateService stateService = new BootstrapStateService(adminStore, bootstrapConfig.mode());
    BootstrapTokenStore tokenStore = bootstrapTokenStore(bootstrapConfig);
    BootstrapTokenOutput tokenOutput = bootstrapTokenOutput(bootstrapConfig, port);
    InitialAdminBootstrapService bootstrapService = new InitialAdminBootstrapService(
        stateService, tokenStore, adminStore, hashingService, new MinimumLengthPasswordPolicy(8),
        bootstrapConfig.tokenValidity(), java.time.Clock.systemUTC());
    DemoBootstrapHandlers bootstrapHandlers = new DemoBootstrapHandlers(
        stateService, bootstrapService, bootstrapAttemptPolicy);

    BootstrapStartup.initializeIfRequired(
        stateService, tokenStore, new BootstrapTokenGenerator(), tokenOutput, bootstrapConfig);

    DemoHttpRouter router = new DemoHttpRouter(
        handlers, bootstrapHandlers, resolver, versionFilter);
    // JS-SEC-137 (CWE-319, CWE-1188): plain HTTP, so loopback only.
    HttpServer server = HttpServer.create(
        new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 0);
    server.createContext(DemoEndpoints.API_PREFIX, router);
    server.start();
    return new DemoRestServer(server, server.getAddress().getPort(), resolver, sessionStore);
  }

  private static LoginAttemptPolicy defaultBootstrapAttemptPolicy() {
    return new InMemoryLoginAttemptPolicy(
        LoginAttemptConfiguration.strictBootstrap(),
        Clock.systemUTC(),
        null);
  }

  private static BootstrapTokenStore bootstrapTokenStore(BootstrapConfiguration cfg) {
    return cfg.mode() == BootstrapMode.PERSISTENT_FILE
        ? new FileBootstrapTokenStore(cfg.tokenFilePath())
        : new InMemoryBootstrapTokenStore();
  }

  private static BootstrapTokenOutput bootstrapTokenOutput(BootstrapConfiguration cfg, int port) {
    return switch (cfg.mode()) {
      case PERSISTENT_FILE -> new FileBootstrapTokenOutput();
      case TRANSIENT_CONSOLE -> new ConsoleBootstrapTokenOutput(
          "Open the Vaadin setup page or POST to /api/bootstrap/admin "
              + "(server on port " + port + ").");
      case DISABLED -> (token, configuration) -> {
        // no output
      };
    };
  }

  public int port() {
    return port;
  }

  /** @return the address the server is bound to - the loopback interface (JS-SEC-137) */
  public InetSocketAddress address() {
    return httpServer.getAddress();
  }

  /** @return the session store the REST filters consult (JS-SEC-131); test seam */
  public SessionStore sessionStore() {
    return sessionStore;
  }

  public void stop() {
    httpServer.stop(0);
  }

  /**
   * No-op {@link SubjectStore} for the REST demo. REST handlers don't bind
   * the current subject to a thread-local; the token store is authoritative.
   */
  private enum NoopSubjectStore implements SubjectStore {
    INSTANCE;

    @Override public <T> Optional<T> currentSubject(Class<T> subjectType) {
      return Optional.empty();
    }

    @Override public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
    }

    @Override public <T> void deleteCurrentSubject(Class<T> subjectType) {
    }
  }

  public static void main(String[] args) throws IOException {
    int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
    // V00.73: the RestSecurity.bootstrap() chain that prints the
    // JCustosRuntime diagnostic banner now lives inside start(...) —
    // every demo entry point (main, tests) sees the same wiring.
    DemoRestServer server = start(port);
    System.out.println("Demo REST server running on http://"
        + server.address().getAddress().getHostAddress() + ":" + server.port()
        + " (loopback only).");
    if (DemoUserStore.insecureSeedAccountsRequested()) {
      System.out.println("INSECURE development switch " + DemoUserStore.INSECURE_SEED_ACCOUNTS_PROPERTY
          + " is on: demo accounts editor, viewer (and admin when bootstrap is disabled) "
          + "have fixed, publicly known passwords.");
    } else {
      System.out.println("No demo accounts: create the first administrator through the "
          + "bootstrap flow (POST " + DemoEndpoints.BOOTSTRAP_ADMIN + ").");
    }
    System.out.println("Press Ctrl+C to stop.");
    Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
  }

  /** @return the server's RestSubjectResolver — for V00.72 bootstrap wiring */
  public RestSubjectResolver subjectResolver() {
    return this.subjectResolver;
  }
}