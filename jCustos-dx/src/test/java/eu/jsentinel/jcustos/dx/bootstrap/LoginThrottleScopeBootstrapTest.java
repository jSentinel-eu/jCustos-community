package eu.jsentinel.jcustos.dx.bootstrap;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptStore;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptLimits;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.NoopLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.StoreBackedLoginAttemptPolicy;
import eu.jsentinel.jcustos.dx.internal.AbstractJCustosBootstrap;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJCustosService;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import eu.jsentinel.jcustos.net.ClientAddressResolver;
import eu.jsentinel.jcustos.session.InMemorySessionStore;
import eu.jsentinel.jcustos.session.TimeoutSessionPolicy;
import eu.jsentinel.jcustos.util.SubjectKeyCanonicalizer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The two findings about where the login throttle counts: {@code
 * bruteforce/in-memory-with-shared-sessions} (JS-SEC-166, CWE-307) and {@code
 * bruteforce/address-limit-without-resolver} (JS-SEC-062, CWE-307, CWE-348). The test bootstrap
 * runs the shared configuration pass of the three adapters, {@code applyCommonConfiguration}.
 */
@DisplayName("JS-SEC-166 / JS-SEC-062: findings about the scope of the login throttle")
class LoginThrottleScopeBootstrapTest {

  private static final String SHARED_SESSIONS = "bruteforce/in-memory-with-shared-sessions";
  private static final String ADDRESS_WITHOUT_RESOLVER = "bruteforce/address-limit-without-resolver";
  private static final LoginAttemptLimits ADDRESS_LIMITED = LoginAttemptLimits.defaults()
      .withAddressLimit(new LoginAttemptLimits.AddressLimit(20, Duration.ofHours(1),
          Duration.ofMinutes(30), Duration.ofHours(2)));

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JCustosServiceResolver.resetAll();
  }

  private static TestBootstrap rest(JCustosBootstrapMode mode) {
    return new TestBootstrap("REST").mode(mode);
  }

  private static TestBootstrap storeBackedSessions(TestBootstrap bootstrap) {
    return bootstrap.sessions(s -> s.storeBacked(new InMemorySessionStore())
        .timeout(Duration.ofMinutes(15)));
  }

  private static List<JCustosBootstrapWarning> findings(List<JCustosBootstrapWarning> warnings,
                                                        String code) {
    return warnings.stream().filter(w -> w.code().equals(code)).toList();
  }

  // ── bruteforce/in-memory-with-shared-sessions ──────────────────────

  @Test
  @DisplayName("store-backed sessions with the resolver's in-memory default: a WARNING in PRODUCTION and STRICT, on REST and Vaadin")
  void storeBackedSessionsWithTheDefaultPolicy() {
    for (String adapter : List.of("REST", "VAADIN")) {
      for (JCustosBootstrapMode mode
          : List.of(JCustosBootstrapMode.PRODUCTION, JCustosBootstrapMode.STRICT)) {
        JCustosServiceResolver.resetAll();
        List<JCustosBootstrapWarning> found = findings(
            storeBackedSessions(new TestBootstrap(adapter).mode(mode)).apply(), SHARED_SESSIONS);
        assertEquals(1, found.size(), adapter + " / " + mode);
        assertEquals(Severity.WARNING, found.getFirst().severity(), adapter + " / " + mode);
        assertTrue(found.getFirst().suggestedFix().contains("StoreBackedLoginAttemptPolicy"),
            found.getFirst().suggestedFix());
      }
    }
  }

  @Test
  @DisplayName("an InMemoryLoginAttemptPolicy passed to .bruteForce(...) is reported as well")
  void storeBackedSessionsWithAnExplicitInMemoryPolicy() {
    List<JCustosBootstrapWarning> warnings = storeBackedSessions(
        rest(JCustosBootstrapMode.PRODUCTION).bruteForce(new InMemoryLoginAttemptPolicy()))
        .apply();
    assertEquals(1, findings(warnings, SHARED_SESSIONS).size(), warnings.toString());
  }

  @Test
  @DisplayName("not reported: a store-backed policy, sessions without a store, the development modes, the no-op, the standalone adapter")
  void sharedSessionsFindingStaysQuietWhereItDoesNotApply() {
    assertTrue(findings(storeBackedSessions(rest(JCustosBootstrapMode.PRODUCTION).bruteForce(
            new StoreBackedLoginAttemptPolicy(new InMemoryLoginAttemptStore()))).apply(),
        SHARED_SESSIONS).isEmpty(), "a store-backed login policy");

    JCustosServiceResolver.resetAll();
    assertTrue(findings(rest(JCustosBootstrapMode.PRODUCTION).apply(), SHARED_SESSIONS).isEmpty(),
        "no .sessions(...)");
    assertTrue(findings(rest(JCustosBootstrapMode.STRICT)
            .sessions(s -> s.policy(new TimeoutSessionPolicy<>()))
            .apply(), SHARED_SESSIONS).isEmpty(),
        "sessions with a policy but without a store");

    for (JCustosBootstrapMode mode
        : List.of(JCustosBootstrapMode.DEVELOPMENT, JCustosBootstrapMode.COMMUNITY_DEFAULTS)) {
      JCustosServiceResolver.resetAll();
      assertTrue(findings(storeBackedSessions(rest(mode)).apply(), SHARED_SESSIONS).isEmpty(),
          mode + " runs on one node");
    }

    JCustosServiceResolver.resetAll();
    List<JCustosBootstrapWarning> noop = storeBackedSessions(
        rest(JCustosBootstrapMode.PRODUCTION).bruteForce(new NoopLoginAttemptPolicy())).apply();
    assertTrue(findings(noop, SHARED_SESSIONS).isEmpty(), "the no-op is not in-memory throttling");
    assertFalse(findings(noop, "bruteforce/noop-policy").isEmpty(), "it has a finding of its own");

    JCustosServiceResolver.resetAll();
    assertTrue(findings(storeBackedSessions(new TestBootstrap("STANDALONE")
            .mode(JCustosBootstrapMode.PRODUCTION)).apply(), SHARED_SESSIONS).isEmpty(),
        "the CLI adapter has no session model");
  }

  // ── bruteforce/address-limit-without-resolver ──────────────────────

  @Test
  @DisplayName("an address limit without a ClientAddressResolver: a WARNING in every mode, for both shipped policies")
  void addressLimitWithoutResolver() {
    List<LoginAttemptPolicy> policies = List.of(
        new InMemoryLoginAttemptPolicy(ADDRESS_LIMITED, Clock.systemUTC(), null),
        new StoreBackedLoginAttemptPolicy(new InMemoryLoginAttemptStore(), ADDRESS_LIMITED,
            null, Clock.systemUTC(), SubjectKeyCanonicalizer.defaults(),
            null));
    for (LoginAttemptPolicy policy : policies) {
      for (JCustosBootstrapMode mode : JCustosBootstrapMode.values()) {
        JCustosServiceResolver.resetAll();
        List<JCustosBootstrapWarning> found = findings(rest(mode).bruteForce(policy).apply(),
            ADDRESS_WITHOUT_RESOLVER);
        String scenario = policy.getClass().getSimpleName() + " / " + mode;
        assertEquals(1, found.size(), scenario);
        assertEquals(Severity.WARNING, found.getFirst().severity(), scenario);
        assertTrue(found.getFirst().suggestedFix().contains("trustedProxies"), scenario);
      }
    }
  }

  @Test
  @DisplayName("not reported: a resolver from .clientAddress(...) - also the connection peer - or from the resolver, no address limit, the standalone adapter")
  void addressLimitFindingStaysQuietWhereItDoesNotApply() {
    LoginAttemptPolicy limited = new InMemoryLoginAttemptPolicy(ADDRESS_LIMITED,
        Clock.systemUTC(), null);
    assertTrue(findings(rest(JCustosBootstrapMode.PRODUCTION).bruteForce(limited)
            .clientAddress(ClientAddressResolver.trustedProxies("10.0.0.0/8")).apply(),
        ADDRESS_WITHOUT_RESOLVER).isEmpty(), "trusted proxies");

    JCustosServiceResolver.resetAll();
    assertTrue(findings(rest(JCustosBootstrapMode.PRODUCTION).bruteForce(limited)
            .clientAddress(ClientAddressResolver.remoteAddress()).apply(),
        ADDRESS_WITHOUT_RESOLVER).isEmpty(), "the connection peer, chosen explicitly");

    JCustosServiceResolver.resetAll();
    JCustosServiceResolver.setClientAddressResolver(
        ClientAddressResolver.trustedProxies("127.0.0.1"));
    assertTrue(findings(rest(JCustosBootstrapMode.PRODUCTION).bruteForce(limited).apply(),
        ADDRESS_WITHOUT_RESOLVER).isEmpty(), "a resolver registered outside the bootstrap");

    JCustosServiceResolver.resetAll();
    assertTrue(findings(rest(JCustosBootstrapMode.PRODUCTION)
            .bruteForce(new InMemoryLoginAttemptPolicy()).apply(),
        ADDRESS_WITHOUT_RESOLVER).isEmpty(), "no address limit");
    assertTrue(findings(rest(JCustosBootstrapMode.PRODUCTION).apply(),
        ADDRESS_WITHOUT_RESOLVER).isEmpty(), "the resolver default has no address limit");

    JCustosServiceResolver.resetAll();
    assertTrue(findings(new TestBootstrap("STANDALONE")
            .mode(JCustosBootstrapMode.PRODUCTION).bruteForce(limited).apply(),
        ADDRESS_WITHOUT_RESOLVER).isEmpty(), "the CLI adapter has no client address");
  }

  // ── test double ──────────────────────────────────────────────────

  /** Runs the shared configuration pass of the adapters for one adapter kind. */
  private static final class TestBootstrap extends AbstractJCustosBootstrap<TestBootstrap> {
    private final AdapterKind adapter;

    /** @param adapter the name of an {@code AdapterKind}: REST, VAADIN or STANDALONE */
    private TestBootstrap(String adapter) {
      this.adapter = AdapterKind.valueOf(adapter);
    }

    List<JCustosBootstrapWarning> apply() {
      List<RegisteredJCustosService> services = new ArrayList<>();
      List<JCustosBootstrapWarning> warnings = new ArrayList<>();
      applyCommonConfiguration(adapter, services, warnings);
      return warnings;
    }
  }
}
