/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.dx.bootstrap;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.dx.internal.AbstractJCustosBootstrap;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJCustosService;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.InMemorySessionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.JCustosVersionStore;
import eu.jsentinel.jcustos.session.SessionPolicy;
import eu.jsentinel.jcustos.session.SessionStore;
import eu.jsentinel.jcustos.session.TimeoutSessionPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * V00.73 session-bootstrap behaviour tests. Tests run against real
 * implementations of {@link SessionStore} / {@link SessionPolicy}
 * etc.; no Mockito.
 */
@DisplayName("SessionBootstrap real surface (V00.73)")
class SessionBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("timeout + storeBacked constructs and registers a TimeoutSessionPolicy")
  void timeoutAndStoreConstructsTimeoutPolicy() {
    SessionStore store = new InMemorySessionStore();
    JCustosRuntime runtime = new VaadinTestBootstrap()
        .sessions(s -> s.storeBacked(store).timeout(Duration.ofMinutes(15)))
        .install();

    SessionPolicy<?> policy = JCustosServiceResolver.findSessionPolicy().orElseThrow();
    assertInstanceOf(TimeoutSessionPolicy.class, policy);
    assertTrue(runtime.services().stream()
        .anyMatch(s -> SessionPolicy.class.equals(s.spi())));
    assertTrue(runtime.services().stream()
        .anyMatch(s -> SessionStore.class.equals(s.spi())
            && InMemorySessionStore.class.equals(s.impl())));
  }

  @Test
  @DisplayName("custom .policy(...) wins over timeout-derived construction")
  void customPolicyWinsOverTimeout() {
    SessionPolicy<?> custom = new TimeoutSessionPolicy<>();
    new VaadinTestBootstrap()
        .sessions(s -> s.policy(custom).timeout(Duration.ofHours(1)))
        .install();
    SessionPolicy<?> registered = JCustosServiceResolver.findSessionPolicy().orElseThrow();
    assertSame(custom, registered, "custom policy must not be wrapped or replaced");
  }

  @Test
  @DisplayName(".securityVersion(...) + .subjectIdResolver(...) register both via resolver")
  void securityVersionAndSubjectIdResolverRegister() {
    JCustosVersionStore vstore = new RecordingVersionStore();
    SubjectIdResolver<String> resolver = subject -> SubjectId.of(subject);
    new VaadinTestBootstrap()
        .sessions(s -> s.securityVersion(vstore).subjectIdResolver(resolver))
        .install();
    assertSame(vstore, JCustosServiceResolver.findJCustosVersionStore().orElseThrow());
    Optional<SubjectIdResolver<Object>> found = JCustosServiceResolver.findSubjectIdResolver();
    assertTrue(found.isPresent());
  }

  @Test
  @DisplayName("STRICT timeout without store throws sessions/missing-store")
  void strictTimeoutWithoutStoreThrows() {
    JCustosBootstrapException ex = assertThrows(
        JCustosBootstrapException.class,
        () -> new VaadinTestBootstrap()
            .mode(JCustosBootstrapMode.STRICT)
            .sessions(s -> s.timeout(Duration.ofMinutes(5)))
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "sessions/missing-store".equals(w.code())));
  }

  @Test
  @DisplayName("STRICT invalid timeout (zero) throws sessions/invalid-timeout")
  void strictInvalidTimeoutThrows() {
    JCustosBootstrapException ex = assertThrows(
        JCustosBootstrapException.class,
        () -> new VaadinTestBootstrap()
            .mode(JCustosBootstrapMode.STRICT)
            .sessions(s -> s.storeBacked(new InMemorySessionStore()).timeout(Duration.ZERO))
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "sessions/invalid-timeout".equals(w.code())));
  }

  @Test
  @DisplayName("BL06/JS-SEC-065: STRICT store-backed sessions without explicit lifetime boot on the secure default and report INFO")
  void strictStoreWithoutLifetimeBootsOnSecureDefault() {
    var runtime = new VaadinTestBootstrap()
        .mode(JCustosBootstrapMode.STRICT)
        .audit(a -> a.logging()) // JS-SEC-080: STRICT refuses to boot without an audit trail
        .sessions(s -> s.storeBacked(new InMemorySessionStore()))
        .install();
    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "sessions/no-timeout-policy".equals(w.code())
            && w.severity() == eu.jsentinel.jcustos.dx.runtime.Severity.INFO),
        "since 00.84.00 the resolver default enforces 30 min / 12 h, so the finding is INFO, not a gate");
  }

  @Test
  @DisplayName("BL06: outside STRICT/PRODUCTION the missing lifetime stays a non-fatal finding")
  void defaultModeStoreWithoutLifetimeBoots() {
    // default (dev) mode: the same setup boots — the finding is INFO, not a gate
    new VaadinTestBootstrap()
        .sessions(s -> s.storeBacked(new InMemorySessionStore()))
        .install();
  }

  @Test
  @DisplayName("BL06: a configured timeout silences sessions/no-timeout-policy")
  void configuredTimeoutSilencesTheFinding() {
    JCustosBootstrapException ex = assertThrows(
        JCustosBootstrapException.class,
        () -> new VaadinTestBootstrap()
            .mode(JCustosBootstrapMode.STRICT)
            .sessions(s -> s.storeBacked(new InMemorySessionStore()).timeout(Duration.ZERO))
            .install());
    // invalid-timeout still fires, but never the no-timeout-policy code
    assertTrue(ex.warnings().stream()
        .noneMatch(w -> "sessions/no-timeout-policy".equals(w.code())));
  }

  @Test
  @DisplayName("STRICT securityVersion without subjectIdResolver throws security-version-without-subject-id-resolver")
  void strictJCustosVersionWithoutResolverThrows() {
    JCustosBootstrapException ex = assertThrows(
        JCustosBootstrapException.class,
        () -> new VaadinTestBootstrap()
            .mode(JCustosBootstrapMode.STRICT)
            .sessions(s -> s.securityVersion(new RecordingVersionStore()))
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "security-version-without-subject-id-resolver".equals(w.code())));
  }

  @Test
  @DisplayName("standalone .sessions(...) records INFO standalone/sessions-not-applicable")
  void standaloneSessionsRecordsInfo() {
    JCustosRuntime runtime = new StandaloneTestBootstrap()
        .sessions(s -> s.storeBacked(new InMemorySessionStore()))
        .install();
    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "standalone/sessions-not-applicable".equals(w.code())
            && w.severity() == Severity.INFO));
    // resolver must not be touched
    assertFalse(JCustosServiceResolver.findSessionPolicy().isPresent());
  }

  @Test
  @DisplayName("REST .storeBacked(...) records INFO rest/session-store-unused but still wires policy/version")
  void restStoreBackedUnusedButOthersWired() {
    SessionStore store = new InMemorySessionStore();
    JCustosVersionStore vstore = new RecordingVersionStore();
    SubjectIdResolver<String> resolver = s -> SubjectId.of(s);
    JCustosRuntime runtime = new RestTestBootstrap()
        .sessions(s -> s.storeBacked(store).securityVersion(vstore).subjectIdResolver(resolver)
            .timeout(Duration.ofMinutes(10)))
        .install();
    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "rest/session-store-unused".equals(w.code())
            && w.severity() == Severity.INFO));
    assertTrue(JCustosServiceResolver.findSessionPolicy().isPresent(),
        "REST still wires SessionPolicy/JCustosVersion/SubjectIdResolver");
  }

  // ── adapter test doubles ─────────────────────────────────────────

  /**
   * Shared install routine for the three test bootstraps. Lives as a
   * static method that subclasses dispatch to via `super`-protected
   * access to the package-private aggregate; the {@link AdapterKind}
   * is the only thing that varies across them.
   */
  private abstract static class BaseTestBootstrap<B extends BaseTestBootstrap<B>>
      extends AbstractJCustosBootstrap<B> {

    abstract AdapterKind adapterKind();

    @Override
    public JCustosRuntime install() {
      List<RegisteredJCustosService> services = new ArrayList<>();
      List<JCustosBootstrapWarning> warnings = new ArrayList<>();
      applyAuditConfiguration(services, warnings);
      applySessionConfiguration(adapterKind(), services, warnings);
      JCustosBootstrapMode mode = state.mode();
      boolean strictError = mode == JCustosBootstrapMode.STRICT
          && warnings.stream().anyMatch(w -> w.severity() == Severity.ERROR);
      if (strictError) {
        throw new JCustosBootstrapException(warnings);
      }
      return new JCustosRuntime(services, warnings, mode);
    }
  }

  private static final class VaadinTestBootstrap extends BaseTestBootstrap<VaadinTestBootstrap> {
    @Override AdapterKind adapterKind() { return AdapterKind.VAADIN; }
  }

  private static final class RestTestBootstrap extends BaseTestBootstrap<RestTestBootstrap> {
    @Override AdapterKind adapterKind() { return AdapterKind.REST; }
  }

  private static final class StandaloneTestBootstrap extends BaseTestBootstrap<StandaloneTestBootstrap> {
    @Override AdapterKind adapterKind() { return AdapterKind.STANDALONE; }
  }

  /** Empty JCustosVersionStore stub — just needs to be a real instance. */
  private static final class RecordingVersionStore implements JCustosVersionStore {
    private JCustosVersion version = JCustosVersion.INITIAL;
    @Override public JCustosVersion current(JCustosVersionKey key) { return version; }
    @Override public JCustosVersion increment(JCustosVersionKey key) {
      version = version.next();
      return version;
    }
    @Override public void reset(JCustosVersionKey key) {
      version = JCustosVersion.INITIAL;
    }
  }
}
