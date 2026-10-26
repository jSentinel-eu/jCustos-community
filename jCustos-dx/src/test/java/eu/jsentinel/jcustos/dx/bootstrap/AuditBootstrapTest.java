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

import eu.jsentinel.jcustos.audit.AuditEnvelope;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditEventStore;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.CompositeAuditService;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.StoreBackedJCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.dx.internal.AbstractJCustosBootstrap;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJCustosService;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * V00.73 audit-bootstrap behaviour tests. Drives the real adapter
 * (concrete subclass {@link TestAuditOnlyBootstrap} below) so audit
 * state actually reaches the {@code JCustosServiceResolver}. No
 * Mockito — fake stores are real implementations.
 */
@DisplayName("AuditBootstrap real surface (V00.73)")
class AuditBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName(".storeBacked(store) registers a StoreBackedJCustosAuditService")
  void storeBackedRegistersStoreBackedService() {
    AuditEventStore store = new InMemoryAuditEventStore();
    JCustosRuntime runtime = new TestAuditOnlyBootstrap()
        .audit(a -> a.storeBacked(store))
        .install();

    JCustosAuditService registered = JCustosServiceResolver
        .findJCustosAuditService().orElseThrow();
    assertInstanceOf(StoreBackedJCustosAuditService.class, registered);
    assertRuntimeHasAuditEntry(runtime, StoreBackedJCustosAuditService.class);
  }

  @Test
  @DisplayName("sinks-only (logging only) registers a CompositeAuditService with a default ring buffer")
  void loggingOnlyComposes() {
    JCustosRuntime runtime = new TestAuditOnlyBootstrap()
        .audit(a -> a.logging())
        .install();

    JCustosAuditService registered = JCustosServiceResolver
        .findJCustosAuditService().orElseThrow();
    assertInstanceOf(CompositeAuditService.class, registered);
    assertRuntimeHasAuditEntry(runtime, CompositeAuditService.class);
  }

  @Test
  @DisplayName("logging + ringBuffer composes into a single CompositeAuditService")
  void loggingPlusRingBufferComposes() {
    JCustosRuntime runtime = new TestAuditOnlyBootstrap()
        .audit(a -> a.logging().ringBuffer(64))
        .install();

    JCustosAuditService registered = JCustosServiceResolver
        .findJCustosAuditService().orElseThrow();
    assertInstanceOf(CompositeAuditService.class, registered);
    CompositeAuditService composite = (CompositeAuditService) registered;
    assertEquals(64, composite.ringBuffer().capacity());
    assertEquals(1, composite.extraSinks().size());
    assertRuntimeHasAuditEntry(runtime, CompositeAuditService.class);
  }

  @Test
  @DisplayName("storeBacked + sinks → TeeingJCustosAuditService")
  void storeBackedPlusSinksTees() {
    AuditEventStore store = new InMemoryAuditEventStore();
    JCustosRuntime runtime = new TestAuditOnlyBootstrap()
        .audit(a -> a.storeBacked(store).ringBuffer(32).logging())
        .install();

    JCustosAuditService registered = JCustosServiceResolver
        .findJCustosAuditService().orElseThrow();
    assertEquals("TeeingJCustosAuditService", registered.getClass().getSimpleName());
    assertRuntimeHasAuditEntry(runtime, registered.getClass());

    AuditEvent event = new LoginSucceeded(Instant.EPOCH, "alice", "127.0.0.1", null);
    registered.publish(event);
    assertEquals(1, ((InMemoryAuditEventStore) store).events.size(),
        "tee forwards publish to store-backed primary");
  }

  @Test
  @DisplayName(".securityAuditService(svc) registers svc directly without wrapping")
  void directServiceWinsWithoutWrapping() {
    JCustosAuditService direct = new RecordingAuditService();
    new TestAuditOnlyBootstrap()
        .audit(a -> a.securityAuditService(direct))
        .install();

    JCustosAuditService registered = JCustosServiceResolver
        .findJCustosAuditService().orElseThrow();
    assertEquals(direct, registered, "direct service must not be wrapped");
  }

  @Test
  @DisplayName("STRICT empty .audit(a -> {}) throws audit/missing-service")
  void strictEmptyAuditThrows() {
    JCustosBootstrapException ex = assertThrows(
        JCustosBootstrapException.class,
        () -> new TestAuditOnlyBootstrap()
            .mode(JCustosBootstrapMode.STRICT)
            .audit(a -> { })
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "audit/missing-service".equals(w.code())));
  }

  @Test
  @DisplayName("PRODUCTION empty .audit(a -> {}) records ERROR warning but does not throw")
  void productionEmptyAuditWarns() {
    JCustosRuntime runtime = new TestAuditOnlyBootstrap()
        .mode(JCustosBootstrapMode.PRODUCTION)
        .audit(a -> { })
        .install();
    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "audit/missing-service".equals(w.code())
            && w.severity() == Severity.ERROR));
  }

  @Test
  @DisplayName("JS-SEC-080: STRICT without .audit(...) and without a registered service throws audit/noop-fallback")
  void strictWithoutAnyAuditThrows() {
    JCustosBootstrapException ex = assertThrows(
        JCustosBootstrapException.class,
        () -> new TestAuditOnlyBootstrap()
            .mode(JCustosBootstrapMode.STRICT)
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "audit/noop-fallback".equals(w.code()) && w.severity() == Severity.ERROR));
  }

  @Test
  @DisplayName("JS-SEC-080: PRODUCTION without .audit(...) records a WARNING audit/noop-fallback and boots")
  void productionWithoutAnyAuditWarns() {
    JCustosRuntime runtime = new TestAuditOnlyBootstrap()
        .mode(JCustosBootstrapMode.PRODUCTION)
        .install();
    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "audit/noop-fallback".equals(w.code()) && w.severity() == Severity.WARNING));
  }

  @Test
  @DisplayName("JS-SEC-080: a service registered outside the bootstrap silences audit/noop-fallback")
  void registeredServiceSilencesNoopFallback() {
    JCustosServiceResolver.setJCustosAuditService(new RecordingAuditService());
    JCustosRuntime runtime = new TestAuditOnlyBootstrap()
        .mode(JCustosBootstrapMode.STRICT)
        .install();
    assertFalse(runtime.warnings().stream()
        .anyMatch(w -> "audit/noop-fallback".equals(w.code())));
  }

  @Test
  @DisplayName("STRICT .storeBacked(null) throws audit/store-backed-without-store")
  void strictStoreBackedNullThrows() {
    JCustosBootstrapException ex = assertThrows(
        JCustosBootstrapException.class,
        () -> new TestAuditOnlyBootstrap()
            .mode(JCustosBootstrapMode.STRICT)
            .audit(a -> a.storeBacked(null))
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "audit/store-backed-without-store".equals(w.code())));
  }

  @Test
  @DisplayName("STRICT .ringBuffer(0) throws audit/invalid-ring-buffer-capacity")
  void strictRingBufferZeroThrows() {
    JCustosBootstrapException ex = assertThrows(
        JCustosBootstrapException.class,
        () -> new TestAuditOnlyBootstrap()
            .mode(JCustosBootstrapMode.STRICT)
            .audit(a -> a.ringBuffer(0))
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "audit/invalid-ring-buffer-capacity".equals(w.code())));
  }

  @Test
  @DisplayName("STRICT direct + composition throws audit/conflicting-direct-service")
  void strictDirectPlusCompositionThrows() {
    JCustosBootstrapException ex = assertThrows(
        JCustosBootstrapException.class,
        () -> new TestAuditOnlyBootstrap()
            .mode(JCustosBootstrapMode.STRICT)
            .audit(a -> a.securityAuditService(new RecordingAuditService())
                .ringBuffer(16))
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "audit/conflicting-direct-service".equals(w.code())));
  }

  @Test
  @DisplayName(".credentialEvents(true) is recorded but does not change audit wiring")
  void credentialEventsRecordedNotWired() {
    AuditEventStore store = new InMemoryAuditEventStore();
    JCustosRuntime runtime = new TestAuditOnlyBootstrap()
        .audit(a -> a.storeBacked(store).credentialEvents(true))
        .install();

    JCustosAuditService registered = JCustosServiceResolver
        .findJCustosAuditService().orElseThrow();
    assertInstanceOf(StoreBackedJCustosAuditService.class, registered);
    // JCustosRuntime surfaces the flag through a synthetic SPI entry
    boolean flagEntryPresent = runtime.services().stream()
        .anyMatch(s -> s.spi().getSimpleName().equals("CredentialEventsFlag"));
    assertTrue(flagEntryPresent, "credentialEvents flag must appear in runtime");
  }

  // ── helpers ──────────────────────────────────────────────────────

  private static void assertRuntimeHasAuditEntry(JCustosRuntime runtime, Class<?> implClass) {
    boolean found = runtime.services().stream()
        .anyMatch(s -> JCustosAuditService.class.equals(s.spi())
            && implClass.equals(s.impl()));
    assertTrue(found,
        "runtime.services() expected to contain JCustosAuditService impl=" + implClass);
    assertFalse(runtime.services().isEmpty());
  }

  /**
   * Minimal adapter that drives only audit configuration. No authn/
   * authz wiring — the tests don't need it, and the audit pipeline
   * must remain independent of those.
   */
  private static final class TestAuditOnlyBootstrap
      extends AbstractJCustosBootstrap<TestAuditOnlyBootstrap> {

    @Override
    public JCustosRuntime install() {
      java.util.List<RegisteredJCustosService> services = new java.util.ArrayList<>();
      java.util.List<JCustosBootstrapWarning> warnings = new java.util.ArrayList<>();
      applyAuditConfiguration(services, warnings);
      JCustosBootstrapMode mode = state.mode();
      if (mode == JCustosBootstrapMode.STRICT && warningsContainError(warnings)) {
        throw new JCustosBootstrapException(warnings);
      }
      return new JCustosRuntime(services, warnings, mode);
    }
  }

  /** Minimal AuditEventStore that just collects events in-memory. */
  private static final class InMemoryAuditEventStore implements AuditEventStore {
    final List<AuditEnvelope> events = new java.util.ArrayList<>();
    @Override public AuditEnvelope append(TenantId tenant, AuditEvent event) {
      assertNotNull(event);
      AuditEnvelope env = new AuditEnvelope(
          "evt-" + (events.size() + 1),
          tenant != null ? tenant : TenantId.DEFAULT,
          event);
      events.add(env);
      return env;
    }
    @Override public List<AuditEnvelope> query(TenantId tenant, AuditQuery query) {
      return List.copyOf(events);
    }
    @Override public int purgeOlderThan(Instant cutoff) {
      events.removeIf(e -> e.event().timestamp().isBefore(cutoff));
      return 0;
    }
  }

  /** Pass-through audit service used to verify direct-wiring. */
  private static final class RecordingAuditService implements JCustosAuditService {
    @Override public void publish(AuditEvent event) { }
    @Override public List<AuditEvent> query(AuditQuery query) { return List.of(); }
  }
}
