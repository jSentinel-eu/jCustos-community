/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.lifecycle;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.CredentialStatusChanged;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.credential.store.CredentialRecord;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.store.CredentialUpdateResult;
import eu.jsentinel.jcustos.credential.store.InMemoryCredentialStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CredentialLifecycleServiceTest {

  private static final Instant T0 = Instant.parse("2026-06-01T12:00:00Z");
  private static final Clock FIXED = Clock.fixed(T0, ZoneOffset.UTC);

  private static final class RecordingAuditService implements JCustosAuditService {
    final List<AuditEvent> events = new ArrayList<>();

    @Override
    public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override
    public List<AuditEvent> query(AuditQuery q) {
      return List.copyOf(events);
    }
  }

  private static final class FailingAuditService implements JCustosAuditService {
    @Override
    public void publish(AuditEvent event) {
      throw new RuntimeException("sink unavailable");
    }

    @Override
    public List<AuditEvent> query(AuditQuery q) {
      return List.of();
    }
  }

  private InMemoryCredentialStore storeWithAlice(CredentialStatus initial) {
    InMemoryCredentialStore store = new InMemoryCredentialStore();
    store.register(CredentialRecord.initial("alice", "encoded-v0", initial, T0));
    return store;
  }

  @Test
  @DisplayName("decide maps ACTIVE to Proceed")
  void decideActive() {
    CredentialLifecycleService svc = new CredentialLifecycleService(
        new InMemoryCredentialStore(), new RecordingAuditService(), FIXED);
    assertSame(CredentialLifecycleDecision.Proceed.INSTANCE,
        svc.decide(CredentialStatus.ACTIVE));
  }

  @Test
  @DisplayName("decide maps MUST_CHANGE to ForcePasswordChange")
  void decideMustChange() {
    CredentialLifecycleService svc = new CredentialLifecycleService(
        new InMemoryCredentialStore(), new RecordingAuditService(), FIXED);
    assertSame(CredentialLifecycleDecision.ForcePasswordChange.INSTANCE,
        svc.decide(CredentialStatus.MUST_CHANGE));
  }

  @Test
  @DisplayName("decide maps RESET_PENDING / LOCKED / COMPROMISED / DISABLED to dedicated decisions")
  void decideBlockedStates() {
    CredentialLifecycleService svc = new CredentialLifecycleService(
        new InMemoryCredentialStore(), new RecordingAuditService(), FIXED);
    assertSame(CredentialLifecycleDecision.ResetInProgress.INSTANCE,
        svc.decide(CredentialStatus.RESET_PENDING));
    assertSame(CredentialLifecycleDecision.BlockedTemporary.INSTANCE,
        svc.decide(CredentialStatus.LOCKED));
    assertSame(CredentialLifecycleDecision.BlockedPermanent.INSTANCE,
        svc.decide(CredentialStatus.COMPROMISED));
    assertSame(CredentialLifecycleDecision.BlockedPermanent.INSTANCE,
        svc.decide(CredentialStatus.DISABLED));
  }

  @Test
  @DisplayName("decide treats REHASH_REQUIRED and DEPRECATED_ALGORITHM as Proceed")
  void decideRehashFamilyProceeds() {
    CredentialLifecycleService svc = new CredentialLifecycleService(
        new InMemoryCredentialStore(), new RecordingAuditService(), FIXED);
    assertSame(CredentialLifecycleDecision.Proceed.INSTANCE,
        svc.decide(CredentialStatus.REHASH_REQUIRED));
    assertSame(CredentialLifecycleDecision.Proceed.INSTANCE,
        svc.decide(CredentialStatus.DEPRECATED_ALGORITHM));
  }

  @Test
  @DisplayName("Valid transition ACTIVE → MUST_CHANGE writes, audits and bumps version")
  void transitionActiveToMustChange() {
    InMemoryCredentialStore store = storeWithAlice(CredentialStatus.ACTIVE);
    RecordingAuditService audit = new RecordingAuditService();
    CredentialLifecycleService svc = new CredentialLifecycleService(store, audit, FIXED);

    CredentialUpdateResult.Updated updated = (CredentialUpdateResult.Updated)
        svc.transition("alice",
            CredentialStatus.ACTIVE,
            CredentialStatus.MUST_CHANGE,
            "force-change");
    assertEquals(CredentialStatus.MUST_CHANGE, updated.newRecord().status());
    assertEquals(2L, updated.newRecord().version());

    assertEquals(1, audit.events.size());
    CredentialStatusChanged ev = assertInstanceOf(
        CredentialStatusChanged.class, audit.events.get(0));
    assertEquals("alice", ev.username());
    assertEquals(CredentialStatus.ACTIVE, ev.fromStatus());
    assertEquals(CredentialStatus.MUST_CHANGE, ev.toStatus());
    assertEquals("force-change", ev.reason());
  }

  @Test
  @DisplayName("Invalid transition throws InvalidStatusTransitionException without touching the store")
  void invalidTransitionThrows() {
    InMemoryCredentialStore store = storeWithAlice(CredentialStatus.DISABLED);
    RecordingAuditService audit = new RecordingAuditService();
    CredentialLifecycleService svc = new CredentialLifecycleService(store, audit, FIXED);
    InvalidStatusTransitionException ex = assertThrows(
        InvalidStatusTransitionException.class,
        () -> svc.transition("alice",
            CredentialStatus.DISABLED, CredentialStatus.LOCKED, "weird"));
    assertEquals(CredentialStatus.DISABLED, ex.from());
    assertEquals(CredentialStatus.LOCKED, ex.to());
    // store untouched
    assertEquals(CredentialStatus.DISABLED,
        store.findByUsername("alice").orElseThrow().status());
    assertTrue(audit.events.isEmpty());
  }

  @Test
  @DisplayName("Stale CAS returns Stale and does not publish an audit event")
  void staleTransitionDoesNotAudit() {
    InMemoryCredentialStore store = storeWithAlice(CredentialStatus.ACTIVE);
    RecordingAuditService audit = new RecordingAuditService();
    CredentialLifecycleService svc = new CredentialLifecycleService(store, audit, FIXED);
    // Pretend the caller saw LOCKED but the store still has ACTIVE.
    CredentialUpdateResult result = svc.transition(
        "alice", CredentialStatus.LOCKED, CredentialStatus.ACTIVE, "unlock");
    assertSame(CredentialUpdateResult.Stale.INSTANCE, result);
    assertTrue(audit.events.isEmpty());
  }

  @Test
  @DisplayName("JS-SEC-076: Compromised → Disabled and → MUST_CHANGE are allowed; Compromised → ACTIVE is not")
  void compromisedTransitions() {
    InMemoryCredentialStore store = storeWithAlice(CredentialStatus.COMPROMISED);
    RecordingAuditService audit = new RecordingAuditService();
    CredentialLifecycleService svc = new CredentialLifecycleService(store, audit, FIXED);
    assertInstanceOf(CredentialUpdateResult.Updated.class,
        svc.transition("alice",
            CredentialStatus.COMPROMISED, CredentialStatus.DISABLED, "purge"));
    // Re-register a second user to verify the disallowed move from
    // COMPROMISED to MUST_CHANGE without disrupting alice's history.
    InMemoryCredentialStore other = new InMemoryCredentialStore();
    other.register(CredentialRecord.initial(
        "bob", "h", CredentialStatus.COMPROMISED, T0));
    CredentialLifecycleService bobSvc = new CredentialLifecycleService(
        other, audit, FIXED);
    assertThrows(InvalidStatusTransitionException.class,
        () -> bobSvc.transition("bob",
            CredentialStatus.COMPROMISED, CredentialStatus.ACTIVE, "unchanged-secret"),
        "a compromised secret must never be accepted again without rotation");
    assertInstanceOf(CredentialUpdateResult.Updated.class,
        bobSvc.transition("bob",
            CredentialStatus.COMPROMISED, CredentialStatus.MUST_CHANGE, "rotate-on-next-login"));
    assertEquals(CredentialStatus.MUST_CHANGE,
        other.findByUsername("bob").orElseThrow().status());
  }

  @Test
  @DisplayName("Audit-sink failure does not propagate from transition() (CWE-778)")
  void auditFailureSwallowed() {
    InMemoryCredentialStore store = storeWithAlice(CredentialStatus.ACTIVE);
    CredentialLifecycleService svc = new CredentialLifecycleService(
        store, new FailingAuditService(), FIXED);
    CredentialUpdateResult result = svc.transition(
        "alice", CredentialStatus.ACTIVE, CredentialStatus.LOCKED, "brute-force");
    assertInstanceOf(CredentialUpdateResult.Updated.class, result);
    assertEquals(CredentialStatus.LOCKED,
        store.findByUsername("alice").orElseThrow().status());
  }

  @Test
  @DisplayName("isAllowed reports the configured state machine without I/O")
  void isAllowedReports() {
    CredentialLifecycleService svc = new CredentialLifecycleService(
        new InMemoryCredentialStore(), new RecordingAuditService(), FIXED);
    assertTrue(svc.isAllowed(CredentialStatus.ACTIVE, CredentialStatus.MUST_CHANGE));
    assertTrue(svc.isAllowed(CredentialStatus.MUST_CHANGE, CredentialStatus.ACTIVE));
    assertTrue(svc.isAllowed(CredentialStatus.RESET_PENDING, CredentialStatus.ACTIVE));
    assertFalse(svc.isAllowed(CredentialStatus.DISABLED, CredentialStatus.LOCKED));
    assertFalse(svc.isAllowed(CredentialStatus.RESET_PENDING, CredentialStatus.LOCKED));
    // JS-SEC-076 (CWE-284): out of COMPROMISED only through rotation or retirement
    assertFalse(svc.isAllowed(CredentialStatus.COMPROMISED, CredentialStatus.ACTIVE));
    assertTrue(svc.isAllowed(CredentialStatus.COMPROMISED, CredentialStatus.MUST_CHANGE));
    assertTrue(svc.isAllowed(CredentialStatus.COMPROMISED, CredentialStatus.RESET_PENDING));
    assertTrue(svc.isAllowed(CredentialStatus.COMPROMISED, CredentialStatus.DISABLED));
    assertTrue(svc.isAllowed(CredentialStatus.DISABLED, CredentialStatus.ACTIVE), "administrative re-enable stays");
    assertTrue(svc.isAllowed(CredentialStatus.DISABLED, CredentialStatus.MUST_CHANGE));
    assertTrue(svc.isAllowed(CredentialStatus.DISABLED, CredentialStatus.RESET_PENDING));
  }

  @Test
  @DisplayName("CredentialStatusChanged event carries no password material")
  void auditEventIsSecretFree() {
    InMemoryCredentialStore store = storeWithAlice(CredentialStatus.ACTIVE);
    RecordingAuditService audit = new RecordingAuditService();
    CredentialLifecycleService svc = new CredentialLifecycleService(store, audit, FIXED);
    svc.transition("alice", CredentialStatus.ACTIVE, CredentialStatus.LOCKED, "br");
    CredentialStatusChanged ev = (CredentialStatusChanged) audit.events.get(0);
    String text = ev.toString();
    assertFalse(text.contains("encoded-v0"));
    assertTrue(text.contains("alice"));
  }
}
