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
package eu.jsentinel.jcustos.credential.emergency;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.CredentialStatusChanged;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.credential.store.CredentialRecord;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.store.InMemoryCredentialStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MassCredentialStatusChangeTest {

  private static final Instant T0 = Instant.parse("2026-06-01T12:00:00Z");

  private static final class RecordingAudit implements JCustosAuditService {
    final List<AuditEvent> events = new ArrayList<>();
    @Override public void publish(AuditEvent event) { events.add(event); }
    @Override public List<AuditEvent> query(AuditQuery q) { return List.copyOf(events); }
  }

  private static EmergencyPolicyOverride override() {
    return new EmergencyPolicyOverride(
        "INC-2026-06-pepper",
        EmergencyPolicyOverride.Reason.PEPPER_COMPROMISE,
        T0.minusSeconds(60),
        T0.plusSeconds(3600),
        "operator-alice");
  }

  private static InMemoryCredentialStore prefilled() {
    InMemoryCredentialStore store = new InMemoryCredentialStore();
    store.register(new CredentialRecord(
        "alice", "$pwh$v=1$...alice", CredentialStatus.ACTIVE, 1L, T0, T0));
    store.register(new CredentialRecord(
        "bob", "$pwh$v=1$...bob", CredentialStatus.ACTIVE, 1L, T0, T0));
    store.register(new CredentialRecord(
        "carol", "$pwh$v=1$...carol", CredentialStatus.MUST_CHANGE, 1L, T0, T0));
    return store;
  }

  @Test
  @DisplayName("Forces every named credential to MUST_CHANGE — counts and audit events match")
  void forceMassChange() {
    InMemoryCredentialStore store = prefilled();
    RecordingAudit audit = new RecordingAudit();
    MassCredentialStatusChange mass = new MassCredentialStatusChange(
        store, audit, Clock.fixed(T0, ZoneOffset.UTC));

    MassCredentialStatusChange.Report report = mass.forceAllToStatus(
        List.of("alice", "bob", "carol", "unknown"),
        CredentialStatus.MUST_CHANGE,
        override());

    assertEquals(2, report.changed(), "alice + bob transition");
    assertEquals(1, report.alreadyAtTarget(),
        "carol is already MUST_CHANGE");
    assertEquals(1, report.notFound(),
        "unknown user is reported as not-found");
    assertEquals(0, report.stale());
    assertEquals(4, report.total());

    assertEquals(2, audit.events.size(),
        "one audit event per real transition");
    CredentialStatusChanged firstAudit = assertInstanceOf(
        CredentialStatusChanged.class, audit.events.get(0));
    assertEquals(CredentialStatus.ACTIVE, firstAudit.fromStatus());
    assertEquals(CredentialStatus.MUST_CHANGE, firstAudit.toStatus());
    assertTrue(firstAudit.reason().startsWith("INC-2026-06-pepper/"),
        "audit reason carries incident id and reason category");
  }

  /** Audit sink that fails on every publish — the incident run must survive it. */
  private static final class FailingAudit implements JCustosAuditService {
    int attempts;
    @Override public void publish(AuditEvent event) { attempts++; throw new IllegalStateException("sink down"); }
    @Override public List<AuditEvent> query(AuditQuery q) { return List.of(); }
  }

  @Test
  @DisplayName("JS-SEC-077: a failing audit sink does not abort the incident run (CWE-703)")
  void auditFailureDoesNotAbortRun() {
    InMemoryCredentialStore store = new InMemoryCredentialStore();
    for (String name : List.of("alice", "bob", "carol")) {
      store.register(new CredentialRecord(name, "$pwh$v=1$..." + name, CredentialStatus.ACTIVE, 1L, T0, T0));
    }
    FailingAudit audit = new FailingAudit();
    MassCredentialStatusChange mass = new MassCredentialStatusChange(
        store, audit, Clock.fixed(T0, ZoneOffset.UTC));

    MassCredentialStatusChange.Report report = mass.forceAllToStatus(
        List.of("alice", "bob", "carol"), CredentialStatus.MUST_CHANGE, override());

    assertEquals(3, report.changed(), "every account must be processed despite the failing sink");
    assertEquals(3, report.auditFailures(), "each failed publish is counted, none is hidden");
    assertEquals(3, audit.attempts);
    for (String name : List.of("alice", "bob", "carol")) {
      assertEquals(CredentialStatus.MUST_CHANGE, store.findByUsername(name).orElseThrow().status(),
          name + " must be at the target status");
    }
    assertEquals(3, report.total(), "audit failures are not a fifth outcome bucket");
  }

  @Test
  @DisplayName("Blank / null usernames in the input are counted as not-found, not crashes")
  void blankUsernamesNotFound() {
    InMemoryCredentialStore store = prefilled();
    RecordingAudit audit = new RecordingAudit();
    MassCredentialStatusChange mass = new MassCredentialStatusChange(
        store, audit, Clock.fixed(T0, ZoneOffset.UTC));

    ArrayList<String> users = new ArrayList<>();
    users.add(null);
    users.add("");
    users.add("   ");
    users.add("alice");
    MassCredentialStatusChange.Report report = mass.forceAllToStatus(
        users, CredentialStatus.MUST_CHANGE, override());

    assertEquals(1, report.changed());
    assertEquals(3, report.notFound());
  }

  @Test
  @DisplayName("CAS contention surfaces as a Stale count, not an exception")
  void staleSurfacesAsCount() {
    // Hand-rolled store that always returns Stale on update so we
    // can verify the helper aggregates correctly without crashing.
    eu.jsentinel.jcustos.credential.store.CredentialStore alwaysStale =
        new eu.jsentinel.jcustos.credential.store.CredentialStore() {
          @Override public java.util.Optional<CredentialRecord> findByUsername(String u) {
            return java.util.Optional.of(new CredentialRecord(
                u, "$pwh$v=1$...x", CredentialStatus.ACTIVE, 1L, T0, T0));
          }
          @Override public eu.jsentinel.jcustos.credential.store.CredentialUpdateResult
              updateHashIfCurrent(String u, String expected, String now, Instant when) {
            return eu.jsentinel.jcustos.credential.store
                .CredentialUpdateResult.Stale.INSTANCE;
          }
          @Override public eu.jsentinel.jcustos.credential.store.CredentialUpdateResult
              updateStatusIfCurrent(String u, CredentialStatus expected, CredentialStatus now, Instant when) {
            return eu.jsentinel.jcustos.credential.store
                .CredentialUpdateResult.Stale.INSTANCE;
          }
        };
    RecordingAudit audit = new RecordingAudit();
    MassCredentialStatusChange mass = new MassCredentialStatusChange(
        alwaysStale, audit, Clock.fixed(T0, ZoneOffset.UTC));

    MassCredentialStatusChange.Report report = mass.forceAllToStatus(
        List.of("alice", "bob"),
        CredentialStatus.MUST_CHANGE,
        override());

    assertEquals(2, report.stale());
    assertEquals(0, report.changed());
    assertTrue(audit.events.isEmpty(),
        "Stale must not emit audit events for non-transitions");
  }

  @Test
  @DisplayName("EmergencyPolicyOverride invariants: blank id / blank operator / time-order")
  void overrideInvariants() {
    assertThrows(IllegalArgumentException.class,
        () -> new EmergencyPolicyOverride(
            "", EmergencyPolicyOverride.Reason.MASS_ROTATION,
            T0, T0.plusSeconds(60), "alice"));
    assertThrows(IllegalArgumentException.class,
        () -> new EmergencyPolicyOverride(
            "INC", EmergencyPolicyOverride.Reason.MASS_ROTATION,
            T0, T0.plusSeconds(60), "  "));
    assertThrows(IllegalArgumentException.class,
        () -> new EmergencyPolicyOverride(
            "INC", EmergencyPolicyOverride.Reason.MASS_ROTATION,
            T0.plusSeconds(60), T0, "alice"));
  }

  @Test
  @DisplayName("Report invariants reject negative counts")
  void reportInvariants() {
    assertThrows(IllegalArgumentException.class,
        () -> new MassCredentialStatusChange.Report(-1, 0, 0, 0));
  }

  @Test
  @DisplayName("Constructor rejects null collaborators")
  void constructorInvariants() {
    InMemoryCredentialStore s = new InMemoryCredentialStore();
    RecordingAudit a = new RecordingAudit();
    Clock c = Clock.systemUTC();
    assertThrows(NullPointerException.class,
        () -> new MassCredentialStatusChange(null, a, c));
    assertThrows(NullPointerException.class,
        () -> new MassCredentialStatusChange(s, null, c));
    assertThrows(NullPointerException.class,
        () -> new MassCredentialStatusChange(s, a, null));
  }

  @Test
  @DisplayName("Audit reason field never embeds operator credentials")
  void auditReasonNoSecrets() {
    InMemoryCredentialStore store = prefilled();
    RecordingAudit audit = new RecordingAudit();
    MassCredentialStatusChange mass = new MassCredentialStatusChange(
        store, audit, Clock.fixed(T0, ZoneOffset.UTC));
    mass.forceAllToStatus(
        List.of("alice"),
        CredentialStatus.LOCKED,
        override());
    CredentialStatusChanged event = assertInstanceOf(
        CredentialStatusChanged.class, audit.events.get(0));
    // sanity: the audit reason carries the incident id + category,
    // but never the operator's authorisedBy field's content beyond
    // the incident id (which is operator-curated).
    assertEquals("INC-2026-06-pepper/PEPPER_COMPROMISE",
        event.reason());
  }
}
