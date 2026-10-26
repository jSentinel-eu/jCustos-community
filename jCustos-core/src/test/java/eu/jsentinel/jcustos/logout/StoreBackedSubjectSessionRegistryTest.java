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
package eu.jsentinel.jcustos.logout;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import eu.jsentinel.jcustos.session.InMemorySessionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("StoreBackedSubjectSessionRegistry")
class StoreBackedSubjectSessionRegistryTest {

  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  private static final SubjectId ALICE = new SubjectId("alice");
  private static final SubjectId BOB = new SubjectId("bob");

  private static Clock fixed(Instant at) {
    return Clock.fixed(at, ZoneOffset.UTC);
  }

  @Test
  @DisplayName("register + sessionsOf round-trip")
  void registerAndList() {
    InMemorySessionStore store = new InMemorySessionStore();
    StoreBackedSubjectSessionRegistry registry =
        new StoreBackedSubjectSessionRegistry(store, TenantId.DEFAULT, fixed(T0));

    registry.register(ALICE, "sid-1");
    registry.register(ALICE, "sid-2");

    Collection<String> sessions = registry.sessionsOf(ALICE);
    assertEquals(2, sessions.size());
    assertTrue(sessions.contains("sid-1"));
    assertTrue(sessions.contains("sid-2"));
  }

  @Test
  @DisplayName("register on the same sessionId is idempotent (refreshes lastActivityAt)")
  void registerIdempotent() {
    InMemorySessionStore store = new InMemorySessionStore();
    StoreBackedSubjectSessionRegistry registry =
        new StoreBackedSubjectSessionRegistry(store, TenantId.DEFAULT, fixed(T0));

    registry.register(ALICE, "sid-1");
    registry.register(ALICE, "sid-1");

    assertEquals(1, registry.sessionsOf(ALICE).size());
  }

  @Test
  @DisplayName("unregister removes one association; foreign-subject calls are no-ops")
  void unregisterScoped() {
    InMemorySessionStore store = new InMemorySessionStore();
    StoreBackedSubjectSessionRegistry registry =
        new StoreBackedSubjectSessionRegistry(store, TenantId.DEFAULT, fixed(T0));
    registry.register(ALICE, "sid-1");
    registry.register(ALICE, "sid-2");

    registry.unregister(ALICE, "sid-1");

    Collection<String> sessions = registry.sessionsOf(ALICE);
    assertEquals(1, sessions.size());
    assertTrue(sessions.contains("sid-2"));

    // BOB unregister on alice's session id must be no-op
    registry.unregister(BOB, "sid-2");
    assertTrue(registry.sessionsOf(ALICE).contains("sid-2"));
  }

  @Test
  @DisplayName("clearAll removes every association of the subject and returns the ids")
  void clearAllReturnsRemoved() {
    InMemorySessionStore store = new InMemorySessionStore();
    StoreBackedSubjectSessionRegistry registry =
        new StoreBackedSubjectSessionRegistry(store, TenantId.DEFAULT, fixed(T0));
    registry.register(ALICE, "sid-1");
    registry.register(ALICE, "sid-2");
    registry.register(BOB, "sid-3");

    Collection<String> removed = registry.clearAll(ALICE);

    assertEquals(2, removed.size());
    assertTrue(removed.contains("sid-1"));
    assertTrue(removed.contains("sid-2"));
    assertTrue(registry.sessionsOf(ALICE).isEmpty());
    assertEquals(1, registry.sessionsOf(BOB).size());
  }

  @Test
  @DisplayName("sessionsOf only returns ACTIVE records; REVOKED/EXPIRED filtered out")
  void sessionsOfSkipsNonActive() {
    InMemorySessionStore store = new InMemorySessionStore();
    StoreBackedSubjectSessionRegistry registry =
        new StoreBackedSubjectSessionRegistry(store, TenantId.DEFAULT, fixed(T0));
    registry.register(ALICE, "sid-1");
    registry.register(ALICE, "sid-2");

    // Mark sid-1 revoked at the store level
    store.findById(new SessionId("sid-1")).ifPresent(record ->
        store.save(record.withStatus(SessionStatus.REVOKED)));

    Collection<String> active = registry.sessionsOf(ALICE);
    assertEquals(1, active.size());
    assertTrue(active.contains("sid-2"));
  }

  @Test
  @DisplayName("registry is tenant-scoped — sessions in another tenant are invisible")
  void tenantScoped() {
    InMemorySessionStore store = new InMemorySessionStore();
    TenantId acme = new TenantId("acme");
    StoreBackedSubjectSessionRegistry defaultReg =
        new StoreBackedSubjectSessionRegistry(store, TenantId.DEFAULT, fixed(T0));
    StoreBackedSubjectSessionRegistry acmeReg =
        new StoreBackedSubjectSessionRegistry(store, acme, fixed(T0));

    defaultReg.register(ALICE, "sid-default");
    acmeReg.register(ALICE, "sid-acme");

    assertEquals(1, defaultReg.sessionsOf(ALICE).size());
    assertTrue(defaultReg.sessionsOf(ALICE).contains("sid-default"));
    assertEquals(1, acmeReg.sessionsOf(ALICE).size());
    assertTrue(acmeReg.sessionsOf(ALICE).contains("sid-acme"));
  }

  @Test
  @DisplayName("with a JCustosVersionStore wired, register captures the subject's current version on a fresh session")
  void registerCapturesCurrentJCustosVersion() {
    InMemorySessionStore sessionStore = new InMemorySessionStore();
    InMemoryJCustosVersionStore versionStore = new InMemoryJCustosVersionStore();
    versionStore.increment(new JCustosVersionKey(TenantId.DEFAULT, ALICE)); // current → 1
    versionStore.increment(new JCustosVersionKey(TenantId.DEFAULT, ALICE)); // current → 2

    StoreBackedSubjectSessionRegistry registry =
        new StoreBackedSubjectSessionRegistry(sessionStore, TenantId.DEFAULT, fixed(T0), versionStore);

    registry.register(ALICE, "sid-1");

    SessionId sid = new SessionId("sid-1");
    JCustosVersion snapshot = sessionStore.findById(sid)
        .orElseThrow().securityVersionAtLogin();
    assertEquals(new JCustosVersion(2L), snapshot,
        "the registry must capture the subject's current security version at register-time");

    // A later increment must NOT mutate the snapshot — it's frozen on the SessionRecord.
    versionStore.increment(new JCustosVersionKey(TenantId.DEFAULT, ALICE)); // current → 3
    JCustosVersion snapshotAfter = sessionStore.findById(sid)
        .orElseThrow().securityVersionAtLogin();
    assertEquals(new JCustosVersion(2L), snapshotAfter);
  }

  @Test
  @DisplayName("JS-SEC-075: a reused session id bound to another subject is rebound, with the new subject's version")
  void registerRebindsForeignSubject() {
    InMemorySessionStore sessionStore = new InMemorySessionStore();
    InMemoryJCustosVersionStore versionStore = new InMemoryJCustosVersionStore();
    versionStore.increment(new JCustosVersionKey(TenantId.DEFAULT, ALICE)); // alice → 1
    versionStore.increment(new JCustosVersionKey(TenantId.DEFAULT, BOB));   // bob → 1
    versionStore.increment(new JCustosVersionKey(TenantId.DEFAULT, BOB));   // bob → 2
    StoreBackedSubjectSessionRegistry registry =
        new StoreBackedSubjectSessionRegistry(sessionStore, TenantId.DEFAULT, fixed(T0), versionStore);

    registry.register(ALICE, "sid-1");
    registry.register(BOB, "sid-1");

    assertTrue(registry.sessionsOf(BOB).contains("sid-1"), "the id now belongs to bob");
    assertTrue(registry.sessionsOf(ALICE).isEmpty(), "alice must not keep a session she no longer has");
    assertEquals(new JCustosVersion(2L),
        sessionStore.findById(new SessionId("sid-1")).orElseThrow().securityVersionAtLogin(),
        "drift detection must compare bob against bob's snapshot, not alice's");
    assertEquals(BOB, sessionStore.findById(new SessionId("sid-1")).orElseThrow().subjectId());
    assertEquals(1, registry.clearAll(ALICE).size() + 1, "clearAll(alice) must not end bob's session");
    assertTrue(registry.sessionsOf(BOB).contains("sid-1"));
  }

  @Test
  @DisplayName("JS-SEC-075: registering over an EXPIRED or REVOKED record revives the session as ACTIVE")
  void registerRevivesInactiveRecord() {
    InMemorySessionStore sessionStore = new InMemorySessionStore();
    StoreBackedSubjectSessionRegistry registry =
        new StoreBackedSubjectSessionRegistry(sessionStore, TenantId.DEFAULT, fixed(T0));
    registry.register(ALICE, "sid-1");
    SessionId sid = new SessionId("sid-1");
    sessionStore.save(sessionStore.findById(sid).orElseThrow().withStatus(SessionStatus.EXPIRED));
    assertTrue(registry.sessionsOf(ALICE).isEmpty(), "precondition: an expired record is not listed");

    registry.register(ALICE, "sid-1");

    assertTrue(registry.sessionsOf(ALICE).contains("sid-1"), "a new login over a dead id is a live session again");
    assertEquals(SessionStatus.ACTIVE, sessionStore.findById(sid).orElseThrow().status());

    sessionStore.save(sessionStore.findById(sid).orElseThrow().withStatus(SessionStatus.REVOKED));
    registry.register(ALICE, "sid-1");
    assertEquals(SessionStatus.ACTIVE, sessionStore.findById(sid).orElseThrow().status());
  }

  @Test
  @DisplayName("without a JCustosVersionStore, register falls back to INITIAL")
  void registerFallsBackToInitialWithoutVersionStore() {
    InMemorySessionStore sessionStore = new InMemorySessionStore();
    StoreBackedSubjectSessionRegistry registry =
        new StoreBackedSubjectSessionRegistry(sessionStore, TenantId.DEFAULT, fixed(T0));

    registry.register(ALICE, "sid-1");

    JCustosVersion snapshot = sessionStore.findById(new SessionId("sid-1"))
        .orElseThrow().securityVersionAtLogin();
    assertEquals(JCustosVersion.INITIAL, snapshot);
  }

  @Test
  @DisplayName("null arguments are rejected uniformly")
  void rejectNulls() {
    InMemorySessionStore store = new InMemorySessionStore();
    StoreBackedSubjectSessionRegistry registry =
        new StoreBackedSubjectSessionRegistry(store);
    assertThrows(NullPointerException.class,
        () -> registry.register(null, "sid"));
    assertThrows(IllegalArgumentException.class,
        () -> registry.register(ALICE, ""));
    assertThrows(NullPointerException.class,
        () -> registry.unregister(null, "sid"));
    assertThrows(IllegalArgumentException.class,
        () -> registry.unregister(ALICE, ""));
    assertThrows(NullPointerException.class,
        () -> registry.sessionsOf(null));
    assertThrows(NullPointerException.class,
        () -> registry.clearAll(null));
    assertThrows(NullPointerException.class,
        () -> new StoreBackedSubjectSessionRegistry(null));
  }
}
