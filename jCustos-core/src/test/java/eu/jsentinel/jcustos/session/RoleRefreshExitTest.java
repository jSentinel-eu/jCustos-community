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
package eu.jsentinel.jcustos.session;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.audit.SessionStale;
import eu.jsentinel.jcustos.authorization.api.roles.InMemoryRoleAssignmentStore;
import eu.jsentinel.jcustos.authorization.api.roles.RoleAssignmentKey;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.api.roles.StoreBackedRoleAuthorizationService;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.StoreBackedSubjectSessionRegistry;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer.EnforcementOutcome;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 4c-5 exit-criterion test — the Phase 4 promise from
 * {@code Implementierungsplan-V00.70.00.md}:
 * <p>
 * "Role-Refresh-Demo: Admin entzieht Rolle → naechster Request der
 * laufenden Session liefert 401/Reroute."
 * <p>
 * End-to-end against the real stores and services (no mocks):
 * <ol>
 *   <li>Alice logs in with role ADMIN. The session registry
 *       captures her {@link JCustosVersion} (still INITIAL).</li>
 *   <li>An admin revokes ADMIN — represented by removing the
 *       role assignment from the store and bumping
 *       {@link JCustosVersionStore#increment} for alice.</li>
 *   <li>Alice's next request runs through
 *       {@link JCustosVersionEnforcer}; the enforcer sees that the
 *       session's snapshot is behind the current version and
 *       returns {@link EnforcementOutcome.SessionStale} plus a
 *       {@link SessionStale} audit event.</li>
 *   <li>Re-issuing a session after the role change captures the
 *       <em>new</em> snapshot, and subsequent requests pass
 *       through ({@link EnforcementOutcome.CONTINUE}).</li>
 * </ol>
 */
@DisplayName("Phase 4c exit — role refresh forces drift, next request is stale")
class RoleRefreshExitTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final RoleName ADMIN = new RoleName("ADMIN");
  private static final RoleAssignmentKey ALICE_ROLES =
      new RoleAssignmentKey(TenantId.DEFAULT, ALICE);
  private static final JCustosVersionKey ALICE_VERSION_KEY =
      new JCustosVersionKey(TenantId.DEFAULT, ALICE);
  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

  @Test
  @DisplayName("admin revokes role + bumps version → next request reports SessionStale; re-login is current again")
  void roleRevocationDriftsNextRequest() {
    // ── Wiring ─────────────────────────────────────────────────────
    InMemoryJCustosVersionStore versionStore = new InMemoryJCustosVersionStore();
    InMemoryRoleAssignmentStore roleStore = new InMemoryRoleAssignmentStore();
    InMemorySessionStore sessionStore = new InMemorySessionStore();
    Clock clock = Clock.fixed(T0, ZoneOffset.UTC);

    StoreBackedSubjectSessionRegistry registry = new StoreBackedSubjectSessionRegistry(
        sessionStore, TenantId.DEFAULT, clock, versionStore);

    CollectingAuditService audit = new CollectingAuditService();
    JCustosVersionEnforcer enforcer = new JCustosVersionEnforcer(
        new JCustosVersionCheck(versionStore), audit, clock);

    StoreBackedRoleAuthorizationService<SubjectId> authz =
        new StoreBackedRoleAuthorizationService<>(roleStore, id -> id);

    // ── 1. Alice logs in as ADMIN ──────────────────────────────────
    roleStore.assignRole(ALICE_ROLES, ADMIN);
    registry.register(ALICE, "sid-alice");

    SessionRecord aliceSession = sessionStore.findById(new SessionId("sid-alice")).orElseThrow();
    assertEquals(JCustosVersion.INITIAL, aliceSession.securityVersionAtLogin(),
        "fresh subject has version INITIAL captured on the session");
    assertTrue(authorisedRoles(authz, ALICE).contains(ADMIN));

    // First request through the enforcer — versions match, request proceeds.
    EnforcementOutcome firstRequest = enforcer.enforce(
        ALICE, TenantId.DEFAULT, aliceSession.securityVersionAtLogin(),
        aliceSession.sessionId().value(), "/admin/dashboard");
    assertSame(EnforcementOutcome.CONTINUE, firstRequest);
    assertTrue(audit.published.isEmpty());

    // ── 2. Admin revokes ADMIN + bumps the security version ───────
    roleStore.revokeRole(ALICE_ROLES, ADMIN);
    versionStore.increment(ALICE_VERSION_KEY); // current → 1
    assertTrue(authorisedRoles(authz, ALICE).isEmpty(),
        "role revocation is visible immediately via the authorization service");

    // ── 3. Alice's next request — the session is now stale ────────
    EnforcementOutcome secondRequest = enforcer.enforce(
        ALICE, TenantId.DEFAULT, aliceSession.securityVersionAtLogin(),
        aliceSession.sessionId().value(), "/admin/dashboard");

    EnforcementOutcome.SessionStale stale =
        assertInstanceOf(EnforcementOutcome.SessionStale.class, secondRequest);
    assertEquals(JCustosVersion.INITIAL, stale.status().snapshot());
    assertEquals(new JCustosVersion(1L), stale.status().current());

    // SessionStale audit event was published with both values
    assertEquals(1, audit.published.size());
    SessionStale staleEvent = (SessionStale) audit.published.get(0);
    assertEquals("alice", staleEvent.subjectId());
    assertEquals(SessionRef.of("sid-alice"), staleEvent.sessionId(), "JS-SEC-117: the reference, never the id");
    assertEquals("/admin/dashboard", staleEvent.route());
    assertEquals(0L, staleEvent.snapshotVersion());
    assertEquals(1L, staleEvent.currentVersion());

    // ── 4. Alice re-authenticates — fresh snapshot is current ─────
    registry.register(ALICE, "sid-alice-2");
    SessionRecord refreshedSession =
        sessionStore.findById(new SessionId("sid-alice-2")).orElseThrow();
    assertEquals(new JCustosVersion(1L), refreshedSession.securityVersionAtLogin(),
        "fresh login captures the bumped current version");

    EnforcementOutcome afterReLogin = enforcer.enforce(
        ALICE, TenantId.DEFAULT, refreshedSession.securityVersionAtLogin(),
        refreshedSession.sessionId().value(), "/admin/dashboard");
    assertSame(EnforcementOutcome.CONTINUE, afterReLogin);
    assertEquals(1, audit.published.size(),
        "no new SessionStale audit after re-login");
  }

  private static Set<RoleName> authorisedRoles(
      StoreBackedRoleAuthorizationService<SubjectId> authz, SubjectId subject) {
    return new HashSet<>(authz.rolesFor(subject).roleNames());
  }

  private static final class CollectingAuditService implements JCustosAuditService {
    final List<AuditEvent> published = new ArrayList<>();
    @Override public void publish(AuditEvent event) { published.add(event); }
    @Override public List<AuditEvent> query(AuditQuery query) { return List.copyOf(published); }
  }
}
