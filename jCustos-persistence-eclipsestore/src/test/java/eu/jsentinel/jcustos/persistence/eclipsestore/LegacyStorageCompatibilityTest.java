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
package eu.jsentinel.jcustos.persistence.eclipsestore;

import eu.jsentinel.jcustos.accountlifecycle.EmailVerificationTokenRecord;
import eu.jsentinel.jcustos.accountlifecycle.PasswordResetTokenRecord;
import eu.jsentinel.jcustos.accountlifecycle.PasswordResetTokenStore;
import eu.jsentinel.jcustos.audit.AuditEnvelope;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.authentication.ApiKeyRecord;
import eu.jsentinel.jcustos.authentication.RefreshTokenRecord;
import eu.jsentinel.jcustos.authentication.RefreshTokenStore;
import eu.jsentinel.jcustos.authentication.RememberMeTokenRecord;
import eu.jsentinel.jcustos.authentication.RememberMeTokenStore;
import eu.jsentinel.jcustos.authorization.api.roles.RoleAssignmentKey;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bootstrap.BootstrapState;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptConfiguration;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptKey;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore;
import eu.jsentinel.jcustos.bruteforce.StoreBackedLoginAttemptPolicy;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.ratelimiting.RateLimitKey;
import eu.jsentinel.jcustos.ratelimiting.RateLimitStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.SessionStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-125 changed how the security store is laid out on disk. These tests open storage
 * directories that <em>earlier code</em> wrote - the released 00.83.00 artefacts, and 00.84.00
 * before the change - and hold the current code to it: the storage opens, every record is there,
 * in its order, and the stores work on it, also across a further restart.
 *
 * <p>The directories are test resources; what they contain is written down in
 * {@code LegacyStorageFixtureWriter.java.txt} next to them, and the expectations below mirror
 * that source line by line.</p>
 */
@DisplayName("a storage written before JS-SEC-125 opens, keeps its data and works")
class LegacyStorageCompatibilityTest {

  private static final Instant T0 = LegacyStorageFixtures.T0;
  private static final TenantId ACME = new TenantId("acme");
  private static final SubjectId ALICE = new SubjectId("alice");
  private static final SubjectId BOB = new SubjectId("bob");
  private static final LoginAttemptKey VICTIM =
      new LoginAttemptKey(TenantId.DEFAULT, "victim", "198.51.100.7");
  private static final RateLimitKey CLIENT = new RateLimitKey(TenantId.DEFAULT, "ip:203.0.113.5");

  @TempDir
  Path tempDir;

  @ParameterizedTest(name = "{0}")
  @ValueSource(strings = {LegacyStorageFixtures.WRITTEN_BY_00_83_00,
      LegacyStorageFixtures.WRITTEN_BY_00_84_00_BEFORE_JS_SEC_125})
  @DisplayName("every record of every store is read back, in the order it was written")
  void everyRecordIsReadBack(String fixture) throws Exception {
    LegacyStorageFixtures.copyTo(fixture, tempDir);
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      assertNotNull(storage.root().tables, "the root was moved to the layout of 00.84.00");
      assertEverythingTheWriterWrote(storage, fixture);
      assertEarlierLayoutIsEmpty(storage);
    }
    // the migration is on disk: a second open finds the new layout and the same data
    try (EclipseStoreJCustosStorage reopened = EclipseStoreJCustosStorage.openAt(tempDir)) {
      assertEverythingTheWriterWrote(reopened, fixture);
      assertEarlierLayoutIsEmpty(reopened);
    }
  }

  @ParameterizedTest(name = "{0}")
  @ValueSource(strings = {LegacyStorageFixtures.WRITTEN_BY_00_83_00,
      LegacyStorageFixtures.WRITTEN_BY_00_84_00_BEFORE_JS_SEC_125})
  @DisplayName("the stores work on the migrated data, and what they change survives a restart")
  void theStoresWorkOnTheMigratedData(String fixture) throws Exception {
    LegacyStorageFixtures.copyTo(fixture, tempDir);
    Instant later = T0.plusSeconds(200);
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      // the lockout the victim earned under the old layout is still in force
      StoreBackedLoginAttemptPolicy policy = new StoreBackedLoginAttemptPolicy(
          storage.loginAttemptStore(), LoginAttemptConfiguration.defaults(), TenantId.DEFAULT,
          Clock.fixed(later, ZoneOffset.UTC));
      assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.beforeAttempt(
          new LoginAttemptContext("victim", "198.51.100.7", null, later)));

      // the migrated rate-limit events count; the bucket is a multiset from now on (JS-SEC-118)
      RateLimitStore rateLimit = storage.rateLimitStore();
      assertFalse(rateLimit.tryAdmit(CLIENT, T0.plusSeconds(3), T0.minusSeconds(60), 3).admitted(),
          "three events were recorded under the old layout");
      assertTrue(rateLimit.tryAdmit(CLIENT, T0.plusSeconds(3), T0.minusSeconds(60), 5).admitted());
      assertTrue(rateLimit.tryAdmit(CLIENT, T0.plusSeconds(3), T0.minusSeconds(60), 5).admitted());
      assertEquals(5, rateLimit.countSince(CLIENT, T0));

      // a remember-me token issued before the upgrade rotates and leaves its trail (JS-SEC-128)
      RememberMeTokenStore rememberMe = storage.rememberMeTokenStore();
      assertTrue(rememberMe.markRotated("rm-hash-alice", later));

      // sessions: an update, a new session, a removal
      SessionStore sessions = storage.sessionStore();
      SessionRecord alice = sessions.findById(new SessionId("session-alice-1")).orElseThrow();
      sessions.save(alice.withLastActivityAt(later));
      sessions.save(new SessionRecord(new SessionId("session-new"), BOB, TenantId.DEFAULT,
          later, later, JCustosVersion.INITIAL, SessionStatus.ACTIVE));
      assertTrue(sessions.delete(new SessionId("session-bob-1")));

      storage.roleAssignmentStore().assignRole(
          new RoleAssignmentKey(TenantId.DEFAULT, ALICE), new RoleName("OPERATOR"));
      storage.securityVersionStore().increment(new JCustosVersionKey(TenantId.DEFAULT, ALICE));
      storage.auditEventStore().append(TenantId.DEFAULT,
          new LoginFailed(later, "user-new", "192.0.2.99", "bad-credentials"));
      assertTrue(storage.passwordResetTokenStore().markConsumed("pr-hash-open", later));
      assertTrue(storage.apiKeyStore().markUsed("ak-hash-1", later));
    }

    try (EclipseStoreJCustosStorage reopened = EclipseStoreJCustosStorage.openAt(tempDir)) {
      assertEquals(5, reopened.loginAttemptStore().failureCount(VICTIM));
      assertEquals(5, reopened.rateLimitStore().countSince(CLIENT, T0));
      assertEquals(later,
          reopened.rememberMeTokenStore().findRotated("rm-hash-alice").orElseThrow().rotatedAt());
      assertTrue(reopened.rememberMeTokenStore().findByHash("rm-hash-alice").isEmpty());

      List<SessionRecord> sessions = reopened.sessionStore().findAll();
      assertEquals(List.of("session-alice-1", "session-alice-2", "session-new"),
          sessions.stream().map(record -> record.sessionId().value()).toList(),
          "an updated record keeps its place, a new one goes to the end");
      assertEquals(later, sessions.get(0).lastActivityAt());

      assertEquals(Set.of(new RoleName("ADMIN"), new RoleName("AUDITOR"), new RoleName("OPERATOR")),
          reopened.roleAssignmentStore().findRoles(new RoleAssignmentKey(TenantId.DEFAULT, ALICE)));
      assertEquals(new JCustosVersion(3),
          reopened.securityVersionStore().current(new JCustosVersionKey(TenantId.DEFAULT, ALICE)));
      List<AuditEnvelope> audit = reopened.auditEventStore().query(TenantId.DEFAULT, AuditQuery.all());
      assertEquals(5, audit.size());
      assertEquals("user-new", ((LoginFailed) audit.get(4).event()).username());
      assertTrue(reopened.passwordResetTokenStore().findByHash("pr-hash-open")
          .orElseThrow().isConsumed());
      assertEquals(Optional.of(later),
          reopened.apiKeyStore().findByHash("ak-hash-1").orElseThrow().lastUsedAt());
    }
  }

  private static void assertEverythingTheWriterWrote(EclipseStoreJCustosStorage storage,
                                                     String fixture) {
    // audit: five events, the fourth under tenant acme, in append order
    List<AuditEnvelope> defaultAudit = storage.auditEventStore().query(TenantId.DEFAULT, AuditQuery.all());
    assertEquals(List.of("user-0", "user-1", "user-2", "user-4"),
        defaultAudit.stream().map(envelope -> ((LoginFailed) envelope.event()).username()).toList());
    assertEquals(T0.plusSeconds(2), defaultAudit.get(2).event().timestamp());
    List<AuditEnvelope> acmeAudit = storage.auditEventStore().query(ACME, AuditQuery.all());
    assertEquals(1, acmeAudit.size());
    assertEquals("192.0.2.3", ((LoginFailed) acmeAudit.get(0).event()).clientAddress());

    // sessions, in insertion order
    SessionStore sessions = storage.sessionStore();
    assertEquals(List.of("session-alice-1", "session-bob-1", "session-alice-2"),
        sessions.findAll().stream().map(record -> record.sessionId().value()).toList());
    assertEquals(new SessionRecord(new SessionId("session-alice-1"), ALICE, TenantId.DEFAULT,
            T0, T0.plusSeconds(60), new JCustosVersion(2), SessionStatus.ACTIVE),
        sessions.findById(new SessionId("session-alice-1")).orElseThrow());
    assertEquals(SessionStatus.REVOKED,
        sessions.findById(new SessionId("session-alice-2")).orElseThrow().status());
    assertEquals(2, sessions.findBySubject(TenantId.DEFAULT, ALICE).size());
    assertEquals(1, sessions.findBySubject(ACME, BOB).size());

    // login attempts
    LoginAttemptStore attempts = storage.loginAttemptStore();
    assertEquals(5, attempts.failureCount(VICTIM));
    assertEquals(Optional.of(T0.plusSeconds(104)), attempts.lastFailureAt(VICTIM));
    assertEquals(1, attempts.failureCount(new LoginAttemptKey(ACME, "bystander", "198.51.100.8")));

    // role assignments
    assertEquals(Set.of(new RoleName("ADMIN"), new RoleName("AUDITOR")),
        storage.roleAssignmentStore().findRoles(new RoleAssignmentKey(TenantId.DEFAULT, ALICE)));
    assertEquals(Set.of(new RoleName("USER")),
        storage.roleAssignmentStore().findRoles(new RoleAssignmentKey(ACME, BOB)));

    // bootstrap states
    assertEquals(Optional.of(BootstrapState.completed(TenantId.DEFAULT, T0)),
        storage.bootstrapStateStore().find(TenantId.DEFAULT));
    assertEquals(Optional.of(BootstrapState.required(ACME)), storage.bootstrapStateStore().find(ACME));

    // remember-me tokens; no trail existed before 00.84.00
    assertEquals(Optional.of(new RememberMeTokenRecord("rm-hash-alice", TenantId.DEFAULT, ALICE,
            T0, T0.plusSeconds(86_400))),
        storage.rememberMeTokenStore().findByHash("rm-hash-alice"));
    assertTrue(storage.rememberMeTokenStore().findByHash("rm-hash-bob").isPresent());
    assertTrue(storage.rememberMeTokenStore().findRotated("rm-hash-alice").isEmpty());

    // password-reset tokens: one open, one consumed
    PasswordResetTokenStore reset = storage.passwordResetTokenStore();
    assertEquals(Optional.of(new PasswordResetTokenRecord("pr-hash-open", TenantId.DEFAULT, ALICE,
        T0, T0.plusSeconds(900), Optional.empty())), reset.findByHash("pr-hash-open"));
    assertEquals(Optional.of(T0.plusSeconds(30)),
        reset.findByHash("pr-hash-used").orElseThrow().consumedAt());

    // email-verification token
    assertEquals(Optional.of(new EmailVerificationTokenRecord("ev-hash-open", TenantId.DEFAULT,
            ALICE, "alice@example.org", T0, T0.plusSeconds(86_400), Optional.empty())),
        storage.emailVerificationTokenStore().findByHash("ev-hash-open"));

    // api keys, in insertion order; the second one revoked
    List<ApiKeyRecord> keys = storage.apiKeyStore().listBySubject(TenantId.DEFAULT, ALICE);
    assertEquals(List.of("ak-hash-1", "ak-hash-2"), keys.stream().map(ApiKeyRecord::keyHash).toList());
    assertEquals("ci", keys.get(0).name());
    assertEquals(Optional.of(T0.plusSeconds(40)), keys.get(1).revokedAt());

    // refresh tokens
    RefreshTokenStore refresh = storage.refreshTokenStore();
    assertEquals(Optional.of("rt-hash-2"),
        refresh.findByHash("rt-hash-1").orElseThrow().replacedByHash());
    assertTrue(refresh.findByHash("rt-hash-2").orElseThrow().isActive(T0.plusSeconds(120)));
    RefreshTokenRecord older = new RefreshTokenRecord("older", ACME, BOB, T0.plusSeconds(79),
        T0.plusSeconds(86_400), Optional.empty(), Optional.empty());
    if (LegacyStorageFixtures.WRITTEN_BY_00_84_00_BEFORE_JS_SEC_125.equals(fixture)) {
      // written with a subject-wide revocation: bob's token is gone and the mark was migrated
      assertTrue(refresh.findByHash("rt-hash-bob").isEmpty());
      assertEquals(T0.plusSeconds(80), storage.tables().refreshTokenInvalidBefore
          .get(new EclipseStoreJCustosRoot.RefreshTokenScope("acme", "bob")));
      assertFalse(refresh.saveUnlessInvalidated(older),
          "the mark written before the layout change still refuses an overtaken token");
    } else {
      assertEquals(Optional.of(T0.plusSeconds(70)),
          refresh.findByHash("rt-hash-bob").orElseThrow().revokedAt());
      assertEquals(0, storage.tables().refreshTokenInvalidBefore.size(),
          "00.83.00 had no marks");
    }

    // rate-limit events
    RateLimitStore rateLimit = storage.rateLimitStore();
    assertEquals(3, rateLimit.countSince(CLIENT, T0));
    assertEquals(2, rateLimit.countSince(CLIENT, T0.plusSeconds(1)));
    assertEquals(1, rateLimit.countSince(new RateLimitKey(ACME, "subject:bob"), T0));

    // security versions
    assertEquals(new JCustosVersion(2),
        storage.securityVersionStore().current(new JCustosVersionKey(TenantId.DEFAULT, ALICE)));
    assertEquals(new JCustosVersion(1),
        storage.securityVersionStore().current(new JCustosVersionKey(ACME, BOB)));
  }

  /** After the move nothing is left in the maps of the earlier layout - one copy of the data. */
  private static void assertEarlierLayoutIsEmpty(EclipseStoreJCustosStorage storage) {
    EclipseStoreJCustosRoot root = storage.root();
    assertTrue(root.auditEnvelopes.isEmpty());
    assertTrue(root.sessions.isEmpty());
    assertTrue(root.loginAttempts.isEmpty());
    assertTrue(root.roleAssignments.isEmpty());
    assertTrue(root.bootstrapStates.isEmpty());
    assertTrue(root.rememberMeTokens.isEmpty());
    assertTrue(root.passwordResetTokens.isEmpty());
    assertTrue(root.emailVerificationTokens.isEmpty());
    assertTrue(root.apiKeys.isEmpty());
    assertTrue(root.refreshTokens.isEmpty());
    assertTrue(root.refreshTokenInvalidBefore == null || root.refreshTokenInvalidBefore.isEmpty());
    assertTrue(root.rateLimitEvents.isEmpty());
    assertTrue(root.securityVersions.isEmpty());
  }
}
