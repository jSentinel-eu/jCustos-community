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
package eu.jsentinel.jcustos.audit;

import eu.jsentinel.jcustos.credential.InternalAuditEventType;
import eu.jsentinel.jcustos.credential.password.RehashReason;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.logout.LogoutScope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Walks every {@link AuditEvent} permits-listed variant through the
 * sealed switch in {@link LoggingAuditSink#accept(AuditEvent)} so the
 * case labels and per-variant field appenders all participate in
 * mutation coverage.
 */
@DisplayName("LoggingAuditSink — every AuditEvent variant")
class LoggingAuditSinkAllVariantsTest {

  private static final Instant T0 = Instant.parse("2026-05-11T10:00:00Z");

  @Test
  @DisplayName("LoginFailed line carries user/client/reason fields")
  void loginFailed() {
    String line = log(new LoginFailed(T0, "alice", "127.0.0.1", "bad pw"));
    assertTrue(line.contains("type=LoginFailed"));
    assertTrue(line.contains("user=alice"));
    assertTrue(line.contains("client=127.0.0.1"));
    // RF (exit-review): the space delimiter is scrubbed in every field so a value
    // cannot forge a second key=value token on the space-separated line.
    assertTrue(line.contains("reason=bad?pw"));
  }

  @Test
  @DisplayName("AccessGranted line carries subject + route")
  void accessGranted() {
    String line = log(new AccessGranted(T0, "alice", "/admin"));
    assertTrue(line.contains("type=AccessGranted"));
    assertTrue(line.contains("subject=alice"));
    assertTrue(line.contains("route=/admin"));
  }

  @Test
  @DisplayName("AccessDenied line carries subject + route + reason")
  void accessDenied() {
    String line = log(new AccessDenied(T0, "alice", "/admin", "no role"));
    assertTrue(line.contains("type=AccessDenied"));
    assertTrue(line.contains("subject=alice"));
    assertTrue(line.contains("route=/admin"));
    // RF (exit-review): space delimiter scrubbed (field-forge defense).
    assertTrue(line.contains("reason=no?role"));
  }

  @Test
  @DisplayName("ActionDenied line carries subject + action")
  void actionDenied() {
    String line = log(new ActionDenied(T0, "alice", "delete-account"));
    assertTrue(line.contains("type=ActionDenied"));
    assertTrue(line.contains("subject=alice"));
    assertTrue(line.contains("action=delete-account"));
  }

  @Test
  @DisplayName("SessionCreated line carries subject + session")
  void sessionCreated() {
    String line = log(new SessionCreated(T0, "alice", "sid-1"));
    assertTrue(line.contains("type=SessionCreated"));
    assertTrue(line.contains("subject=alice"));
    assertTrue(line.contains("sessionRef=" + LoggingAuditSink.sessionRef("sid-1")));
    assertFalse(line.contains("sid-1"), line);
  }

  @Test
  @DisplayName("SessionExpired line carries subject + session + reason")
  void sessionExpired() {
    String line = log(new SessionExpired(T0, "alice", "sid-1", "IdleTimeout"));
    assertTrue(line.contains("type=SessionExpired"));
    assertTrue(line.contains("reason=IdleTimeout"));
  }

  @Test
  @DisplayName("SessionInvalidated line carries subject + session + reason")
  void sessionInvalidated() {
    String line = log(new SessionInvalidated(T0, "alice", "sid-old", "Rotation"));
    assertTrue(line.contains("type=SessionInvalidated"));
    assertTrue(line.contains("reason=Rotation"));
  }

  @Test
  @DisplayName("SessionStale line carries subject + session + route + snapshot + current")
  void sessionStale() {
    String line = log(new SessionStale(T0, "alice", "sid-7", "/admin", 0L, 2L));
    assertTrue(line.contains("type=SessionStale"));
    assertTrue(line.contains("subject=alice"));
    assertTrue(line.contains("sessionRef=" + LoggingAuditSink.sessionRef("sid-7")));
    assertFalse(line.contains("sid-7"), line);
    assertTrue(line.contains("route=/admin"));
    assertTrue(line.contains("snapshot=0"));
    assertTrue(line.contains("current=2"));
  }

  @Test
  @DisplayName("RoleAssigned line carries subject + role + by")
  void roleAssigned() {
    String line = log(new RoleAssigned(T0, "alice", "ADMIN", "root"));
    assertTrue(line.contains("type=RoleAssigned"));
    assertTrue(line.contains("role=ADMIN"));
    assertTrue(line.contains("by=root"));
  }

  @Test
  @DisplayName("RoleRevoked line carries subject + role + by")
  void roleRevoked() {
    String line = log(new RoleRevoked(T0, "alice", "ADMIN", "root"));
    assertTrue(line.contains("type=RoleRevoked"));
    assertTrue(line.contains("role=ADMIN"));
    assertTrue(line.contains("by=root"));
  }

  @Test
  @DisplayName("UserCreated line carries username + role + by")
  void userCreated() {
    String line = log(new UserCreated(T0, "alice", "USER", "root"));
    assertTrue(line.contains("type=UserCreated"));
    assertTrue(line.contains("username=alice"));
    assertTrue(line.contains("role=USER"));
    assertTrue(line.contains("by=root"));
  }

  @Test
  @DisplayName("UserDeleted line carries username + by")
  void userDeleted() {
    String line = log(new UserDeleted(T0, "alice", "root"));
    assertTrue(line.contains("type=UserDeleted"));
    assertTrue(line.contains("username=alice"));
    assertTrue(line.contains("by=root"));
  }

  @Test
  @DisplayName("BootstrapAdminCreated line carries username + client")
  void bootstrapAdminCreated() {
    String line = log(new BootstrapAdminCreated(T0, "root", "127.0.0.1"));
    assertTrue(line.contains("type=BootstrapAdminCreated"));
    assertTrue(line.contains("username=root"));
    assertTrue(line.contains("client=127.0.0.1"));
  }

  @Test
  @DisplayName("BootstrapTokenRejected line carries reason + client")
  void bootstrapTokenRejected() {
    String line = log(new BootstrapTokenRejected(T0, "Expired", "127.0.0.1"));
    assertTrue(line.contains("type=BootstrapTokenRejected"));
    assertTrue(line.contains("reason=Expired"));
    assertTrue(line.contains("client=127.0.0.1"));
  }

  @Test
  @DisplayName("PolicyEvaluated line carries subject + policy + decision + reason")
  void policyEvaluated() {
    String line = log(new PolicyEvaluated(T0, "alice", "doc.owner", "GRANTED", "is-owner"));
    assertTrue(line.contains("type=PolicyEvaluated"));
    assertTrue(line.contains("policy=doc.owner"));
    assertTrue(line.contains("decision=GRANTED"));
    assertTrue(line.contains("reason=is-owner"));
  }

  @Test
  @DisplayName("StepUpChallenged line carries subject + route + method + reason")
  void stepUpChallenged() {
    String line = log(new StepUpChallenged(T0, "alice", "/admin", "MFA", "sensitive"));
    assertTrue(line.contains("type=StepUpChallenged"));
    assertTrue(line.contains("method=MFA"));
    assertTrue(line.contains("reason=sensitive"));
  }

  @Test
  @DisplayName("PasswordResetRequested line carries subject + tokenHash")
  void passwordResetRequested() {
    String line = log(new PasswordResetRequested(T0, "alice", "h:abc"));
    assertTrue(line.contains("type=PasswordResetRequested"));
    assertTrue(line.contains("subject=alice"));
    assertTrue(line.contains("tokenHash=h:abc"));
  }

  @Test
  @DisplayName("PasswordResetCompleted line carries subject + tokenHash")
  void passwordResetCompleted() {
    String line = log(new PasswordResetCompleted(T0, "alice", "h:abc"));
    assertTrue(line.contains("type=PasswordResetCompleted"));
    assertTrue(line.contains("tokenHash=h:abc"));
  }

  @Test
  @DisplayName("EmailVerificationRequested line carries subject + email + tokenHash")
  void emailVerificationRequested() {
    String line = log(new EmailVerificationRequested(
        T0, "alice", "alice@example.com", "h:abc"));
    assertTrue(line.contains("type=EmailVerificationRequested"));
    assertTrue(line.contains("email=alice@example.com"));
    assertTrue(line.contains("tokenHash=h:abc"));
  }

  @Test
  @DisplayName("EmailVerified line carries subject + email + tokenHash")
  void emailVerified() {
    String line = log(new EmailVerified(
        T0, "alice", "alice@example.com", "h:abc"));
    assertTrue(line.contains("type=EmailVerified"));
    assertTrue(line.contains("email=alice@example.com"));
    assertTrue(line.contains("tokenHash=h:abc"));
  }

  @Test
  @DisplayName("ApiKeyUsed line carries subject + keyName + keyHash")
  void apiKeyUsed() {
    String line = log(new ApiKeyUsed(T0, "alice", "my-key", "h:abc"));
    assertTrue(line.contains("type=ApiKeyUsed"));
    assertTrue(line.contains("keyName=my-key"));
    assertTrue(line.contains("keyHash=h:abc"));
  }

  @Test
  @DisplayName("ApiKeyDenied line carries subject + keyHash + reason")
  void apiKeyDenied() {
    String line = log(new ApiKeyDenied(T0, "alice", "h:abc", "Revoked"));
    assertTrue(line.contains("type=ApiKeyDenied"));
    assertTrue(line.contains("keyHash=h:abc"));
    assertTrue(line.contains("reason=Revoked"));
  }

  @Test
  @DisplayName("TokenRotated line carries subject + oldHash + newHash")
  void tokenRotated() {
    String line = log(new TokenRotated(T0, "alice", "h:old", "h:new"));
    assertTrue(line.contains("type=TokenRotated"));
    assertTrue(line.contains("oldHash=h:old"));
    assertTrue(line.contains("newHash=h:new"));
  }

  @Test
  @DisplayName("RateLimitExceeded line carries scope + subject + limit + window + events")
  void rateLimitExceeded() {
    String line = log(new RateLimitExceeded(
        T0, "subject:alice", "alice", 5, Duration.ofMinutes(1), 5));
    assertTrue(line.contains("type=RateLimitExceeded"));
    assertTrue(line.contains("scope=subject:alice"));
    assertTrue(line.contains("subject=alice"));
    assertTrue(line.contains("limit=5"));
    assertTrue(line.contains("windowSeconds=60"));
    assertTrue(line.contains("eventsInWindow=5"));
  }

  @Test
  @DisplayName("LogoutPerformed honours scope CurrentSession too")
  void logoutPerformedCurrentSession() {
    String line = log(new LogoutPerformed(T0, "alice", "sid", LogoutScope.CurrentSession));
    assertTrue(line.contains("scope=CurrentSession"));
  }

  // ── V00.71 credential events ────────────────────────────────────

  @Test
  @DisplayName("CredentialVerificationSucceeded line carries every field")
  void credentialVerificationSucceeded() {
    String line = log(new CredentialVerificationSucceeded(
        T0, "alice", "127.0.0.1",
        "PBKDF2WithHmacSHA256", "pbkdf2-jdk", 1,
        true, false));
    assertTrue(line.contains("type=CredentialVerificationSucceeded"));
    assertTrue(line.contains("user=alice"));
    assertTrue(line.contains("client=127.0.0.1"));
    assertTrue(line.contains("algorithm=PBKDF2WithHmacSHA256"));
    assertTrue(line.contains("provider=pbkdf2-jdk"));
    assertTrue(line.contains("policyVersion=1"));
    assertTrue(line.contains("pepper=true"));
    assertTrue(line.contains("rehashRequired=false"));
  }

  @Test
  @DisplayName("CredentialVerificationSucceeded — different bool combinations preserved")
  void credentialVerificationSucceededFlagFlipped() {
    String line = log(new CredentialVerificationSucceeded(
        T0, "alice", "10.0.0.1",
        "Argon2id", "argon2id-bc", 2,
        false, true));
    assertTrue(line.contains("pepper=false"));
    assertTrue(line.contains("rehashRequired=true"));
    assertTrue(line.contains("policyVersion=2"));
  }

  @Test
  @DisplayName("CredentialVerificationFailed line carries user + client + internalReason")
  void credentialVerificationFailed() {
    String line = log(new CredentialVerificationFailed(
        T0, "alice", "127.0.0.1",
        InternalAuditEventType.VERIFICATION_FAILED_MISMATCH));
    assertTrue(line.contains("type=CredentialVerificationFailed"));
    assertTrue(line.contains("user=alice"));
    assertTrue(line.contains("client=127.0.0.1"));
    assertTrue(line.contains("internalReason=VERIFICATION_FAILED_MISMATCH"));
  }

  @Test
  @DisplayName("CredentialRehashed line carries user + from/to + reason + policyVersion")
  void credentialRehashed() {
    String line = log(new CredentialRehashed(
        T0, "alice",
        "PBKDF2WithHmacSHA256", "Argon2id",
        RehashReason.ALGORITHM_DEPRECATED, 2));
    assertTrue(line.contains("type=CredentialRehashed"));
    assertTrue(line.contains("user=alice"));
    assertTrue(line.contains("from=PBKDF2WithHmacSHA256"));
    assertTrue(line.contains("to=Argon2id"));
    assertTrue(line.contains("reason=ALGORITHM_DEPRECATED"));
    assertTrue(line.contains("targetPolicyVersion=2"));
  }

  @Test
  @DisplayName("CredentialStatusChanged line carries user + from/to status + reason")
  void credentialStatusChanged() {
    String line = log(new CredentialStatusChanged(
        T0, "alice",
        CredentialStatus.ACTIVE, CredentialStatus.MUST_CHANGE,
        "INC-2026-06-pepper/PEPPER_COMPROMISE"));
    assertTrue(line.contains("type=CredentialStatusChanged"));
    assertTrue(line.contains("user=alice"));
    assertTrue(line.contains("from=ACTIVE"));
    assertTrue(line.contains("to=MUST_CHANGE"));
    assertTrue(line.contains("reason=INC-2026-06-pepper/PEPPER_COMPROMISE"));
  }

  /** Drive one event through a recording SLF4J logger and return its single line. */
  private static String log(AuditEvent event) {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingAuditSink(logger).accept(event);
    return logger.firstMessage();
  }
}
