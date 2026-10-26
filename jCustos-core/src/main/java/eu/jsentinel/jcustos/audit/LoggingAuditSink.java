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

import com.svenruppert.dependencies.core.logger.HasLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/**
 * {@link AuditSink} that writes a single {@link Logger SLF4J Logger} line per
 * event at {@code INFO} level. Never throws.
 * <p>
 * The line format is intentionally compact and stable so it can be
 * grepped from a deployment log: {@code AUDIT type=… field=value …}.
 * <p>
 * R037: the audit stream is a named SLF4J logger
 * ({@code eu.jsentinel.jcustos.audit}) — the {@code HasLogger} Shape-4
 * "audit/metrics stream" pattern — so operators can route it to its own
 * appender. The {@code (Logger)} constructor remains a test/injection seam.
 */
public final class LoggingAuditSink implements AuditSink {

  /** Audit stream name; route this to a dedicated appender in logback/simplelogger. */
  public static final String AUDIT_LOGGER_NAME = "eu.jsentinel.jcustos.audit";

  private static final Logger DEFAULT_LOGGER = LoggerFactory.getLogger(AUDIT_LOGGER_NAME);

  private final Logger logger;

  public LoggingAuditSink() {
    this(DEFAULT_LOGGER);
  }

  public LoggingAuditSink(Logger logger) {
    this.logger = Objects.requireNonNull(logger, "logger");
  }

  @Override
  public void accept(AuditEvent event) {
    if (event == null) return;
    try {
      logger.info(format(event));
    } catch (RuntimeException ex) {
      // R036: sinks must never throw, but a failing audit sink is a
      // security-relevant blind spot — log the swallowed failure at WARN via a
      // separate framework logger (the event's audit logger just failed). No
      // secrets in the message: only the event type.
      HasLogger.staticLogger().warn(
          "audit/sink-failure: dropped a {} audit line because the audit logger threw",
          event.getClass().getSimpleName(), ex);
    }
  }

  private static String format(AuditEvent event) {
    StringBuilder sb = new StringBuilder("AUDIT ");
    sb.append("type=").append(event.getClass().getSimpleName());
    switch (event) {
      case LoginSucceeded e -> appendLogin(sb, e.username(), e.clientAddress(), e.sessionId());
      case LoginFailed e -> {
        appendLogin(sb, e.username(), e.clientAddress(), null);
        appendField(sb, "reason", e.reason());
      }
      case LogoutPerformed e -> {
        appendField(sb, "subject", e.subjectId());
        appendSessionRef(sb, e.sessionId());
        appendField(sb, "scope", e.scope().name());
      }
      case AccessGranted e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "route", e.route());
      }
      case AccessDenied e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "route", e.route());
        appendField(sb, "reason", e.reason());
      }
      case ActionDenied e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "action", e.action());
      }
      case BruteForceLimitReached e -> {
        appendLogin(sb, e.username(), e.clientAddress(), null);
        appendField(sb, "failedAttempts", String.valueOf(e.failedAttempts()));
        appendField(sb, "lockoutSeconds",
            String.valueOf(e.lockoutDuration().toSeconds()));
      }
      case SessionCreated e -> {
        appendField(sb, "subject", e.subjectId());
        appendSessionRef(sb, e.sessionId());
      }
      case SessionExpired e -> {
        appendField(sb, "subject", e.subjectId());
        appendSessionRef(sb, e.sessionId());
        appendField(sb, "reason", e.reason());
      }
      case SessionInvalidated e -> {
        appendField(sb, "subject", e.subjectId());
        appendSessionRef(sb, e.sessionId());
        appendField(sb, "reason", e.reason());
      }
      case RoleAssigned e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "role", e.role());
        appendField(sb, "by", e.assignedBy());
      }
      case RoleRevoked e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "role", e.role());
        appendField(sb, "by", e.revokedBy());
      }
      case BootstrapAdminCreated e -> {
        appendField(sb, "username", e.username());
        appendField(sb, "client", e.clientAddress());
      }
      case BootstrapTokenRejected e -> {
        appendField(sb, "reason", e.reason());
        appendField(sb, "client", e.clientAddress());
      }
      case UserCreated e -> {
        appendField(sb, "username", e.username());
        appendField(sb, "role", e.role());
        appendField(sb, "by", e.createdBy());
      }
      case UserDeleted e -> {
        appendField(sb, "username", e.username());
        appendField(sb, "by", e.deletedBy());
      }
      case PolicyEvaluated e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "policy", e.policyName());
        appendField(sb, "decision", e.decision());
        appendField(sb, "reason", e.reason());
      }
      case StepUpChallenged e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "route", e.route());
        appendField(sb, "method", e.method());
        appendField(sb, "reason", e.reason());
      }
      case SessionStale e -> {
        appendField(sb, "subject", e.subjectId());
        appendSessionRef(sb, e.sessionId());
        appendField(sb, "route", e.route());
        appendField(sb, "snapshot", String.valueOf(e.snapshotVersion()));
        appendField(sb, "current", String.valueOf(e.currentVersion()));
      }
      case PasswordResetRequested e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "tokenHash", e.tokenHash());
      }
      case PasswordResetCompleted e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "tokenHash", e.tokenHash());
      }
      case EmailVerificationRequested e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "email", e.email());
        appendField(sb, "tokenHash", e.tokenHash());
      }
      case EmailVerified e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "email", e.email());
        appendField(sb, "tokenHash", e.tokenHash());
      }
      case ApiKeyUsed e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "keyName", e.keyName());
        appendField(sb, "keyHash", e.keyHash());
      }
      case ApiKeyDenied e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "keyHash", e.keyHash());
        appendField(sb, "reason", e.reason());
      }
      case TokenRotated e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "oldHash", e.oldHash());
        appendField(sb, "newHash", e.newHash());
      }
      case RateLimitExceeded e -> {
        appendField(sb, "scope", e.scope());
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "limit", String.valueOf(e.limit()));
        appendField(sb, "windowSeconds", String.valueOf(e.window().toSeconds()));
        appendField(sb, "eventsInWindow", String.valueOf(e.eventsInWindow()));
      }
      case CredentialVerificationSucceeded e -> {
        appendField(sb, "user", e.username());
        appendField(sb, "client", e.clientAddress());
        appendField(sb, "algorithm", e.algorithm());
        appendField(sb, "provider", e.providerId());
        appendField(sb, "policyVersion", String.valueOf(e.policyVersion()));
        appendField(sb, "pepper", String.valueOf(e.pepperKeyIdPresent()));
        appendField(sb, "rehashRequired", String.valueOf(e.rehashRequired()));
      }
      case CredentialVerificationFailed e -> {
        appendField(sb, "user", e.username());
        appendField(sb, "client", e.clientAddress());
        appendField(sb, "internalReason", e.internalAuditEventType().name());
      }
      case CredentialRehashed e -> {
        appendField(sb, "user", e.username());
        appendField(sb, "from", e.fromAlgorithm());
        appendField(sb, "to", e.toAlgorithm());
        appendField(sb, "reason", e.reason().name());
        appendField(sb, "targetPolicyVersion",
            String.valueOf(e.targetPolicyVersion()));
      }
      case CredentialStatusChanged e -> {
        appendField(sb, "user", e.username());
        appendField(sb, "from", e.fromStatus().name());
        appendField(sb, "to", e.toStatus().name());
        appendField(sb, "reason", e.reason());
      }
    }
    return sb.toString();
  }

  private static void appendLogin(
      StringBuilder sb, String username, String clientAddress, String sessionId) {
    appendField(sb, "user", username);
    appendField(sb, "client", clientAddress);
    appendSessionRef(sb, sessionId);
  }

  /**
   * JS-SEC-079 (CWE-532): the session id in these events is the live servlet
   * session cookie value. Written as-is, anyone who reads the audit log — log
   * shipping, SIEM, support — can take over a running session. The line
   * therefore carries {@code sessionRef=}, the first 16 hex characters of the
   * SHA-256 of the id: stable for correlation across events, useless for
   * hijacking. Tokens and API keys already follow the same hash convention.
   */
  private static void appendSessionRef(StringBuilder sb, String sessionId) {
    if (sessionId == null) return;
    appendField(sb, "sessionRef", sessionRef(sessionId));
  }

  /**
   * Correlation reference for a session id: 16 hex characters of its SHA-256.
   *
   * @param sessionId the raw session id; non-null
   * @return the reference, never the id itself
   * @since 00.84.00
   */
  public static String sessionRef(String sessionId) {
    Objects.requireNonNull(sessionId, "sessionId");
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256")
          .digest(sessionId.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest, 0, 8);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  private static void appendField(StringBuilder sb, String key, String value) {
    if (value == null) return;
    sb.append(' ').append(key).append('=').append(scrub(value));
  }

  /**
   * JS-SEC-031 (CWE-117): replace CR / LF / other ISO control chars in a logged
   * value so an attacker-influenced field (e.g. a request-path-derived route)
   * cannot forge a second log line.
   *
   * <p>RF (exit-review, same-line field spoofing): the audit line is a
   * space-separated sequence of {@code key=value} tokens, so a value that contains
   * a raw space can forge a <em>second field</em> on the same line even with no
   * control char — a username like {@code "alice user=admin"} (spaces only, passing
   * the control-char filter unchanged) would make a whitespace-splitting SIEM parser
   * attribute the event to {@code admin}. The space (0x20) — the field delimiter — is
   * therefore neutralized alongside control chars; identifiers carried in audit fields
   * (user / client / session / route) have no semantic need for embedded spaces, and a
   * space in one is itself suspicious. Applied to every field this sink emits; only
   * allocates when a disallowed char is actually present.
   */
  static String scrub(String value) {
    // JS-SEC-045: delegate to the single shared LogFieldScrubber so this sink and
    // LoggingNotificationSender / RestAccessContextFactory cannot drift.
    return LogFieldScrubber.scrub(value);
  }
}
