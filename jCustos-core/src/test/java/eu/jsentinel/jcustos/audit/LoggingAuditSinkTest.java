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

import eu.jsentinel.jcustos.logout.LogoutScope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("LoggingAuditSink")
class LoggingAuditSinkTest {

  private static final Instant T0 = Instant.parse("2026-05-11T10:00:00Z");

  @Test
  @DisplayName("JS-SEC-031: CR/LF in a logged field is scrubbed so it cannot forge a second log line")
  void scrubsCrlfInLoggedField() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingAuditSink(logger).accept(
        new LoginSucceeded(T0, "alice\r\nfake=INJECTED", "127.0.0.1", "S-1"));

    String line = logger.firstMessage();
    assertFalse(line.contains("\n"), "log line must not contain a newline: " + line);
    assertFalse(line.contains("\r"), "log line must not contain a CR: " + line);
    assertTrue(line.contains("user=alice??fake=INJECTED"), line);
  }

  @Test
  @DisplayName("RF (exit-review): a space in a logged field cannot forge a second key=value token")
  void scrubsSpaceFieldForging() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    // username carries no control char at all — only spaces — attempting to forge
    // an attributable user=admin field on the space-separated audit line.
    new LoggingAuditSink(logger).accept(
        new LoginSucceeded(T0, "alice user=admin client=10.0.0.1", "127.0.0.1", "S-1"));

    String line = logger.firstMessage();
    // the real user field stays attacker-bounded — the injected " user=admin" cannot
    // appear as a standalone token, because every space in the value became '?'.
    assertFalse(line.contains("user=alice user=admin"), line);
    assertTrue(line.contains("user=alice?user=admin?client=10.0.0.1"), line);
  }

  @Test
  @DisplayName("JS-SEC-079: the live session id never reaches the line; sessionRef is deterministic (CWE-532)")
  void sessionIdIsReplacedByStableReference() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    LoggingAuditSink sink = new LoggingAuditSink(logger);
    sink.accept(new SessionCreated(T0, "alice", "ABCDEF0123456789"));
    sink.accept(new SessionInvalidated(T0, "alice", "ABCDEF0123456789", "RotationAfterLogin"));
    String first = logger.messages.get(0);
    String second = logger.messages.get(1);
    assertFalse(first.contains("ABCDEF0123456789"), first);
    assertFalse(second.contains("ABCDEF0123456789"), second);
    String ref = LoggingAuditSink.sessionRef("ABCDEF0123456789");
    assertEquals(16, ref.length());
    assertTrue(first.contains("sessionRef=" + ref), first);
    assertTrue(second.contains("sessionRef=" + ref), "two events with the same id share the reference: " + second);
    assertFalse(LoggingAuditSink.sessionRef("other").equals(ref), "different ids give different references");
  }

  @Test
  @DisplayName("LoginSucceeded is logged with user/client/session fields")
  void logsLoginSucceeded() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingAuditSink(logger).accept(
        new LoginSucceeded(T0, "alice", "127.0.0.1", "S-1"));

    String line = logger.firstMessage();
    assertTrue(line.contains("type=LoginSucceeded"), line);
    assertTrue(line.contains("user=alice"), line);
    assertTrue(line.contains("client=127.0.0.1"), line);
    assertFalse(line.contains("S-1"), "the live session id must not be logged: " + line);
    assertTrue(line.contains("sessionRef=" + LoggingAuditSink.sessionRef("S-1")), line);
  }

  @Test
  @DisplayName("LogoutPerformed is logged with subject/session/scope")
  void logsLogoutPerformed() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingAuditSink(logger).accept(
        new LogoutPerformed(T0, "alice", "tok-7", LogoutScope.AllSessionsOfSubject));

    String line = logger.firstMessage();
    assertTrue(line.contains("type=LogoutPerformed"));
    assertTrue(line.contains("subject=alice"));
    assertFalse(line.contains("tok-7"), "the live session id must not be logged: " + line);
    assertTrue(line.contains("sessionRef=" + LoggingAuditSink.sessionRef("tok-7")));
    assertTrue(line.contains("scope=AllSessionsOfSubject"));
  }

  @Test
  @DisplayName("BruteForceLimitReached logs failedAttempts and lockoutSeconds")
  void logsBruteForce() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingAuditSink(logger).accept(new BruteForceLimitReached(
        T0, "alice", "127.0.0.1", 5, Duration.ofMinutes(15)));

    String line = logger.firstMessage();
    assertTrue(line.contains("type=BruteForceLimitReached"));
    assertTrue(line.contains("failedAttempts=5"));
    assertTrue(line.contains("lockoutSeconds=900"));
  }

  @Test
  @DisplayName("Null event is silently dropped")
  void nullEventDropped() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingAuditSink(logger).accept(null);
    assertEquals(0, logger.messages.size());
  }

  @Test
  @DisplayName("Fields with null values are omitted from the log line")
  void nullFieldsAreOmitted() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingAuditSink(logger).accept(
        new AccessGranted(T0, null, null));

    String line = logger.firstMessage();
    assertTrue(line.contains("type=AccessGranted"));
    assertTrue(!line.contains("subject="), "null subject must not be logged: " + line);
    assertTrue(!line.contains("route="), "null route must not be logged: " + line);
  }

  @Test
  @DisplayName("R036: a throwing audit logger is swallowed (accept never throws)")
  void throwingLoggerIsSwallowed() {
    RecordingSlf4jLogger throwing = new RecordingSlf4jLogger() {
      @Override
      public void info(String msg) {
        throw new RuntimeException("logger boom");
      }
    };
    // Must not propagate — the WARN goes to the framework static logger.
    new LoggingAuditSink(throwing).accept(new LoginSucceeded(T0, "alice", "127.0.0.1", "S-1"));
  }
}
