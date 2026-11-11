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
package eu.jsentinel.jcustos.authentication;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.LoggingAuditSink;
import eu.jsentinel.jcustos.audit.RecordingSlf4jLogger;
import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.credential.CredentialTestKit.MutableClock;
import eu.jsentinel.jcustos.credential.CredentialTestKit.RecordingAudit;
import eu.jsentinel.jcustos.credential.token.Sha256TokenHasher;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-128 (CWE-778, CWE-294): a remember-me token that was already rotated and is presented
 * again revokes the subject's tokens - and that incident reaches the audit trail, not only the
 * application log.
 */
@DisplayName("JS-SEC-128 — a remember-me replay is audited")
class RememberMeReplayAuditTest {

  private static final SubjectId ALICE = SubjectId.of("alice");
  private static final SubjectId BOB = SubjectId.of("bob");
  private static final Instant T0 = Instant.parse("2026-11-10T10:00:00Z");
  private static final Duration TTL = Duration.ofDays(14);

  private final MutableClock clock = new MutableClock(T0);
  private final AtomicLong counter = new AtomicLong();
  private final RecordingAudit audit = new RecordingAudit();

  private StoreBackedRememberMeService service(JCustosAuditService sink) {
    return new StoreBackedRememberMeService(new InMemoryRememberMeTokenStore(),
        new Sha256TokenHasher(), TenantId.DEFAULT, clock,
        () -> "remember-me-" + counter.incrementAndGet(), sink);
  }

  @AfterEach
  void resetResolver() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("the replay publishes one SessionInvalidated for the subject, without a session id, with the replay reason")
  void replayIsAudited() {
    StoreBackedRememberMeService service = service(audit);
    String stolen = service.issue(ALICE, TTL).plainToken();
    service.issue(BOB, TTL);
    String thiefs = service.rotate(stolen).orElseThrow().plainToken();
    assertTrue(audit.events.isEmpty(), "an ordinary rotation is not an incident");

    clock.advance(Duration.ofHours(1));
    assertTrue(service.rotate(stolen).isEmpty());

    assertEquals(1, audit.events.size(), "one incident, one event: " + audit.events);
    SessionInvalidated event = assertInstanceOf(SessionInvalidated.class, audit.events.getFirst());
    assertEquals("alice", event.subjectId());
    assertEquals(StoreBackedRememberMeService.REASON_TOKEN_REPLAY, event.reason());
    assertEquals("RememberMeTokenReplay", event.reason());
    assertNull(event.sessionId(), "the event stands for every remembered login of the subject");
    assertEquals(T0.plus(Duration.ofHours(1)), event.timestamp());
    assertTrue(service.validate(thiefs).isEmpty(), "the event states what has already happened");
  }

  @Test
  @DisplayName("validate() of a replayed token is audited as well")
  void replaySeenByValidateIsAudited() {
    StoreBackedRememberMeService service = service(audit);
    String original = service.issue(ALICE, TTL).plainToken();
    service.rotate(original).orElseThrow();

    clock.advance(Duration.ofMinutes(10));
    assertTrue(service.validate(original).isEmpty());

    assertEquals(1, audit.events.size());
    assertEquals("alice", ((SessionInvalidated) audit.events.getFirst()).subjectId());
  }

  @Test
  @DisplayName("no event for a parallel request inside the tolerance, an unknown token or an expired token")
  void whatIsNotAReplayIsNotAudited() {
    StoreBackedRememberMeService service = service(audit);
    String original = service.issue(ALICE, TTL).plainToken();
    service.rotate(original).orElseThrow();

    clock.advance(StoreBackedRememberMeService.ROTATION_RACE_TOLERANCE.minusMillis(1));
    assertTrue(service.rotate(original).isEmpty());
    assertTrue(service.rotate("never-issued").isEmpty());
    String shortLived = service.issue(BOB, Duration.ofSeconds(1)).plainToken();
    clock.advance(Duration.ofSeconds(2));
    assertTrue(service.rotate(shortLived).isEmpty());

    // The last step moved the clock past the tolerance of the first token; a replay of that
    // one is audited from now on, which shows the silence above was not a broken sink.
    assertTrue(audit.events.isEmpty(), audit.events.toString());
    assertTrue(service.rotate(original).isEmpty());
    assertEquals(1, audit.events.size());
  }

  @Test
  @DisplayName("without an explicit sink the event goes to the audit service registered with the resolver")
  void fallsBackToTheRegisteredAuditService() {
    JCustosServiceResolver.setJCustosAuditService(audit);
    StoreBackedRememberMeService service = new StoreBackedRememberMeService(
        new InMemoryRememberMeTokenStore(), new Sha256TokenHasher(), TenantId.DEFAULT, clock,
        () -> "remember-me-" + counter.incrementAndGet());
    String original = service.issue(ALICE, TTL).plainToken();
    service.rotate(original).orElseThrow();

    clock.advance(Duration.ofMinutes(1));
    assertTrue(service.rotate(original).isEmpty());

    assertEquals(1, audit.events.size());
    assertInstanceOf(SessionInvalidated.class, audit.events.getFirst());
  }

  @Test
  @DisplayName("a failing audit sink does not undo the revocation and does not reach the caller")
  void failingSinkDoesNotBlockTheRevocation() {
    JCustosAuditService broken = new JCustosAuditService() {
      @Override
      public void publish(AuditEvent event) {
        throw new IllegalStateException("audit store unreachable");
      }

      @Override
      public List<AuditEvent> query(AuditQuery query) {
        return List.of();
      }
    };
    StoreBackedRememberMeService service = service(broken);
    String original = service.issue(ALICE, TTL).plainToken();
    String successor = service.rotate(original).orElseThrow().plainToken();

    clock.advance(Duration.ofMinutes(1));

    assertTrue(service.rotate(original).isEmpty());
    assertTrue(service.validate(successor).isEmpty());
  }

  @Test
  @DisplayName("the event is found by subject and renders as one audit line without a session reference")
  void eventRendersThroughTheExistingSinks() {
    StoreBackedRememberMeService service = service(audit);
    String original = service.issue(ALICE, TTL).plainToken();
    service.rotate(original).orElseThrow();
    clock.advance(Duration.ofMinutes(1));
    service.rotate(original);
    AuditEvent event = audit.events.getFirst();

    assertTrue(AuditQuery.forSubject("alice").matches(event));
    assertFalse(AuditQuery.forSubject("bob").matches(event));
    assertTrue(AuditQuery.ofType(SessionInvalidated.class).matches(event));

    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingAuditSink(logger).accept(event);
    assertEquals("AUDIT type=SessionInvalidated subject=alice reason=RememberMeTokenReplay",
        logger.firstMessage());
  }
}
