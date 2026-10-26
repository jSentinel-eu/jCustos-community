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
package eu.jsentinel.jcustos.accountlifecycle;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.EmailVerificationRequested;
import eu.jsentinel.jcustos.audit.EmailVerified;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authentication.PasswordHasher;
import eu.jsentinel.jcustos.authentication.Pbkdf2PasswordHasher;
import eu.jsentinel.jcustos.credential.token.TokenHasher;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("EmailVerificationService")
class EmailVerificationServiceTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final SubjectId BOB = new SubjectId("bob");
  private static final String ALICE_EMAIL = "alice@example.com";
  private static final String BOB_EMAIL = "bob@example.com";
  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

  private static final class FakeHasher implements TokenHasher {
    @Override public String hash(char[] raw) {
      return "h:" + HexFormat.of().formatHex(new String(raw).getBytes());
    }
  }

  /** Deterministic construction, salted output — the dangerous shape the guard rejects. */
  private static final class SaltedTokenHasher implements TokenHasher {
    private final java.security.SecureRandom rng = new java.security.SecureRandom();
    @Override public String hash(char[] raw) {
      byte[] salt = new byte[8];
      rng.nextBytes(salt);
      return HexFormat.of().formatHex(salt) + ":" + new String(raw);
    }
  }

  @Test
  @DisplayName("the deprecated ctor rejects a salted PasswordHasher at construction (H2)")
  void saltedPasswordHasherRejected() {
    PasswordHasher salted = new Pbkdf2PasswordHasher(); // real, salted per call — no mock
    assertThrows(IllegalArgumentException.class,
        () -> new EmailVerificationService(new InMemoryEmailVerificationTokenStore(), salted,
            new CollectingAuditService(), new RecordingNotificationSender()));
  }

  @Test
  @DisplayName("a non-deterministic TokenHasher makes validate() silently fail — why the guard exists (H2)")
  void nonDeterministicHasherBreaksValidate() {
    EmailVerificationService service = new EmailVerificationService(
        new InMemoryEmailVerificationTokenStore(), new SaltedTokenHasher(),
        new CollectingAuditService(), new RecordingNotificationSender());
    EmailVerificationService.IssuedToken issued =
        service.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(5));
    assertTrue(service.validate(issued.plainToken()).isEmpty(),
        "a fresh salt per hash() means the stored hash can never be looked up");
  }

  private static Supplier<String> sequentialSource(String prefix) {
    AtomicLong c = new AtomicLong();
    return () -> prefix + c.incrementAndGet();
  }

  private static Clock fixed(Instant at) { return Clock.fixed(at, ZoneOffset.UTC); }

  private static Clock steppingClock(Instant start, Duration step) {
    return new Clock() {
      private Instant cursor = start.minus(step);
      @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
      @Override public Clock withZone(java.time.ZoneId zone) { return this; }
      @Override public synchronized Instant instant() {
        cursor = cursor.plus(step);
        return cursor;
      }
    };
  }

  @Test
  @DisplayName("request stores only the hash, emits audit + notification with email + tokenPlain")
  void requestHashesAndNotifies() {
    InMemoryEmailVerificationTokenStore store = new InMemoryEmailVerificationTokenStore();
    CollectingAuditService audit = new CollectingAuditService();
    RecordingNotificationSender sender = new RecordingNotificationSender();
    TokenHasher hasher = new FakeHasher();

    EmailVerificationService service = new EmailVerificationService(
        store, hasher, audit, sender, TenantId.DEFAULT, fixed(T0),
        sequentialSource("tok-"));

    EmailVerificationService.IssuedToken issued =
        service.request(ALICE, ALICE_EMAIL, Duration.ofHours(24));

    assertEquals("tok-1", issued.plainToken());
    assertEquals(ALICE_EMAIL, issued.record().email());
    assertEquals(hasher.hash("tok-1".toCharArray()), issued.record().tokenHash());
    assertTrue(store.findByHash("tok-1").isEmpty());
    assertTrue(store.findByHash(hasher.hash("tok-1".toCharArray())).isPresent());

    EmailVerificationRequested event = (EmailVerificationRequested) audit.published.get(0);
    assertEquals("alice", event.subjectId());
    assertEquals(ALICE_EMAIL, event.email());

    JCustosNotification n = sender.received.get(0);
    assertEquals(JCustosNotification.Kind.EMAIL_VERIFICATION_REQUESTED, n.kind());
    assertEquals("tok-1", n.attributes().get("tokenPlain"));
    assertEquals(ALICE_EMAIL, n.attributes().get("email"));
  }

  @Test
  @DisplayName("JS-SEC-074: a second request retires the first token; only the newest link works")
  void requestRetiresPredecessors() {
    InMemoryEmailVerificationTokenStore store = new InMemoryEmailVerificationTokenStore();
    EmailVerificationService service = new EmailVerificationService(
        store, new FakeHasher(), new CollectingAuditService(), new RecordingNotificationSender(),
        TenantId.DEFAULT, steppingClock(T0, Duration.ofSeconds(1)), sequentialSource("tok-"));
    EmailVerificationService.IssuedToken first = service.request(ALICE, ALICE_EMAIL, Duration.ofHours(24));
    EmailVerificationService.IssuedToken second = service.request(ALICE, ALICE_EMAIL, Duration.ofHours(24));

    assertTrue(service.validate(first.plainToken()).isEmpty(), "the older link must be dead");
    assertTrue(service.consume(second.plainToken()).isPresent());
    assertEquals(1, store.size(), "only the consumed record remains");
  }

  @Test
  @DisplayName("JS-SEC-074: consume retires every other token of the subject but keeps the consumed marker")
  void consumeRetiresSiblingsKeepsConsumed() {
    InMemoryEmailVerificationTokenStore store = new InMemoryEmailVerificationTokenStore();
    FakeHasher hasher = new FakeHasher();
    EmailVerificationService service = new EmailVerificationService(
        store, hasher, new CollectingAuditService(), new RecordingNotificationSender(),
        TenantId.DEFAULT, steppingClock(T0, Duration.ofSeconds(1)), sequentialSource("tok-"));
    EmailVerificationService.IssuedToken issued = service.request(ALICE, ALICE_EMAIL, Duration.ofHours(24));
    String strayHash = hasher.hash("stray".toCharArray());
    store.save(new EmailVerificationTokenRecord(strayHash, TenantId.DEFAULT, ALICE, ALICE_EMAIL,
        T0, T0.plus(Duration.ofHours(24)), Optional.empty()));

    assertTrue(service.consume(issued.plainToken()).isPresent());

    assertTrue(store.findByHash(strayHash).isEmpty(), "siblings are retired");
    assertTrue(store.findByHash(hasher.hash(issued.plainToken().toCharArray())).orElseThrow().isConsumed(),
        "the consumed record stays as the single-use marker");
    assertTrue(service.consume(issued.plainToken()).isEmpty(), "still single-use");
  }

  @Test
  @DisplayName("validate rejects unknown / wrong tenant / expired tokens")
  void validateNegativeCases() {
    InMemoryEmailVerificationTokenStore store = new InMemoryEmailVerificationTokenStore();
    TokenHasher hasher = new FakeHasher();
    EmailVerificationService defaultSvc = new EmailVerificationService(
        store, hasher, new CollectingAuditService(), new RecordingNotificationSender(),
        TenantId.DEFAULT, fixed(T0), sequentialSource("def-"));
    EmailVerificationService acmeSvc = new EmailVerificationService(
        store, hasher, new CollectingAuditService(), new RecordingNotificationSender(),
        new TenantId("acme"), fixed(T0), sequentialSource("acme-"));

    String good = defaultSvc.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(15)).plainToken();
    assertTrue(defaultSvc.validate(good).isPresent());

    assertTrue(defaultSvc.validate(null).isEmpty());
    assertTrue(defaultSvc.validate("").isEmpty());
    assertTrue(defaultSvc.validate("ghost").isEmpty());

    String acmePlain = acmeSvc.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(15)).plainToken();
    assertTrue(defaultSvc.validate(acmePlain).isEmpty());

    EmailVerificationService shortLived = new EmailVerificationService(
        store, hasher, new CollectingAuditService(), new RecordingNotificationSender(),
        TenantId.DEFAULT, fixed(T0), sequentialSource("short-"));
    String shortPlain = shortLived.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(1)).plainToken();
    EmailVerificationService future = new EmailVerificationService(
        store, hasher, new CollectingAuditService(), new RecordingNotificationSender(),
        TenantId.DEFAULT, fixed(T0.plus(Duration.ofMinutes(2))), sequentialSource("unused-"));
    assertTrue(future.validate(shortPlain).isEmpty());
  }

  @Test
  @DisplayName("consume is single-use and emits EmailVerified")
  void consumeIsSingleUse() {
    InMemoryEmailVerificationTokenStore store = new InMemoryEmailVerificationTokenStore();
    TokenHasher hasher = new FakeHasher();
    CollectingAuditService audit = new CollectingAuditService();
    RecordingNotificationSender sender = new RecordingNotificationSender();
    EmailVerificationService service = new EmailVerificationService(
        store, hasher, audit, sender, TenantId.DEFAULT,
        steppingClock(T0, Duration.ofSeconds(1)), sequentialSource("tok-"));

    String plain = service.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(15)).plainToken();

    Optional<EmailVerificationTokenRecord> first = service.consume(plain);
    assertTrue(first.isPresent());
    assertTrue(first.get().isConsumed());

    Optional<EmailVerificationTokenRecord> second = service.consume(plain);
    assertTrue(second.isEmpty(), "second consume must yield empty");

    assertEquals(2, audit.published.size());
    EmailVerified verified = (EmailVerified) audit.published.get(1);
    assertEquals("alice", verified.subjectId());
    assertEquals(ALICE_EMAIL, verified.email());

    assertEquals(2, sender.received.size());
    assertEquals(JCustosNotification.Kind.EMAIL_VERIFIED, sender.received.get(1).kind());
    assertEquals(ALICE_EMAIL, sender.received.get(1).attributes().get("email"));
  }

  @Test
  @DisplayName("revokeAll removes only the subject's tokens within the tenant")
  void revokeAllScoped() {
    InMemoryEmailVerificationTokenStore store = new InMemoryEmailVerificationTokenStore();
    TokenHasher hasher = new FakeHasher();
    EmailVerificationService service = new EmailVerificationService(
        store, hasher, new CollectingAuditService(), new RecordingNotificationSender(),
        TenantId.DEFAULT, fixed(T0), sequentialSource("tok-"));

    String a1 = service.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(15)).plainToken();
    String a2 = service.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(15)).plainToken();
    String b1 = service.request(BOB, BOB_EMAIL, Duration.ofMinutes(15)).plainToken();
    assertNotEquals(a1, a2);

    // JS-SEC-074: the second request already retired a1, so one record remains
    assertEquals(1, service.revokeAll(ALICE));
    assertTrue(service.validate(a1).isEmpty());
    assertTrue(service.validate(a2).isEmpty());
    assertTrue(service.validate(b1).isPresent());
  }

  @Test
  @DisplayName("audit + notification failures do not block the lifecycle flow")
  void sinkFailuresSwallowed() {
    InMemoryEmailVerificationTokenStore store = new InMemoryEmailVerificationTokenStore();
    JCustosAuditService throwingAudit = new JCustosAuditService() {
      @Override public void publish(AuditEvent event) { throw new RuntimeException("boom"); }
      @Override public List<AuditEvent> query(AuditQuery query) { return List.of(); }
    };
    JCustosNotificationSender throwingSender = n -> { throw new RuntimeException("boom"); };
    EmailVerificationService service = new EmailVerificationService(
        store, new FakeHasher(), throwingAudit, throwingSender,
        TenantId.DEFAULT, steppingClock(T0, Duration.ofSeconds(1)),
        sequentialSource("tok-"));

    var issued = service.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(15));
    assertEquals("tok-1", issued.plainToken());
    Optional<EmailVerificationTokenRecord> consumed = service.consume(issued.plainToken());
    assertTrue(consumed.isPresent());
  }

  @Test
  @DisplayName("null / blank arguments + non-positive TTL are rejected")
  void rejectNulls() {
    InMemoryEmailVerificationTokenStore store = new InMemoryEmailVerificationTokenStore();
    TokenHasher hasher = new FakeHasher();
    CollectingAuditService audit = new CollectingAuditService();
    RecordingNotificationSender sender = new RecordingNotificationSender();

    assertThrows(NullPointerException.class,
        () -> new EmailVerificationService(null, hasher, audit, sender));
    assertThrows(NullPointerException.class,
        () -> new EmailVerificationService(store, (TokenHasher) null, audit, sender));

    EmailVerificationService service = new EmailVerificationService(
        store, hasher, audit, sender, TenantId.DEFAULT, fixed(T0), sequentialSource("tok-"));

    assertThrows(NullPointerException.class,
        () -> service.request(null, ALICE_EMAIL, Duration.ofMinutes(1)));
    assertThrows(IllegalArgumentException.class,
        () -> service.request(ALICE, "", Duration.ofMinutes(1)));
    assertThrows(IllegalArgumentException.class,
        () -> service.request(ALICE, null, Duration.ofMinutes(1)));
    assertThrows(NullPointerException.class,
        () -> service.request(ALICE, ALICE_EMAIL, null));
    assertThrows(IllegalArgumentException.class,
        () -> service.request(ALICE, ALICE_EMAIL, Duration.ZERO));
    assertThrows(NullPointerException.class, () -> service.revokeAll(null));

    EmailVerificationService bad = new EmailVerificationService(
        store, hasher, audit, sender, TenantId.DEFAULT, fixed(T0), () -> "");
    assertThrows(IllegalStateException.class,
        () -> bad.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(1)));
  }

  @Test
  @DisplayName("default constructor uses TenantId.DEFAULT and 256-bit token source")
  void defaultConstructorSmoke() {
    InMemoryEmailVerificationTokenStore store = new InMemoryEmailVerificationTokenStore();
    EmailVerificationService service = new EmailVerificationService(
        store, new FakeHasher(), new CollectingAuditService(),
        new RecordingNotificationSender());
    var issued = service.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(5));
    assertEquals(TenantId.DEFAULT, issued.record().tenant());
    assertEquals(43, issued.plainToken().length());
  }

  private static final class CollectingAuditService implements JCustosAuditService {
    final List<AuditEvent> published = new ArrayList<>();
    @Override public void publish(AuditEvent event) { published.add(event); }
    @Override public List<AuditEvent> query(AuditQuery query) { return List.copyOf(published); }
  }

  private static final class RecordingNotificationSender implements JCustosNotificationSender {
    final List<JCustosNotification> received = new ArrayList<>();
    @Override public void send(JCustosNotification n) { received.add(n); }
  }

  // ── V00.74.10 / L2 — audit-sink WARN log discipline ─────────────────

  @Test
  @DisplayName("audit + notification failures surface as WARN log entries (V00.74.10 / L2)")
  void sinkFailures_logWarning() {
    PrintStream originalErr = System.err;
    ByteArrayOutputStream capture = new ByteArrayOutputStream();
    System.setErr(new PrintStream(capture, true, StandardCharsets.UTF_8));
    try {
      InMemoryEmailVerificationTokenStore store = new InMemoryEmailVerificationTokenStore();
      RuntimeException auditBoom = new RuntimeException("audit-boom");
      RuntimeException senderBoom = new RuntimeException("sender-boom");
      JCustosAuditService throwingAudit = new JCustosAuditService() {
        @Override public void publish(AuditEvent event) { throw auditBoom; }
        @Override public List<AuditEvent> query(AuditQuery query) { return List.of(); }
      };
      JCustosNotificationSender throwingSender = n -> { throw senderBoom; };
      EmailVerificationService service = new EmailVerificationService(
          store, new FakeHasher(), throwingAudit, throwingSender,
          TenantId.DEFAULT, steppingClock(T0, Duration.ofSeconds(1)),
          sequentialSource("tok-"));

      // request + consume both trigger publish + notify
      var issued = service.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(15));
      assertTrue(service.consume(issued.plainToken()).isPresent(),
          "consume should still succeed despite sink failures (existing contract)");

      String stderr = capture.toString(StandardCharsets.UTF_8);
      assertTrue(stderr.contains("WARN") && stderr.contains("audit sink failed"),
          "expected an audit-sink WARN entry. Captured:\n" + stderr);
      assertTrue(stderr.contains("audit-boom"),
          "expected the audit-sink sentinel message in the stacktrace. Captured:\n" + stderr);
      assertTrue(stderr.contains("notification sender failed"),
          "expected a notification-sender WARN entry. Captured:\n" + stderr);
      assertTrue(stderr.contains("sender-boom"),
          "expected the notification-sender sentinel message in the stacktrace. Captured:\n" + stderr);
    } finally {
      System.setErr(originalErr);
    }
  }
}
