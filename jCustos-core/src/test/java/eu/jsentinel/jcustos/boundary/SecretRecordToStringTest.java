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
package eu.jsentinel.jcustos.boundary;

import eu.jsentinel.jcustos.accountlifecycle.EmailVerificationService;
import eu.jsentinel.jcustos.accountlifecycle.InMemoryEmailVerificationTokenStore;
import eu.jsentinel.jcustos.accountlifecycle.InMemoryPasswordResetTokenStore;
import eu.jsentinel.jcustos.accountlifecycle.JCustosNotification;
import eu.jsentinel.jcustos.accountlifecycle.PasswordResetService;
import eu.jsentinel.jcustos.authentication.InMemoryRefreshTokenStore;
import eu.jsentinel.jcustos.authentication.InMemoryRememberMeTokenStore;
import eu.jsentinel.jcustos.authentication.StoreBackedRememberMeService;
import eu.jsentinel.jcustos.authentication.TokenService;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bootstrap.CreateInitialAdminCommand;
import eu.jsentinel.jcustos.credential.CredentialTestKit;
import eu.jsentinel.jcustos.credential.propagation.BearerToken;
import eu.jsentinel.jcustos.credential.propagation.HeaderValue;
import eu.jsentinel.jcustos.credential.propagation.OutboundCall;
import eu.jsentinel.jcustos.credential.propagation.PassThroughStrategy;
import eu.jsentinel.jcustos.credential.token.Sha256TokenHasher;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-127 and JS-SEC-088 (CWE-532): the string form of a record that
 * carries a plaintext token must not contain the token. Every record is
 * obtained from the real service that produces it.
 */
@DisplayName("JS-SEC-127 / JS-SEC-088 — toString of token-bearing records masks the token")
class SecretRecordToStringTest {

  private static final SubjectId ALICE = SubjectId.of("alice");

  @Test
  @DisplayName("JS-SEC-088: HeaderValue masks the header value and keeps the name")
  void headerValue() {
    HeaderValue header = new HeaderValue("Authorization", "Bearer abc");

    assertEquals("HeaderValue[name=Authorization, value=***]", header.toString());
    assertFalse(header.toString().contains("abc"));
    assertFalse(header.toString().contains("Bearer abc"));
    assertEquals("Bearer abc", header.value(), "the accessor still delivers the value");
  }

  @Test
  @DisplayName("JS-SEC-088: the header a strategy resolves does not print the bearer token")
  void headerValueFromStrategy() {
    HeaderValue resolved = PassThroughStrategy.INSTANCE.resolve(
        new OutboundCall("Svc", "method", "", Map.of()),
        Optional.of(new BearerToken("eyJhbGciOiJSUzI1NiJ9.payload.signature"))).orElseThrow();

    String text = "outbound header " + resolved;
    assertFalse(text.contains("eyJhbGciOiJSUzI1NiJ9"));
    assertTrue(text.contains("Authorization"));
  }

  @Test
  @DisplayName("TokenPair masks access and refresh token, issued and rotated")
  void tokenPair() {
    TokenService service = new TokenService(new InMemoryRefreshTokenStore(),
        new Sha256TokenHasher(), new CredentialTestKit.RecordingAudit());
    TokenService.TokenPair issued = service.issue(ALICE);
    TokenService.TokenPair rotated = service.rotate(issued.refreshToken()).orElseThrow();

    for (TokenService.TokenPair pair : List.of(issued, rotated)) {
      String text = pair.toString();
      assertFalse(text.contains(pair.accessToken()), text);
      assertFalse(text.contains(pair.refreshToken()), text);
      assertTrue(text.contains("alice"), "non-secret components stay readable: " + text);
      assertTrue(text.contains(pair.refreshExpiresAt().toString()), text);
    }
  }

  @Test
  @DisplayName("remember-me IssuedToken masks the plain token")
  void rememberMeIssuedToken() {
    StoreBackedRememberMeService service = new StoreBackedRememberMeService(
        new InMemoryRememberMeTokenStore(), new Sha256TokenHasher());
    StoreBackedRememberMeService.IssuedToken issued = service.issue(ALICE, Duration.ofDays(14));

    assertFalse(issued.toString().contains(issued.plainToken()), issued.toString());
    assertTrue(issued.toString().contains("alice"));
  }

  @Test
  @DisplayName("password-reset IssuedToken and the notification handed to the sender mask the plain token")
  void passwordResetIssuedTokenAndNotification() {
    List<JCustosNotification> delivered = new CopyOnWriteArrayList<>();
    PasswordResetService service = new PasswordResetService(
        new InMemoryPasswordResetTokenStore(), new Sha256TokenHasher(),
        new CredentialTestKit.RecordingAudit(), delivered::add);

    PasswordResetService.IssuedToken issued = service.request(ALICE, Duration.ofMinutes(15));

    assertFalse(issued.toString().contains(issued.plainToken()), issued.toString());
    assertEquals(1, delivered.size());
    JCustosNotification notification = delivered.getFirst();
    assertEquals(issued.plainToken(), notification.attributes().get("tokenPlain"),
        "the sender still receives the token it has to deliver");
    String text = notification.toString();
    assertFalse(text.contains(issued.plainToken()), text);
    assertTrue(text.contains("tokenPlain=***"), text);
    assertTrue(text.contains("expiresAt=" + issued.record().expiresAt()),
        "non-secret attributes stay readable: " + text);
    assertTrue(text.contains("PASSWORD_RESET_REQUESTED"), text);
  }

  @Test
  @DisplayName("email-verification IssuedToken and its notification mask the plain token")
  void emailVerificationIssuedTokenAndNotification() {
    List<JCustosNotification> delivered = new CopyOnWriteArrayList<>();
    EmailVerificationService service = new EmailVerificationService(
        new InMemoryEmailVerificationTokenStore(), new Sha256TokenHasher(),
        new CredentialTestKit.RecordingAudit(), delivered::add);

    EmailVerificationService.IssuedToken issued =
        service.request(ALICE, "alice@example.org", Duration.ofHours(1));

    assertFalse(issued.toString().contains(issued.plainToken()), issued.toString());
    String text = delivered.getFirst().toString();
    assertFalse(text.contains(issued.plainToken()), text);
    assertTrue(text.contains("email=alice@example.org"), text);
  }

  @Test
  @DisplayName("JCustosNotification masks every attribute whose key names a token, secret or password")
  void notificationMasksBySharedRule() {
    JCustosNotification notification = new JCustosNotification(
        JCustosNotification.Kind.PASSWORD_RESET_REQUESTED, ALICE, TenantId.DEFAULT,
        Instant.parse("2026-11-10T10:00:00Z"),
        Map.of("resetToken", "t-1", "clientSecret", "s-1", "newPassword", "p-1",
            "TOKEN_PLAIN", "t-2", "locale", "en-GB"));

    String text = notification.toString();
    for (String secret : List.of("t-1", "s-1", "p-1", "t-2")) {
      assertFalse(text.contains(secret), text);
    }
    assertTrue(text.contains("locale=en-GB"), text);

    assertTrue(JCustosNotification.isSensitiveAttribute("tokenPlain"));
    assertTrue(JCustosNotification.isSensitiveAttribute("API_SECRET"));
    assertTrue(JCustosNotification.isSensitiveAttribute("oldPassword"));
    assertFalse(JCustosNotification.isSensitiveAttribute("email"));
    assertFalse(JCustosNotification.isSensitiveAttribute("expiresAt"));
    assertFalse(JCustosNotification.isSensitiveAttribute(null));
  }

  @Test
  @DisplayName("CreateInitialAdminCommand masks the bootstrap token and the password")
  void createInitialAdminCommand() {
    CreateInitialAdminCommand command = new CreateInitialAdminCommand(
        "ABCD-EFGH-JKLM-NPQR-STUV", "root-admin", "a-long-password-123".toCharArray(),
        "Root Admin", "root@example.org");

    String text = command.toString();
    assertFalse(text.contains("ABCD-EFGH-JKLM-NPQR-STUV"), text);
    assertFalse(text.contains("a-long-password-123"), text);
    assertTrue(text.contains("root-admin"), text);
    assertTrue(text.contains("root@example.org"), text);
  }
}
