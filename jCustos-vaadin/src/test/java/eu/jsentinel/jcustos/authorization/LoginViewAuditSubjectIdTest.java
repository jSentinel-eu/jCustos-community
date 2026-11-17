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
package eu.jsentinel.jcustos.authorization;

import eu.jsentinel.jcustos.authorization.api.CurrentSubject;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.SessionContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * R14 (V00.76.10): the post-login session-rotation audit
 * ({@code SessionInvalidated}) must derive its subject id from the registered
 * {@link SubjectIdResolver}, never from {@code subject.toString()} — an
 * application user object commonly serialises email / password-hash / internal
 * ids in its {@code toString()}, which would leak into the audit channel.
 * <p>
 * JS-SEC-097 (decision F06): without a resolver the id is the identity handle that
 * navigation and session lifetime derive for the same subject - no longer an empty string.
 */
@DisplayName("LoginView.subjectIdOf — R14 audit subject-id never leaks toString()")
class LoginViewAuditSubjectIdTest {

  /** An application user whose toString() carries PII — the exact leak shape. */
  record PiiUser(String email, String passwordHash) {
    @Override
    public String toString() {
      return "PiiUser[email=" + email + ", hash=" + passwordHash + "]";
    }
  }

  private static SessionContext<Object> contextWith(Object subject) {
    return new SessionContext<>(subject, "sid-1", Instant.now(), Instant.now(),
        "127.0.0.1", Map.of());
  }

  @BeforeEach
  @AfterEach
  void reset() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("with a SubjectIdResolver: returns the resolved id, never the PII toString()")
  void usesResolverNotToString() {
    PiiUser user = new PiiUser("alice@corp.example", "argon2id$secret");
    SubjectIdResolver<Object> resolver = s -> new SubjectId("uid-42");
    JCustosServiceResolver.setSubjectIdResolver(resolver);

    String id = LoginView.subjectIdOf(contextWith(user));

    assertEquals("uid-42", id);
    assertFalse(id.contains("alice@corp.example"),
        "the email must never reach the audit subject id");
    assertFalse(id.contains("argon2id"),
        "the password hash must never reach the audit subject id");
  }

  @Test
  @DisplayName("JS-SEC-097: without a SubjectIdResolver: the identity handle of CurrentSubject, never empty, never the PII toString()")
  void noResolverReturnsIdentityHandleNotToString() {
    PiiUser user = new PiiUser("bob@corp.example", "argon2id$secret");

    String id = LoginView.subjectIdOf(contextWith(user));

    assertEquals(CurrentSubject.subjectIdOf(user), id,
        "the rotation audit derives the id by the rule every other Vaadin site uses");
    assertEquals("PiiUser@" + Integer.toHexString(System.identityHashCode(user)), id);
    assertFalse(id.contains("bob@corp.example"), "the email must never reach the audit subject id");
    assertFalse(id.contains("argon2id"), "the password hash must never reach the audit subject id");
  }

  @Test
  @DisplayName("null subject: empty id - no subject, nothing to identify")
  void nullSubjectEmpty() {
    assertEquals("", LoginView.subjectIdOf(contextWith(null)));
  }
}
