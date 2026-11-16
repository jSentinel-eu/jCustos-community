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
package eu.jsentinel.jcustos.demo.standalone;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("DemoAuthenticationService")
class DemoAuthenticationServiceTest {

  @BeforeAll
  static void seedDemoAccounts() {
    // JS-SEC-137: the fixed-password accounts exist only on explicit request.
    UserDirectory.instance().seedInsecureDemoAccounts();
  }

  private final DemoAuthenticationService service = new DemoAuthenticationService();

  @Test
  @DisplayName("checkCredentials returns false for null")
  void nullCredentialsRejected() {
    assertFalse(service.checkCredentials(null),
        "null credentials must be rejected");
  }

  @Test
  @DisplayName("checkCredentials returns false for an unknown user / wrong password")
  void unknownCredentialsRejected() {
    assertFalse(service.checkCredentials(new Credentials("nobody", "x")));
    assertFalse(service.checkCredentials(new Credentials("alice", "WRONG")));
  }

  @Test
  @DisplayName("checkCredentials returns true for a seeded user")
  void validCredentialsAccepted() {
    assertTrue(service.checkCredentials(new Credentials("alice", "alice")));
  }

  @Test
  @DisplayName("loadSubject returns null for unknown / wrong credentials")
  void loadSubjectNullForUnknown() {
    assertNull(service.loadSubject(new Credentials("nobody", "x")));
  }

  @Test
  @DisplayName("loadSubject returns the matching User")
  void loadSubjectReturnsUser() {
    User user = service.loadSubject(new Credentials("alice", "alice"));
    assertNotNull(user);
    assertSame("alice", user.username());
  }

  @Test
  @DisplayName("subjectType is User.class")
  void subjectTypeIsUser() {
    assertSame(User.class, service.subjectType());
  }
}
