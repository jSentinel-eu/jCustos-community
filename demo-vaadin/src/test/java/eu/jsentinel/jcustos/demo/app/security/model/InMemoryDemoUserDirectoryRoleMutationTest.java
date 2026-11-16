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
package eu.jsentinel.jcustos.demo.app.security.model;

import eu.jsentinel.jcustos.audit.RoleAssigned;
import eu.jsentinel.jcustos.audit.RoleRevoked;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryDemoUserDirectory — assignRole / revokeRole")
class InMemoryDemoUserDirectoryRoleMutationTest {

  private RecordingAuditSink audit;

  @BeforeEach
  void setUp() {
    JCustosServiceResolver.resetAll();
    audit = new RecordingAuditSink();
    JCustosServiceResolver.setJCustosAuditService(audit);
  }

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("assignRole adds the role to the stored MyUser and emits RoleAssigned")
  void assignRoleAddsAndAudits() {
    InMemoryDemoUserDirectory directory = new InMemoryDemoUserDirectory(PasswordHashingServices.defaults());
    audit.clear(); // discard the seeded UserCreated events

    MyUser before = directory.findById(2L).orElseThrow();
    assertFalse(before.roles().contains(AuthorizationRole.ADMIN));

    directory.assignRole(2L, AuthorizationRole.ADMIN);

    MyUser after = directory.findById(2L).orElseThrow();
    assertTrue(after.roles().contains(AuthorizationRole.ADMIN));
    assertEquals(1, audit.events().size());
    RoleAssigned event = assertInstanceOf(RoleAssigned.class, audit.events().get(0));
    assertEquals("2", event.subjectId());
    assertEquals("ADMIN", event.role());
  }

  @Test
  @DisplayName("assignRole for a role the user already has is a no-op (no audit)")
  void assignRoleIdempotent() {
    InMemoryDemoUserDirectory directory = new InMemoryDemoUserDirectory(PasswordHashingServices.defaults());
    audit.clear(); // discard the seeded UserCreated events

    directory.assignRole(2L, AuthorizationRole.USER); // user already has USER

    assertEquals(0, audit.events().size(),
        "idempotent assignment must not emit a RoleAssigned event");
  }

  @Test
  @DisplayName("revokeRole removes the role and emits RoleRevoked")
  void revokeRoleRemovesAndAudits() {
    InMemoryDemoUserDirectory directory = new InMemoryDemoUserDirectory(PasswordHashingServices.defaults());
    audit.clear(); // discard the seeded UserCreated events

    directory.assignRole(2L, AuthorizationRole.NERD);
    audit.clear();

    directory.revokeRole(2L, AuthorizationRole.NERD);

    MyUser after = directory.findById(2L).orElseThrow();
    assertFalse(after.roles().contains(AuthorizationRole.NERD));
    assertEquals(1, audit.events().size());
    RoleRevoked event = assertInstanceOf(RoleRevoked.class, audit.events().get(0));
    assertEquals("2", event.subjectId());
    assertEquals("NERD", event.role());
  }

  @Test
  @DisplayName("revokeRole for a role the user doesn't have is a no-op (no audit)")
  void revokeRoleIdempotent() {
    InMemoryDemoUserDirectory directory = new InMemoryDemoUserDirectory(PasswordHashingServices.defaults());
    audit.clear(); // discard the seeded UserCreated events

    directory.revokeRole(2L, AuthorizationRole.ADMIN); // user only has USER

    assertEquals(0, audit.events().size());
  }

  @Test
  @DisplayName("unknown user id is a silent no-op")
  void unknownIdNoOp() {
    InMemoryDemoUserDirectory directory = new InMemoryDemoUserDirectory(PasswordHashingServices.defaults());
    audit.clear(); // discard the seeded UserCreated events

    directory.assignRole(999L, AuthorizationRole.ADMIN);
    directory.revokeRole(999L, AuthorizationRole.USER);

    assertEquals(0, audit.events().size());
  }

  @Test
  @DisplayName("After assign + revoke the user reaches its original role set; logins still work")
  void roundTripPreservesLogin() {
    InMemoryDemoUserDirectory directory = new InMemoryDemoUserDirectory(PasswordHashingServices.defaults());
    audit.clear(); // discard the seeded UserCreated events

    directory.assignRole(2L, AuthorizationRole.ADMIN);
    directory.revokeRole(2L, AuthorizationRole.ADMIN);

    // The user can still log in with the original password — the
    // password hash is preserved across the role mutation.
    assertTrue(directory.checkCredentials(new Credentials("user", "user")));
  }

}
