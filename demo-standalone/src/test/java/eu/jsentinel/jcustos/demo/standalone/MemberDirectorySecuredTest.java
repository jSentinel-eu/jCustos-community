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

import eu.jsentinel.jcustos.authorization.api.AccessDeniedException;
import eu.jsentinel.jcustos.standalone.StandaloneLoginFlow;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the compile-time enforcement path: the
 * {@code security-processor} annotation processor generates
 * {@code MemberDirectorySecured} as a subclass of
 * {@link MemberDirectory}, and every guarded method calls into
 * {@code JCustosEnforcer} before delegating to {@code super}. If this
 * test class even compiles, the processor ran and produced the
 * subclass; the test bodies verify that the inserted enforcer calls
 * actually decide accesses against the bound subject.
 *
 * <p>Sibling test: {@link DemoStandaloneJCustosTest} drives the
 * runtime / dynamic-proxy path on {@link LibraryService}.
 */
@DisplayName("Demo standalone — compile-time @Secured wrapper for MemberDirectory")
class MemberDirectorySecuredTest {

  @BeforeAll
  static void seedDemoAccounts() {
    // JS-SEC-137: the fixed-password accounts exist only on explicit request.
    UserDirectory.instance().seedInsecureDemoAccounts();
  }

  private final StandaloneLoginFlow<Credentials, User> flow = new StandaloneLoginFlow<>();
  private final MemberDirectory members = new MemberDirectorySecured();

  @AfterEach
  void logout() {
    flow.logout();
  }

  // ── @RequiresPermission (single value) ──────────────────────────

  @Test
  @DisplayName("MEMBER can list members (member:list granted via MEMBER role)")
  void memberCanList() {
    flow.login(new Credentials("alice", "alice"), "alice");
    assertEquals(0, members.listMembers().size(),
        "freshly constructed directory is empty");
  }

  @Test
  @DisplayName("Anonymous listMembers() throws AccessDeniedException")
  void anonymousCannotList() {
    assertThrows(AccessDeniedException.class, members::listMembers,
        "compile-time-generated requirePermission(\"member:list\") must reject anonymous calls");
  }

  // ── @RequiresAnyPermission (OR semantics) ───────────────────────

  @Test
  @DisplayName("LIBRARIAN can invite via member:invite (any-of branch)")
  void librarianCanInvite() {
    flow.login(new Credentials("librarian", "librarian"), "librarian");
    members.addMember("bob", "bob@example.org");
    assertTrue(members.listMembers().contains("bob"),
        "invite must succeed — LIBRARIAN holds member:invite (one of the candidates)");
  }

  @Test
  @DisplayName("MEMBER cannot invite (neither member:add nor member:invite granted)")
  void memberCannotInvite() {
    flow.login(new Credentials("alice", "alice"), "alice");
    assertThrows(AccessDeniedException.class,
        () -> members.addMember("eve", "eve@example.org"),
        "MEMBER lacks both candidate permissions, so requireAnyPermission(...) must deny");
  }

  // ── @RequiresAllPermissions (AND semantics) ─────────────────────

  @Test
  @DisplayName("ADMIN can remove a member (both member:remove and member:audit-log held)")
  void adminCanRemoveMember() {
    flow.login(new Credentials("admin", "admin"), "admin");
    members.addMember("charlie", "charlie@example.org");
    members.removeMember("charlie");
    assertFalse(members.listMembers().contains("charlie"),
        "ADMIN holds both required permissions — removal must succeed");
  }

  @Test
  @DisplayName("LIBRARIAN cannot remove a member (missing member:audit-log)")
  void librarianCannotRemoveMember() {
    flow.login(new Credentials("librarian", "librarian"), "librarian");
    members.addMember("dave", "dave@example.org");
    assertThrows(AccessDeniedException.class,
        () -> members.removeMember("dave"),
        "requireAllPermissions(...) demands every name; LIBRARIAN lacks member:audit-log");
  }

  // ── @RequiresRole (single role) ─────────────────────────────────

  @Test
  @DisplayName("ADMIN can resetAll() (single-role path)")
  void adminCanReset() {
    flow.login(new Credentials("admin", "admin"), "admin");
    members.addMember("erin", "erin@example.org");
    members.resetAll();
    assertEquals(0, members.listMembers().size(),
        "ADMIN must be allowed to drop every entry");
  }

  @Test
  @DisplayName("LIBRARIAN cannot resetAll() — role check is strictly ADMIN")
  void librarianCannotReset() {
    flow.login(new Credentials("librarian", "librarian"), "librarian");
    assertThrows(AccessDeniedException.class, members::resetAll,
        "requireRole(\"ADMIN\") must reject any non-ADMIN subject");
  }
}
