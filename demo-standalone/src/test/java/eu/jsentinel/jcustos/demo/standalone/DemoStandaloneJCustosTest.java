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
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.standalone.SecuredProxy;
import eu.jsentinel.jcustos.standalone.StandaloneLoginFlow;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives the standalone-demo flow end-to-end: SPI resolves the right
 * services, login binds the subject, the dynamic-proxy proxy enforces
 * {@code @RequiresPermission} / {@code @RequiresRole} on each call.
 */
@DisplayName("Demo standalone — login + proxy-secured library service")
class DemoStandaloneJCustosTest {

  @BeforeAll
  static void seedDemoAccounts() {
    // JS-SEC-137: the fixed-password accounts exist only on explicit request.
    UserDirectory.instance().seedInsecureDemoAccounts();
  }

  private final StandaloneLoginFlow<Credentials, User> flow = new StandaloneLoginFlow<>();
  private final LibraryService library = SecuredProxy.wrap(
      LibraryService.class, new InMemoryLibraryService());

  @AfterEach
  void logoutAndClearStore() {
    flow.logout();
  }

  // ── Login ──────────────────────────────────────────────────────

  @Test
  @DisplayName("Valid credentials bind a User into the SubjectStore")
  void loginSuccess() {
    StandaloneLoginFlow.LoginResult<User> result = flow.login(
        new Credentials("alice", "alice"), "alice");

    StandaloneLoginFlow.LoginResult.Success<User> success =
        assertInstanceOf(StandaloneLoginFlow.LoginResult.Success.class, result);
    assertEquals("alice", success.subject().username());
    assertTrue(SubjectStores.subjectStore().currentSubject(User.class).isPresent(),
        "successful login must bind a User into the SubjectStore");
  }

  @Test
  @DisplayName("Wrong password yields Rejected and leaves the SubjectStore empty")
  void loginRejected() {
    StandaloneLoginFlow.LoginResult<User> result = flow.login(
        new Credentials("alice", "WRONG"), "alice");

    assertInstanceOf(StandaloneLoginFlow.LoginResult.Rejected.class, result);
    assertFalse(SubjectStores.subjectStore().currentSubject(User.class).isPresent(),
        "a rejected login must NOT bind any subject");
  }

  @Test
  @DisplayName("logout removes the bound subject")
  void logoutClearsSubject() {
    flow.login(new Credentials("alice", "alice"), "alice");
    assertTrue(SubjectStores.subjectStore().currentSubject(User.class).isPresent());

    flow.logout();

    assertFalse(SubjectStores.subjectStore().currentSubject(User.class).isPresent(),
        "logout must remove the subject from the store");
  }

  // ── Proxy-enforced access decisions ────────────────────────────

  @Test
  @DisplayName("MEMBER can list and borrow but not add/remove books")
  void memberAccessMatrix() {
    flow.login(new Credentials("alice", "alice"), "alice");

    // permission-based — allowed
    assertEquals(3, library.listBooks().size(),
        "MEMBER must be allowed to list books");
    library.borrowBook("Effective Java");

    // permission-based — denied (book:add not granted to MEMBER)
    assertThrows(AccessDeniedException.class,
        () -> library.addBook("New Book"),
        "MEMBER must not be allowed to add books");

    // role-based — denied (removeBook is @RequiresRole(\"ADMIN\"))
    assertThrows(AccessDeniedException.class,
        () -> library.removeBook("Effective Java"),
        "MEMBER must not be allowed to remove books");
  }

  @Test
  @DisplayName("LIBRARIAN can add books but cannot remove them (ADMIN-only)")
  void librarianAccessMatrix() {
    flow.login(new Credentials("librarian", "librarian"), "librarian");

    library.addBook("Operating Systems");
    assertTrue(library.listBooks().contains("Operating Systems"),
        "addBook must have actually mutated the catalog");

    assertThrows(AccessDeniedException.class,
        () -> library.removeBook("Effective Java"),
        "LIBRARIAN must not be allowed to remove books");
  }

  @Test
  @DisplayName("ADMIN can do everything, including removeBook")
  void adminCanRemove() {
    flow.login(new Credentials("admin", "admin"), "admin");

    library.addBook("Distributed Systems");
    library.removeBook("Distributed Systems");
    assertFalse(library.listBooks().contains("Distributed Systems"),
        "ADMIN must be able to remove a book");
  }

  // ── Anonymous (no login) ───────────────────────────────────────

  @Test
  @DisplayName("Without a bound subject every annotated call is denied")
  void anonymousIsDenied() {
    assertThrows(AccessDeniedException.class, library::listBooks,
        "anonymous calls to @RequiresPermission methods must be denied");
    assertThrows(AccessDeniedException.class,
        () -> library.borrowBook("Effective Java"),
        "anonymous calls to @RequiresPermission methods must be denied");
    assertThrows(AccessDeniedException.class,
        () -> library.removeBook("Effective Java"),
        "anonymous calls to @RequiresRole methods must be denied");
  }
}
