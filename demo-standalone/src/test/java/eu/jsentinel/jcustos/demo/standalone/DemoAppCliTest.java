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

import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives {@link DemoApp} end-to-end via in-memory streams. Pins the
 * full CLI flow: login prompt, command dispatch, denial output, and
 * the final logout.
 */
@DisplayName("DemoApp — CLI flow")
class DemoAppCliTest {

  @BeforeAll
  static void seedDemoAccounts() {
    // JS-SEC-137: the fixed-password accounts exist only on explicit request.
    UserDirectory.instance().seedInsecureDemoAccounts();
  }

  @AfterEach
  void clearSubject() {
    // Any test that gets through login leaves a thread-local binding;
    // wipe it so the next test starts clean.
    SubjectStores.subjectStore().deleteCurrentSubject(User.class);
  }

  // ── Login ──────────────────────────────────────────────────────

  @Test
  @DisplayName("Failed login: header + 'Login failed.' + no command loop")
  void failedLogin() throws Exception {
    String out = runWith("nobody\nbad-password\n");
    assertTrue(out.contains("=== Library CLI ==="),
        "header must be printed: " + out);
    assertTrue(out.contains("Login failed."),
        "rejected login must print 'Login failed.': " + out);
    assertFalse(out.contains("Welcome,"),
        "no welcome banner after a failed login");
    assertFalse(SubjectStores.subjectStore().currentSubject(User.class).isPresent(),
        "failed login must not bind a subject");
  }

  // ── Successful login + commands ────────────────────────────────

  @Test
  @DisplayName("alice (MEMBER) can list, borrow, return; add/remove are denied")
  void aliceMemberFlow() throws Exception {
    String script = String.join("\n",
        "alice",
        "alice",
        "list",
        "borrow Effective Java",
        "return Effective Java",
        "add NewBook",
        "remove Clean Code",
        "quit") + "\n";
    String out = runWith(script);

    assertTrue(out.contains("Welcome, Alice"),
        "successful login must greet the user: " + out);
    assertTrue(out.contains("- Effective Java"),
        "list command must show 'Effective Java'");
    assertTrue(out.contains("OK — borrowed Effective Java"),
        "borrow command must report success");
    assertTrue(out.contains("OK — returned Effective Java"),
        "return command must report success");
    assertTrue(out.contains("DENIED"),
        "MEMBER must be denied add/remove; got: " + out);
    assertTrue(out.contains("Logged out."),
        "quit must print the logout banner");
  }

  @Test
  @DisplayName("admin can add and remove books")
  void adminFullFlow() throws Exception {
    String script = String.join("\n",
        "admin",
        "admin",
        "add NewBook",
        "remove NewBook",
        "list",
        "quit") + "\n";
    String out = runWith(script);

    assertTrue(out.contains("OK — added NewBook"));
    assertTrue(out.contains("OK — removed NewBook"));
    assertFalse(out.contains("- NewBook"),
        "after remove, NewBook must be gone from the list output");
  }

  @Test
  @DisplayName("Library mutation error (borrow unknown title) surfaces as ERROR")
  void runtimeErrorIsCaught() throws Exception {
    String script = String.join("\n",
        "alice",
        "alice",
        "borrow NotInCatalog",
        "quit") + "\n";
    String out = runWith(script);

    assertTrue(out.contains("ERROR"),
        "runtime errors from the delegate must surface as ERROR; got: " + out);
  }

  // ── Built-in commands ──────────────────────────────────────────

  @Test
  @DisplayName("'help' command prints the command list")
  void helpCommand() throws Exception {
    String script = String.join("\n",
        "alice",
        "alice",
        "help",
        "quit") + "\n";
    String out = runWith(script);

    assertTrue(out.contains("borrow <title>"),
        "help must include the borrow command syntax");
    assertTrue(out.contains("quit"));
  }

  @Test
  @DisplayName("Unknown commands print a hint")
  void unknownCommand() throws Exception {
    String script = String.join("\n",
        "alice",
        "alice",
        "bogus",
        "quit") + "\n";
    String out = runWith(script);

    assertTrue(out.contains("Unknown command"),
        "unknown command must surface the 'Unknown command' hint");
  }

  @Test
  @DisplayName("CLI prints the 'Username: ', 'Password: ' and '> ' prompts")
  void promptsArePrinted() throws Exception {
    String out = runWith("alice\nalice\nquit\n");

    assertTrue(out.contains("Username: "),
        "username prompt must be printed: " + out);
    assertTrue(out.contains("Password: "),
        "password prompt must be printed: " + out);
    assertTrue(out.contains("> "),
        "command prompt '> ' must be printed: " + out);
  }

  @Test
  @DisplayName("After quit the SubjectStore no longer has a User binding (logout fired)")
  void quitTriggersLogout() throws Exception {
    runWith("alice\nalice\nquit\n");
    assertFalse(SubjectStores.subjectStore().currentSubject(User.class).isPresent(),
        "the logout in run() must clear the SubjectStore on exit");
  }

  @Test
  @DisplayName("After 'return', the same title becomes borrow-able again — proves returnBook ran")
  void returnReleasesTheBook() throws Exception {
    String script = String.join("\n",
        "alice",
        "alice",
        "borrow Effective Java",
        "return Effective Java",
        "borrow Effective Java",
        "quit") + "\n";
    String out = runWith(script);

    long borrows = out.lines()
        .filter(l -> l.contains("OK — borrowed Effective Java"))
        .count();
    org.junit.jupiter.api.Assertions.assertEquals(2, borrows,
        "Effective Java must be borrowable twice once it has been returned in between; got output: " + out);
  }

  @Test
  @DisplayName("Empty lines in the command loop are skipped")
  void emptyLinesAreSkipped() throws Exception {
    String script = String.join("\n",
        "alice",
        "alice",
        "",
        "   ",
        "list",
        "quit") + "\n";
    String out = runWith(script);

    assertTrue(out.contains("- Effective Java"),
        "list command must still run after blank lines");
  }

  // ── Helpers ────────────────────────────────────────────────────

  private static String runWith(String stdin) throws Exception {
    BufferedReader in = new BufferedReader(new StringReader(stdin));
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    try (PrintStream out = new PrintStream(buf, true, StandardCharsets.UTF_8)) {
      new DemoApp(in, out).run();
    }
    return buf.toString(StandardCharsets.UTF_8);
  }
}
