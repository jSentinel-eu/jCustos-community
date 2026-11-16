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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.AccessDeniedException;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationUnavailableException;
import eu.jsentinel.jcustos.dx.diagnostics.JCustosDiagnostics;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.standalone.bootstrap.StandaloneSecurity;
import eu.jsentinel.jcustos.standalone.SecuredProxy;
import eu.jsentinel.jcustos.standalone.StandaloneLoginFlow;

import java.util.ServiceLoader;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Minimal interactive CLI demonstrating the standalone security
 * adapter. Showcases both enforcement paths side by side:
 *
 * <ul>
 *   <li><b>Runtime / dynamic proxy</b>: {@link LibraryService} is an
 *       interface; {@code SecuredProxy.wrap(LibraryService.class,
 *       impl)} produces a proxy that consults the framework
 *       evaluators on every call.</li>
 *   <li><b>Compile-time / annotation processor</b>:
 *       {@link MemberDirectory} is a concrete class annotated with
 *       {@code @Secured}; the {@code security-processor} module
 *       emits a {@code MemberDirectorySecured} subclass during
 *       compilation, the demo instantiates that subclass, and every
 *       guarded method calls into {@code JCustosEnforcer} before
 *       delegating to {@code super}.</li>
 * </ul>
 *
 * <p>Flow:
 * <ol>
 *   <li>Prompt for username + password.</li>
 *   <li>Authenticate via the SPI-resolved
 *       {@code AuthenticationService}; on success the
 *       {@code StandaloneLoginFlow} binds the subject into the
 *       thread-local {@code SubjectStore}.</li>
 *   <li>Read CLI commands. Both wrappers throw
 *       {@link AccessDeniedException} when an action is not allowed —
 *       the loop catches it and prints a denial message.</li>
 * </ol>
 *
 * <p>Run with: {@code mvn -pl demo-standalone exec:java -Dexec.mainClass=...}
 * or just from your IDE.
 */
public final class DemoApp {

  /** Bootstrap mode of this CLI. */
  public static final JCustosBootstrapMode MODE = JCustosBootstrapMode.DEVELOPMENT;

  private final BufferedReader in;
  private final java.io.PrintStream out;
  private final StandaloneLoginFlow<Credentials, User> loginFlow;
  private final LibraryService library;
  private final MemberDirectory members;

  public DemoApp(BufferedReader in, java.io.PrintStream out) {
    this.in = in;
    this.out = out;
    this.loginFlow = new StandaloneLoginFlow<>();
    // Runtime path: dynamic-proxy enforcement on an interface.
    this.library = SecuredProxy.wrap(LibraryService.class, new InMemoryLibraryService());
    // Compile-time path: annotation-processor-generated subclass on a
    // concrete class. Instantiating MemberDirectorySecured wires every
    // guarded method through JCustosEnforcer.
    this.members = new MemberDirectorySecured();
  }

  public static void main(String[] args) throws Exception {
    // V00.72 fluent bootstrap. The AuthN/AuthZ services are discovered
    // through @JCustosAutoService and pulled here so the bootstrap can
    // wire them explicitly into JCustosServiceResolver and produce a
    // JCustosRuntime that lists every active service.
    var authn = ServiceLoader.load(
            eu.jsentinel.jcustos.authentication.AuthenticationService.class)
        .findFirst().orElseThrow(() -> new IllegalStateException(
            "No AuthenticationService registered (expected DemoAuthenticationService via @JCustosAutoService)"));
    var authz = ServiceLoader.load(
            eu.jsentinel.jcustos.authorization.api.AuthorizationService.class)
        .findFirst().orElseThrow(() -> new IllegalStateException(
            "No AuthorizationService registered (expected DemoAuthorizationService via @JCustosAutoService)"));

    // V00.73 fluent bootstrap. The .audit(...) sub-builder adds an
    // in-memory RingBuffer + a LoggingAuditSink so the CLI demo's
    // diagnose command can show audit events end-to-end without any
    // additional wiring on the consumer side.
    if (UserDirectory.insecureSeedAccountsRequested() && MODE != JCustosBootstrapMode.DEVELOPMENT) {
      throw new IllegalStateException(UserDirectory.INSECURE_SEED_ACCOUNTS_PROPERTY
          + " is a development switch and is refused in " + MODE + " mode");
    }
    JCustosRuntime runtime = StandaloneSecurity.bootstrap()
        .mode(MODE)
        .authentication(authn)
        .authorization(authz)
        .audit(a -> a.ringBuffer(256).logging())
        .install();
    // Startup banner goes through the framework's SLF4J pipeline so the
    // operator can route it like every other log line. The interactive
    // CLI prompts below stay on System.out because they're the program's
    // user interface, not a log stream.
    HasLogger.staticLogger().info("{}", runtime.log());

    // Inspect the broader diagnostics surface (DiagnosticContributor SPI).
    var report = JCustosDiagnostics.inspect();
    var processorReport = report.processorReport();
    boolean hasProcessorEntries = !processorReport.wrappers().isEmpty()
        || !processorReport.warnings().isEmpty();
    if (!report.missing().isEmpty() || !report.duplicates().isEmpty()
        || !report.warnings().isEmpty() || hasProcessorEntries) {
      System.out.println("--- JCustosDiagnostics ---");
      report.missing().forEach(m -> System.out.println("  missing: " + m.spi().getSimpleName() + " — " + m.reason()));
      report.duplicates().forEach(d -> System.out.println("  duplicate: " + d.spi().getSimpleName()));
      report.warnings().forEach(w -> System.out.println("  " + w.code() + ": " + w.message()));
      // V00.73: wrapper-index reader now sees the entries the
      // security-processor wrote at compile time.
      processorReport.wrappers().forEach(w -> System.out.println(
          "  wrapper: " + w.sourceType().getName()
              + "\n           -> " + w.generatedType().getName()
              + "\n           methods=" + w.delegatedMethods()));
      processorReport.warnings().forEach(w -> System.out.println(
          "  processor-warning: " + w.code() + ": " + w.message()));
    }

    BufferedReader reader = new BufferedReader(
        new InputStreamReader(System.in, StandardCharsets.UTF_8));
    new DemoApp(reader, System.out).run();
  }

  void run() throws Exception {
    out.println("=== Library CLI ===");
    if (UserDirectory.insecureSeedAccountsRequested()) {
      out.println("Seeded users: admin/admin, librarian/librarian, alice/alice");
    } else {
      out.println("No users yet. For a local try-out restart with -D"
          + UserDirectory.INSECURE_SEED_ACCOUNTS_PROPERTY + "=true (DEVELOPMENT only).");
    }
    User user = promptLogin();
    if (user == null) {
      out.println("Login failed. Goodbye.");
      return;
    }
    out.println("Welcome, " + user.displayName() + ". Roles: " + user.roles());
    printHelp();
    loop();
    loginFlow.logout();
    out.println("Logged out. Bye.");
  }

  private User promptLogin() throws java.io.IOException {
    out.print("Username: "); out.flush();
    String username = in.readLine();
    if (username == null) return null;
    out.print("Password: "); out.flush();
    String password = in.readLine();
    if (password == null) return null;
    StandaloneLoginFlow.LoginResult<User> result;
    try {
      result = loginFlow.login(new Credentials(username, password), username);
    } catch (CredentialVerificationUnavailableException shed) {
      // JS-SEC-126: the check was shed under load - nothing was counted; not a wrong password.
      out.println("Login temporarily unavailable. Try again later.");
      return null;
    }
    // LockedOut is also the answer when the account was locked while the
    // password was being checked (JS-SEC-123): no subject is bound then.
    return switch (result) {
      case StandaloneLoginFlow.LoginResult.Success<User> s -> s.subject();
      case StandaloneLoginFlow.LoginResult.Rejected<User> ignored -> null;
      case StandaloneLoginFlow.LoginResult.LockedOut<User> l -> {
        out.println("Account locked. Try again in "
            + l.decision().remaining().toSeconds() + " s.");
        yield null;
      }
    };
  }

  private void printHelp() {
    out.println("""
        Commands:
          list                       -- list books
          borrow <title>             -- borrow a book
          return <title>             -- return a book
          add <title>                -- add a book to the catalog (LIBRARIAN+)
          remove <title>             -- remove a book from the catalog (ADMIN)
          members                    -- list registered members
          invite <name> <email>      -- register/invite a member (LIBRARIAN+)
          remove-member <name>       -- remove a member (ADMIN, audited)
          reset-members              -- drop every member (ADMIN)
          help                       -- this help
          quit                       -- exit
        """);
  }

  private void loop() throws java.io.IOException {
    String line;
    while (true) {
      out.print("> "); out.flush();
      line = in.readLine();
      if (line == null || line.equalsIgnoreCase("quit")) return;
      line = line.trim();
      if (line.isEmpty()) continue;
      String[] parts = line.split("\\s+", 2);
      String cmd = parts[0].toLowerCase();
      String arg = parts.length > 1 ? parts[1] : "";
      try {
        dispatch(cmd, arg);
      } catch (AccessDeniedException denied) {
        out.println("DENIED — " + denied.getMessage());
      } catch (RuntimeException failure) {
        out.println("ERROR — " + failure.getMessage());
      }
    }
  }

  private void dispatch(String cmd, String arg) {
    switch (cmd) {
      case "list" -> library.listBooks().forEach(b -> out.println("  - " + b));
      case "borrow" -> {
        library.borrowBook(arg);
        out.println("OK — borrowed " + arg);
      }
      case "return" -> {
        library.returnBook(arg);
        out.println("OK — returned " + arg);
      }
      case "add" -> {
        library.addBook(arg);
        out.println("OK — added " + arg);
      }
      case "remove" -> {
        library.removeBook(arg);
        out.println("OK — removed " + arg);
      }
      case "members" -> members.listMembers().forEach(m -> out.println("  - " + m));
      case "invite" -> {
        String[] parts = arg.split("\\s+", 2);
        if (parts.length < 2 || parts[0].isEmpty() || parts[1].isEmpty()) {
          out.println("usage: invite <name> <email>");
          return;
        }
        members.addMember(parts[0], parts[1]);
        out.println("OK — invited " + parts[0] + " <" + parts[1] + ">");
      }
      case "remove-member" -> {
        members.removeMember(arg);
        out.println("OK — removed member " + arg);
      }
      case "reset-members" -> {
        members.resetAll();
        out.println("OK — member directory reset");
      }
      case "help" -> printHelp();
      default -> out.println("Unknown command. Try 'help'.");
    }
  }
}
