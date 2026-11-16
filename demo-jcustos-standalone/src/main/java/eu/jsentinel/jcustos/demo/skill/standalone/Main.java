package eu.jsentinel.jcustos.demo.skill.standalone;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AccessDeniedException;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationUnavailableException;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.standalone.bootstrap.StandaloneSecurity;
import eu.jsentinel.jcustos.standalone.SecuredProxy;
import eu.jsentinel.jcustos.standalone.StandaloneLoginFlow;
import eu.jsentinel.jcustos.demo.skill.standalone.security.model.Credentials;
import eu.jsentinel.jcustos.demo.skill.standalone.security.model.InMemoryUserDirectory;
import eu.jsentinel.jcustos.demo.skill.standalone.security.model.User;
import eu.jsentinel.jcustos.demo.skill.standalone.services.DocumentService;
import eu.jsentinel.jcustos.demo.skill.standalone.services.InMemoryDocumentService;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ServiceLoader;

/**
 * Interactive CLI demoing the standalone adapter. Login binds the
 * subject to a thread-local; every command method on
 * {@link DocumentService} is gated by {@code SecuredProxy.wrap(...)},
 * with deny-by-default on.
 *
 * <p>The user directory starts empty; for a local try-out start with
 * {@code -Djcustos.demo.insecure-seed-accounts=true} to get the
 * fixed-password accounts {@code admin/admin} and {@code user/user}
 * (refused outside {@code DEVELOPMENT} mode, JS-SEC-137).
 */
public final class Main implements HasLogger {

  /** Bootstrap mode of this CLI. */
  public static final JCustosBootstrapMode MODE = JCustosBootstrapMode.DEVELOPMENT;

  private final BufferedReader in;
  private final PrintStream out;
  private final StandaloneLoginFlow<Credentials, User> loginFlow;
  private final DocumentService documents;

  public Main(BufferedReader in, PrintStream out) {
    this.in = in;
    this.out = out;
    this.loginFlow = new StandaloneLoginFlow<>();
    this.documents = SecuredProxy.wrap(DocumentService.class, new InMemoryDocumentService());
  }

  public static void main(String[] args) throws Exception {
    if (InMemoryUserDirectory.insecureSeedAccountsRequested()
        && MODE != JCustosBootstrapMode.DEVELOPMENT) {
      throw new IllegalStateException(InMemoryUserDirectory.INSECURE_SEED_ACCOUNTS_PROPERTY
          + " is a development switch and is refused in " + MODE + " mode");
    }
    installSecurity();
    BufferedReader reader = new BufferedReader(
        new InputStreamReader(System.in, StandardCharsets.UTF_8));
    new Main(reader, System.out).run();
  }

  /** Installs the security stack; {@link #main} calls it before the CLI starts. */
  static JCustosRuntime installSecurity() {
    AuthenticationService<?, ?> authn = ServiceLoader.load(AuthenticationService.class)
        .findFirst().orElseThrow();
    AuthorizationService<?> authz = ServiceLoader.load(AuthorizationService.class)
        .findFirst().orElseThrow();
    JCustosRuntime runtime = eu.jsentinel.jcustos.demo.skill.standalone.security.bootstrap.BootstrapBuilder.apply(
        StandaloneSecurity.bootstrap()
            .mode(MODE)
            .denyByDefault(true)
            .authentication(authn)
            .authorization(authz)
    ).install();
    HasLogger.staticLogger().info("{}", runtime.log());
    return runtime;
  }

  void run() throws IOException {
    out.println("=== jCustos Standalone Demo ===");
    if (InMemoryUserDirectory.insecureSeedAccountsRequested()) {
      out.println("Seeded users: admin/admin (full), user/user (doc:list only)");
    } else {
      out.println("No users yet. For a local try-out restart with -D"
          + InMemoryUserDirectory.INSECURE_SEED_ACCOUNTS_PROPERTY + "=true (DEVELOPMENT only).");
    }
    User subject = promptLogin();
    if (subject == null) {
      out.println("Login failed. Bye.");
      return;
    }
    out.println("Welcome, " + subject.name() + " — roles=" + subject.roles());
    printHelp();
    loop(subject);
    loginFlow.logout();
    out.println("Bye.");
  }

  private User promptLogin() throws IOException {
    out.print("Username: ");
    out.flush();
    String username = in.readLine();
    if (username == null) return null;
    out.print("Password: ");
    out.flush();
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
        out.println("Locked. Try again in "
            + l.decision().remaining().toSeconds() + " s.");
        yield null;
      }
    };
  }

  private void printHelp() {
    out.println("""
        Commands:
          list             list documents       (doc:list)
          create <title>   create a document    (doc:create)
          delete <title>   delete a document    (doc:delete)
          audit            show last events     (audit:read)
          whoami           display subject info
          help             this help
          quit             exit
        """);
  }

  private void loop(User subject) throws IOException {
    String line;
    while (true) {
      out.print("> ");
      out.flush();
      line = in.readLine();
      if (line == null || line.equalsIgnoreCase("quit")) return;
      line = line.trim();
      if (line.isEmpty()) continue;
      String[] parts = line.split("\\s+", 2);
      String cmd = parts[0].toLowerCase();
      String arg = parts.length > 1 ? parts[1] : "";
      try {
        dispatch(subject, cmd, arg);
      } catch (AccessDeniedException denied) {
        out.println("DENIED — " + denied.getMessage());
      } catch (RuntimeException failure) {
        out.println("ERROR — " + failure.getMessage());
      }
    }
  }

  private void dispatch(User subject, String cmd, String arg) {
    switch (cmd) {
      case "list" -> documents.list().forEach(d -> out.println("  - " + d));
      case "create" -> {
        documents.create(arg);
        out.println("OK — created " + arg);
      }
      case "delete" -> {
        documents.delete(arg);
        out.println("OK — deleted " + arg);
      }
      case "audit" -> {
        // Reading the audit ring buffer is itself a permission-gated
        // operation when called against a wrapped service — here we
        // demo the raw query path and check permission inline.
        if (!subject.roles().stream().anyMatch(r -> r.name().equals("ADMIN"))) {
          out.println("DENIED — audit:read");
          return;
        }
        for (AuditEvent event : JCustosServiceResolver.securityAuditService().query(AuditQuery.all())) {
          out.println("  " + event.timestamp() + " " + event.getClass().getSimpleName());
        }
      }
      case "whoami" -> out.println("id=" + subject.id()
          + " name=" + subject.name() + " roles=" + subject.roles());
      case "help" -> printHelp();
      default -> out.println("Unknown. Try 'help'.");
    }
  }
}
