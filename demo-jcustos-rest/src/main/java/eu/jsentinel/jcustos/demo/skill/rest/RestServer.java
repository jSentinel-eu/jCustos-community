package eu.jsentinel.jcustos.demo.skill.rest;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.dx.rest.bootstrap.RestSecurity;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import com.sun.net.httpserver.HttpServer;
import eu.jsentinel.jcustos.demo.skill.rest.security.bootstrap.BootstrapBuilder;
import eu.jsentinel.jcustos.demo.skill.rest.handlers.AuditHandler;
import eu.jsentinel.jcustos.demo.skill.rest.handlers.AuthHandler;
import eu.jsentinel.jcustos.demo.skill.rest.handlers.SessionsHandler;
import eu.jsentinel.jcustos.demo.skill.rest.handlers.UsersHandler;
import eu.jsentinel.jcustos.demo.skill.rest.security.MyRestSubjectResolver;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.InMemoryUserDirectory;
import eu.jsentinel.jcustos.demo.skill.rest.security.services.MyAuthenticationService;
import eu.jsentinel.jcustos.demo.skill.rest.security.services.MyAuthorizationService;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;

/**
 * Standalone REST server (JDK {@link HttpServer}, no servlet
 * container). Layer-1 minimum: in-memory users + tokens.
 *
 * <p>Binds to the loopback interface only (JS-SEC-137) — put a TLS
 * reverse proxy in front before exposing it. Deny-by-default is on:
 * every handler carries a restriction or {@code @PublicRoute}.
 *
 * <p>Start with {@code mvn exec:java} or {@code java -cp ... RestServer}.
 * The user directory starts empty; for a local try-out start with
 * {@code -Djcustos.demo.insecure-seed-accounts=true} to get the
 * fixed-password accounts {@code admin/admin} and {@code user/user}
 * (refused outside {@code DEVELOPMENT} mode).
 */
public final class RestServer implements HasLogger {

  public static final int DEFAULT_PORT = 8081;

  /** Bootstrap mode of this server. */
  public static final JCustosBootstrapMode MODE = JCustosBootstrapMode.DEVELOPMENT;

  private final HttpServer http;
  private final int port;

  private RestServer(HttpServer http, int port) {
    this.http = http;
    this.port = port;
  }

  public static RestServer start(int port) throws IOException {
    if (InMemoryUserDirectory.insecureSeedAccountsRequested()
        && MODE != JCustosBootstrapMode.DEVELOPMENT) {
      throw new IllegalStateException(InMemoryUserDirectory.INSECURE_SEED_ACCOUNTS_PROPERTY
          + " is a development switch and is refused in " + MODE + " mode");
    }
    MyRestSubjectResolver resolver = new MyRestSubjectResolver();

    JCustosRuntime runtime = BootstrapBuilder.apply(
        RestSecurity.bootstrap()
            .mode(MODE)
            .denyByDefault(true)
            .authentication(new MyAuthenticationService())
            .authorization(new MyAuthorizationService())
            .subjectResolver(resolver)
    ).install();
    HasLogger.staticLogger().info("{}", runtime.log());

    Router router = new Router(resolver, routes());

    HttpServer server = HttpServer.create(
        new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 0);
    server.createContext("/api", router);
    server.start();
    return new RestServer(server, server.getAddress().getPort());
  }

  /** The route table. Restrictions are annotations on the handler methods. */
  public static List<Router.Route> routes() {
    return new Router.Builder()
        .add("POST", "/api/auth/login", AuthHandler.class, "login")
        .add("POST", "/api/auth/logout", AuthHandler.class, "logout")
        .add("GET", "/api/whoami", AuthHandler.class, "whoami")
        .add("GET", "/api/audit", AuditHandler.class, "list")
        .add("GET", "/api/sessions", SessionsHandler.class, "list")
        .add("DELETE", "/api/sessions/{ref}", SessionsHandler.class, "revoke")
        .add("GET", "/api/users", UsersHandler.class, "list")
        .add("POST", "/api/users", UsersHandler.class, "create")
        .add("DELETE", "/api/users/{id}", UsersHandler.class, "delete")
        .add("POST", "/api/users/{id}/roles/{role}", UsersHandler.class, "assignRole")
        .add("DELETE", "/api/users/{id}/roles/{role}", UsersHandler.class, "revokeRole")
        .build();
  }

  public int port() {
    return port;
  }

  public InetSocketAddress address() {
    return http.getAddress();
  }

  public void stop() {
    http.stop(0);
  }

  public static void main(String[] args) throws IOException {
    int port = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_PORT;
    RestServer server = start(port);
    String base = "http://" + server.address().getHostString() + ":" + server.port();
    System.out.println("REST server listening on " + base + " (loopback only)");
    if (InMemoryUserDirectory.insecureSeedAccountsRequested()) {
      System.out.println("Try: curl -X POST -H 'Content-Type: application/json' \\");
      System.out.println("       -d '{\"username\":\"admin\",\"password\":\"admin\"}' \\");
      System.out.println("       " + base + "/api/auth/login");
    } else {
      System.out.println("No users yet. For a local try-out restart with -D"
          + InMemoryUserDirectory.INSECURE_SEED_ACCOUNTS_PROPERTY + "=true (DEVELOPMENT only).");
    }
    System.out.println("Press Ctrl+C to stop.");
    Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
  }
}
