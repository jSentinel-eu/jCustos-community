package eu.jsentinel.jcustos.demo.skill.rest;

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.dx.rest.bootstrap.RestSecurity;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import eu.jsentinel.jcustos.demo.skill.rest.handlers.AuditHandler;
import eu.jsentinel.jcustos.demo.skill.rest.handlers.AuthHandler;
import eu.jsentinel.jcustos.demo.skill.rest.handlers.BootstrapHandler;
import eu.jsentinel.jcustos.demo.skill.rest.handlers.SessionsHandler;
import eu.jsentinel.jcustos.demo.skill.rest.handlers.UsersHandler;
import eu.jsentinel.jcustos.demo.skill.rest.security.MyRestSubjectResolver;
import eu.jsentinel.jcustos.demo.skill.rest.security.bootstrap.BootstrapBuilder;
import eu.jsentinel.jcustos.demo.skill.rest.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.skill.rest.security.services.MyAuthenticationService;
import eu.jsentinel.jcustos.demo.skill.rest.security.services.MyAuthorizationService;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;

/**
 * Persistence-layer REST server — same bootstrap-chain mechanism as
 * layer 1 (delegates audit / sessions / credentials to
 * {@link BootstrapBuilder#apply(eu.jsentinel.jcustos.dx.rest.bootstrap.RestJCustosBootstrap)}),
 * but adds the {@code /api/setup} route + a bootstrap-required guard
 * that returns 503 on every other endpoint until the first admin is
 * provisioned.
 *
 * <p>Bootstrap-chain configuration is contributed by
 * {@code PersistenceBootstrapExtension} (Eclipse-Store storeBacked
 * for audit + sessions). Hardening, if applied, adds a separate
 * {@code HardeningBootstrapExtension} that stacks alongside this
 * one — both contribute to the same {@code .audit / .sessions /
 * .credentials} sub-builders, no conflict.
 *
 * <p>Binds to the loopback interface only (JS-SEC-137) — put a TLS
 * reverse proxy in front before exposing it. Deny-by-default is on:
 * every handler carries a restriction or {@code @PublicRoute}.
 */
public final class RestServer implements HasLogger {

  public static final int DEFAULT_PORT = 8083;

  /** Bootstrap mode of this server. */
  public static final JCustosBootstrapMode MODE = JCustosBootstrapMode.DEVELOPMENT;

  private final HttpServer http;
  private final int port;

  private RestServer(HttpServer http, int port) {
    this.http = http;
    this.port = port;
  }

  public static RestServer start(int port) throws IOException {
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
    // After install(): the first administrator is hashed with the configured pipeline.
    BootstrapWiring.instance();

    Router router = new Router(resolver, routes());
    HttpHandler guarded = exchange -> {
      String path = exchange.getRequestURI().getPath();
      if (BootstrapWiring.instance().stateService().bootstrapRequired()
          && !path.equals("/api/setup")) {
        Router.respondJson(exchange, HttpStatus.SERVICE_UNAVAILABLE.code(), Json.encode(Map.of(
            "error", "bootstrap required",
            "setupEndpoint", "POST /api/setup")));
        exchange.close();
        return;
      }
      router.handle(exchange);
    };

    HttpServer server = HttpServer.create(
        new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 0);
    server.createContext("/api", guarded);
    server.start();
    return new RestServer(server, server.getAddress().getPort());
  }

  /** The route table. Restrictions are annotations on the handler methods. */
  public static List<Router.Route> routes() {
    return new Router.Builder()
        .add("POST", "/api/setup", BootstrapHandler.class, "setup")
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
    System.out.println("REST server listening on http://" + server.address().getHostString()
        + ":" + server.port() + " (loopback only)");
    System.out.println("First start? Look on stdout for the bootstrap token,");
    System.out.println("then POST it to /api/setup with the admin's chosen username/password.");
    Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
  }
}
