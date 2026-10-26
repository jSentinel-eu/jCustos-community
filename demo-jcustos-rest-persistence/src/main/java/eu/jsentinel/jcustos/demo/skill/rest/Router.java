package eu.jsentinel.jcustos.demo.skill.rest;

import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Composite {@link HttpHandler} that dispatches requests to method
 * handlers based on (HTTP method, path-prefix), performs the
 * {@code @RequiresPermission}-equivalent check via the resolved
 * {@link JCustosSubject}, and writes the JSON response.
 *
 * <p>Demo-level routing — no path parameter capture beyond the last
 * segment, no content-negotiation. Production swaps for any
 * Jersey/Spring/Vert.x router.
 */
public final class Router implements HttpHandler {

  private final RestSubjectResolver resolver;
  private final List<Route> routes;

  public Router(RestSubjectResolver resolver, List<Route> routes) {
    this.resolver = resolver;
    this.routes = List.copyOf(routes);
  }

  @Override
  public void handle(HttpExchange exchange) throws IOException {
    try {
      String method = exchange.getRequestMethod();
      String path = exchange.getRequestURI().getPath();
      Route match = routes.stream()
          .filter(r -> r.matches(method, path))
          .findFirst()
          .orElse(null);
      if (match == null) {
        respond(exchange, 404, "Not Found");
        return;
      }
      RestRequest req = restRequestFrom(exchange);
      Optional<JCustosSubject> subject = resolver.resolveSubject(req);
      if (match.requiredPermission != null) {
        if (subject.isEmpty()) {
          respond(exchange, 401, "Unauthorized");
          return;
        }
        if (!subject.get().permissions().contains(new PermissionName(match.requiredPermission))) {
          respond(exchange, 403, "Forbidden");
          return;
        }
      }
      match.handler.handle(exchange, subject.orElse(null));
    } catch (RuntimeException failure) {
      respond(exchange, 500, "Internal Server Error");
    }
  }

  // ── Builder ────────────────────────────────────────────────────

  /** Convenience accumulator for {@link Route} entries. */
  public static final class Builder {
    private final List<Route> routes = new java.util.ArrayList<>();

    public Builder add(String method, String pathPrefix, String requiredPermission, RouteHandler handler) {
      routes.add(new Route(method, pathPrefix, requiredPermission, handler));
      return this;
    }

    public Builder addPublic(String method, String pathPrefix, RouteHandler handler) {
      return add(method, pathPrefix, null, handler);
    }

    public List<Route> build() {
      return List.copyOf(routes);
    }
  }

  /** Handler signature with the resolved subject (or null for public routes). */
  @FunctionalInterface
  public interface RouteHandler {
    void handle(HttpExchange exchange, JCustosSubject subject) throws IOException;
  }

  /** Route record — method + path prefix + optional permission requirement. */
  public record Route(String method, String pathPrefix, String requiredPermission, RouteHandler handler) {

    boolean matches(String reqMethod, String reqPath) {
      return method.equalsIgnoreCase(reqMethod)
          && (reqPath.equals(pathPrefix)
              || reqPath.startsWith(pathPrefix + "/")
              || reqPath.startsWith(pathPrefix + "?"));
    }
  }

  // ── HttpExchange ↔ RestRequest bridge ──────────────────────────

  private static RestRequest restRequestFrom(HttpExchange exchange) {
    URI uri = exchange.getRequestURI();
    Map<String, String> headers = new HashMap<>();
    exchange.getRequestHeaders().forEach((k, v) -> {
      if (!v.isEmpty()) headers.put(k, v.get(0));
    });
    Map<String, String> query = parseQuery(uri.getQuery());
    String method = exchange.getRequestMethod();
    String path = uri.getPath();
    return new RestRequest() {
      /** JS-SEC-061: expose the connection peer; the ClientAddressResolver decides the client. */
      @Override
      public String remoteAddress() {
        var remote = exchange.getRemoteAddress();
        return remote == null || remote.getAddress() == null
            ? null : remote.getAddress().getHostAddress();
      }

      @Override
      public String method() {
        return method;
      }

      @Override
      public String path() {
        return path;
      }

      @Override
      public Map<String, String> headers() {
        return headers;
      }

      @Override
      public Map<String, String> queryParameters() {
        return query;
      }
    };
  }

  private static Map<String, String> parseQuery(String raw) {
    Map<String, String> out = new LinkedHashMap<>();
    if (raw == null || raw.isEmpty()) return out;
    for (String pair : raw.split("&")) {
      int eq = pair.indexOf('=');
      if (eq < 0) {
        out.put(pair, "");
      } else {
        out.put(pair.substring(0, eq), pair.substring(eq + 1));
      }
    }
    return out;
  }

  /** Writes a plain-text body with the given status. */
  public static void respond(HttpExchange exchange, int status, String body) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
    exchange.sendResponseHeaders(status, bytes.length);
    try (OutputStream os = exchange.getResponseBody()) {
      os.write(bytes);
    }
  }

  /** Writes a JSON body with the given status. */
  public static void respondJson(HttpExchange exchange, int status, String json) throws IOException {
    byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
    exchange.sendResponseHeaders(status, bytes.length);
    try (OutputStream os = exchange.getResponseBody()) {
      os.write(bytes);
    }
  }

  /** Reads the request body as a UTF-8 string. */
  public static String readBody(HttpExchange exchange) throws IOException {
    return new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
  }
}
