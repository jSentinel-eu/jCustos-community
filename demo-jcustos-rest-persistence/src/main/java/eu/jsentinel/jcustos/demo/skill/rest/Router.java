package eu.jsentinel.jcustos.demo.skill.rest;

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.dependencies.core.net.HttpStatus;
import com.svenruppert.dependencies.core.net.MediaType;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.rest.RestAuditCorrelation;
import eu.jsentinel.jcustos.rest.RestAuthorizationFilter;
import eu.jsentinel.jcustos.rest.RestDecisionContext;
import eu.jsentinel.jcustos.rest.RestHeaderLines;
import eu.jsentinel.jcustos.rest.RestJCustosVersionFilter;
import eu.jsentinel.jcustos.rest.RestOriginGuard;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestResponse;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Composite {@link HttpHandler} that dispatches requests to handler
 * methods and lets the jCustos REST filters decide who may call them.
 *
 * <p>Per request, in this order:
 * <ol>
 *   <li>A request that repeats {@code Authorization}, {@code X-Api-Key}
 *       or {@code Cookie} is refused with {@code 400} before anything
 *       else runs (JS-SEC-113). Every other header reaches the library
 *       with all of its lines ({@link RestHeaderLines}).</li>
 *   <li>The route is chosen by HTTP method and path pattern
 *       ({@code /api/users/{id}/roles/{role}}); the most specific
 *       pattern wins, a path with extra segments matches nothing.</li>
 *   <li>Everything below runs inside one audit correlation scope
 *       ({@link RestAuditCorrelation}, R5): the filters' events and the
 *       handlers' own ones (login, logout) carry the same request id.</li>
 *   <li>A {@link RestOriginGuard} installed with
 *       {@code .originGuard(...)} runs first and refuses a
 *       state-changing request from a foreign origin with 403 (CSRF).
 *       This demo authenticates with bearer tokens, which a browser
 *       never sends on its own, and installs none; an application whose
 *       session rides on a cookie does.</li>
 *   <li>For a route that is not {@link PublicRoute @PublicRoute}, the
 *       {@link RestJCustosVersionFilter} refuses a session whose
 *       security version drifted (only when a version store is
 *       registered).</li>
 *   <li>{@link RestAuthorizationFilter} evaluates the restriction
 *       annotation of the handler method <em>as it runs on the handler
 *       class</em> (JS-SEC-114), refuses revoked sessions (JS-SEC-131)
 *       and expired ones, audits the decision and renders every refusal
 *       through the published decision mapper (JS-SEC-086, a
 *       {@code WWW-Authenticate: Bearer} challenge on every 401).</li>
 * </ol>
 *
 * <p>Handlers are {@code public static} methods with the signature
 * {@code (HttpExchange, JCustosSubject)}; their restriction is an
 * annotation on the method ({@code @RequiresPermission},
 * {@code @PublicRoute}, …). Route keys must be unique:
 * {@link Builder#build()} fails at start-up on a duplicate.
 *
 * <p>Demo-level routing — production swaps for any
 * Jersey/Spring/Vert.x router and keeps the filters.
 */
public final class Router implements HttpHandler, HasLogger {

  /** Exchange attribute holding the {@link RestRequest} built for the exchange. */
  public static final String REST_REQUEST_ATTRIBUTE = "jcustos.restRequest";

  /** Exchange attribute holding the path variables of the matched route. */
  public static final String PATH_VARIABLES_ATTRIBUTE = "jcustos.pathVariables";

  private final RestSubjectResolver resolver;
  private final List<Route> routes;
  private final RestAuthorizationFilter authorization;
  private final RestJCustosVersionFilter versionFilter;

  public Router(RestSubjectResolver resolver, List<Route> routes) {
    this.resolver = Objects.requireNonNull(resolver, "resolver");
    this.routes = List.copyOf(routes);
    this.authorization = new RestAuthorizationFilter(resolver);
    // Drift detection is active when a JCustosVersionStore is registered (hardening layer).
    this.versionFilter = JCustosServiceResolver.findJCustosVersionStore()
        .map(store -> new RestJCustosVersionFilter(resolver,
            new JCustosVersionEnforcer(store, JCustosServiceResolver.securityAuditService())))
        .orElse(null);
  }

  @Override
  public void handle(HttpExchange exchange) throws IOException {
    try {
      BufferedResponse response = new BufferedResponse();
      Map<String, List<String>> headerLines = exchange.getRequestHeaders();
      // JS-SEC-113: two lines of a credential header are never legitimate.
      if (RestHeaderLines.rejectDuplicates(headerLines, response)) {
        response.writeTo(exchange);
        return;
      }
      String path = exchange.getRequestURI().getPath();
      Optional<Match> match = match(exchange.getRequestMethod(), path);
      if (match.isEmpty()) {
        respond(exchange, HttpStatus.NOT_FOUND.code(), HttpStatus.NOT_FOUND.reason());
        return;
      }
      Route route = match.get().route();
      RestRequest request = restRequestFrom(exchange, headerLines);
      exchange.setAttribute(REST_REQUEST_ATTRIBUTE, request);
      exchange.setAttribute(PATH_VARIABLES_ATTRIBUTE, match.get().variables());

      // R5 (JS-SEC-066): one correlation scope for guard, filters and handler
      boolean refused = RestAuditCorrelation.call(request,
          () -> dispatch(exchange, request, route, response));
      if (refused) {
        response.writeTo(exchange);
      }
    } catch (RuntimeException failure) {
      logger().warn("Request failed: {}", failure.getClass().getName());
      respond(exchange, HttpStatus.INTERNAL_SERVER_ERROR.code(),
          HttpStatus.INTERNAL_SERVER_ERROR.reason());
    } finally {
      exchange.close();
    }
  }

  /**
   * Runs guard, filters and handler of a matched route.
   *
   * @return {@code true} when a filter refused the request and its buffered
   *         answer still has to be written; the handler has not run
   */
  private boolean dispatch(HttpExchange exchange, RestRequest request, Route route,
                           BufferedResponse response) {
    // CSRF (CWE-352): the outermost filter; a no-op unless .originGuard(...) installed one.
    if (RestOriginGuard.installed().map(guard -> !guard.allow(request, response)).orElse(false)) {
      return true;
    }
    if (versionFilter != null && !route.isPublic() && !versionFilter.allow(request, response)) {
      return true;
    }
    boolean[] invoked = {false};
    authorization.authorizeAndHandle(request, response, (req, resp) -> {
      invoked[0] = true;
      route.invoke(exchange, resolver.resolveSubject(req).orElse(null));
    }, route.method(), route.handlerClass());
    return !invoked[0];
  }

  private Optional<Match> match(String method, String path) {
    Match best = null;
    for (Route route : routes) {
      if (!route.httpMethod().equalsIgnoreCase(method)) {
        continue;
      }
      Map<String, String> variables = route.pattern().match(path);
      if (variables != null && (best == null || route.pattern().moreSpecificThan(best.route().pattern()))) {
        best = new Match(route, variables);
      }
    }
    return Optional.ofNullable(best);
  }

  /** Path variables of the matched route, e.g. {@code id} for {@code /api/users/{id}}. */
  public static String pathVariable(HttpExchange exchange, String name) {
    Object variables = exchange.getAttribute(PATH_VARIABLES_ATTRIBUTE);
    return variables instanceof Map<?, ?> map ? (String) map.get(name) : null;
  }

  /** The {@link RestRequest} the router built for this exchange. */
  public static RestRequest restRequest(HttpExchange exchange) {
    return (RestRequest) exchange.getAttribute(REST_REQUEST_ATTRIBUTE);
  }

  // ── Builder ────────────────────────────────────────────────────

  /** Accumulates {@link Route} entries; {@link #build()} refuses duplicate keys. */
  public static final class Builder {
    private final List<Route> routes = new ArrayList<>();

    /**
     * Adds a route served by the {@code public static} method
     * {@code methodName(HttpExchange, JCustosSubject)} of
     * {@code handlerClass}. The method's annotation is its restriction.
     */
    public Builder add(String httpMethod, String pathPattern, Class<?> handlerClass, String methodName) {
      routes.add(Route.of(httpMethod, pathPattern, handlerClass, methodName));
      return this;
    }

    /**
     * @throws IllegalStateException when two routes share HTTP method and
     *                               path pattern (variable names do not count)
     */
    public List<Route> build() {
      Set<String> keys = new HashSet<>();
      for (Route route : routes) {
        String key = route.httpMethod().toUpperCase(Locale.ROOT) + " " + route.pattern().key();
        if (!keys.add(key)) {
          throw new IllegalStateException("Duplicate route: " + key);
        }
      }
      return List.copyOf(routes);
    }
  }

  /** Route: HTTP method + path pattern + the handler method that carries the restriction. */
  public record Route(String httpMethod, PathPattern pattern, Class<?> handlerClass, Method method) {

    static Route of(String httpMethod, String pathPattern, Class<?> handlerClass, String methodName) {
      Method method;
      try {
        method = handlerClass.getMethod(methodName, HttpExchange.class, JCustosSubject.class);
      } catch (NoSuchMethodException e) {
        throw new IllegalStateException("No handler method " + handlerClass.getName() + "#"
            + methodName + "(HttpExchange, JCustosSubject)", e);
      }
      if (!Modifier.isStatic(method.getModifiers())) {
        throw new IllegalStateException("Handler method must be static: " + method);
      }
      return new Route(httpMethod, PathPattern.parse(pathPattern), handlerClass, method);
    }

    boolean isPublic() {
      return method.isAnnotationPresent(PublicRoute.class)
          || handlerClass.isAnnotationPresent(PublicRoute.class);
    }

    void invoke(HttpExchange exchange, JCustosSubject subject) {
      try {
        method.invoke(null, exchange, subject);
      } catch (IllegalAccessException e) {
        throw new IllegalStateException(e);
      } catch (InvocationTargetException e) {
        Throwable cause = e.getCause();
        if (cause instanceof IOException io) {
          throw new UncheckedIOException(io);
        }
        if (cause instanceof RuntimeException runtime) {
          throw runtime;
        }
        if (cause instanceof Error error) {
          throw error;
        }
        throw new IllegalStateException(cause);
      }
    }
  }

  /** Path pattern of literal segments and {@code {name}} variables. */
  public record PathPattern(List<String> segments) {

    static PathPattern parse(String pattern) {
      if (pattern == null || !pattern.startsWith("/")) {
        throw new IllegalArgumentException("Path pattern must start with '/': " + pattern);
      }
      return new PathPattern(List.of(pattern.substring(1).split("/", -1)));
    }

    /** Route key: variables are anonymous, so {@code {id}} and {@code {userId}} collide. */
    String key() {
      return "/" + String.join("/", segments.stream()
          .map(s -> isVariable(s) ? "{}" : s).toList());
    }

    /** @return the path variables, or {@code null} when the path does not match */
    Map<String, String> match(String path) {
      if (path == null || !path.startsWith("/")) {
        return null;
      }
      String[] parts = path.substring(1).split("/", -1);
      if (parts.length != segments.size()) {
        return null;
      }
      Map<String, String> variables = new LinkedHashMap<>();
      for (int i = 0; i < parts.length; i++) {
        String segment = segments.get(i);
        if (isVariable(segment)) {
          if (parts[i].isEmpty()) {
            return null;
          }
          variables.put(segment.substring(1, segment.length() - 1), parts[i]);
        } else if (!segment.equals(parts[i])) {
          return null;
        }
      }
      return variables;
    }

    /** Left to right, the first literal segment opposite a variable wins. */
    boolean moreSpecificThan(PathPattern other) {
      for (int i = 0; i < segments.size() && i < other.segments.size(); i++) {
        boolean mine = isVariable(segments.get(i));
        boolean theirs = isVariable(other.segments.get(i));
        if (mine != theirs) {
          return !mine;
        }
      }
      return false;
    }

    private static boolean isVariable(String segment) {
      return segment.length() > 2 && segment.startsWith("{") && segment.endsWith("}");
    }
  }

  private record Match(Route route, Map<String, String> variables) {
  }

  // ── HttpExchange ↔ RestRequest / RestResponse bridge ───────────

  private static RestRequest restRequestFrom(HttpExchange exchange, Map<String, List<String>> headerLines) {
    URI uri = exchange.getRequestURI();
    // JS-SEC-113: list headers are joined in wire order, never reduced to their first line.
    Map<String, String> headers = RestHeaderLines.joined(headerLines);
    // JS-SEC-098: every value of a repeated query parameter; the single-valued view keeps the last.
    Map<String, List<String>> queryValues = parseQuery(uri.getQuery());
    Map<String, String> query = lastValues(queryValues);
    String method = exchange.getRequestMethod();
    String path = uri.getPath();
    var remote = exchange.getRemoteAddress();
    String remoteAddress = remote == null || remote.getAddress() == null
        ? null : remote.getAddress().getHostAddress();
    return new RestRequest() {
      /** JS-SEC-061: expose the connection peer; the ClientAddressResolver decides the client. */
      @Override
      public String remoteAddress() {
        return remoteAddress;
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

      /** JS-SEC-113: every line of the header, in wire order. */
      @Override
      public List<String> headerValues(String name) {
        return RestHeaderLines.values(headerLines, name);
      }

      @Override
      public Map<String, String> queryParameters() {
        return query;
      }

      /**
       * JS-SEC-098: every value of every query parameter, in wire order. The OAuth2 callback
       * handler reads the callback through this view and refuses a repeated {@code state},
       * {@code code} or {@code iss}; the default derived from {@link #queryParameters()} would
       * show only the last value.
       */
      @Override
      public Map<String, List<String>> queryParameterValues() {
        return queryValues;
      }
    };
  }

  /** The query parameters with all their values, in wire order; unmodifiable. */
  private static Map<String, List<String>> parseQuery(String raw) {
    Map<String, List<String>> out = new LinkedHashMap<>();
    if (raw == null || raw.isEmpty()) return Collections.unmodifiableMap(out);
    for (String pair : raw.split("&")) {
      int eq = pair.indexOf('=');
      String name = eq < 0 ? pair : pair.substring(0, eq);
      String value = eq < 0 ? "" : pair.substring(eq + 1);
      out.computeIfAbsent(name, key -> new ArrayList<>()).add(value);
    }
    out.replaceAll((name, values) -> List.copyOf(values));
    return Collections.unmodifiableMap(out);
  }

  /** The single-valued view: the last value of every parameter. */
  private static Map<String, String> lastValues(Map<String, List<String>> values) {
    Map<String, String> out = new LinkedHashMap<>();
    values.forEach((name, all) -> out.put(name, all.getLast()));
    return out;
  }

  /** Collects a refusal the filters render, then writes it to the exchange. */
  private static final class BufferedResponse implements RestResponse {
    private int status = HttpStatus.OK.code();
    private String body = "";
    private final Map<String, String> headers = new LinkedHashMap<>();

    @Override
    public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override
    public void body(String body) {
      this.body = body == null ? "" : body;
    }

    @Override
    public void header(String name, String value) {
      if (name != null && value != null) {
        headers.put(name, value);
      }
    }

    void writeTo(HttpExchange exchange) throws IOException {
      headers.forEach((name, value) -> exchange.getResponseHeaders().set(name, value));
      if (body.startsWith("{")) {
        respondJson(exchange, status, body);
      } else {
        respond(exchange, status, body);
      }
    }
  }

  /**
   * Answers with a refusal rendered by the decision mapper the bootstrap
   * published (JS-SEC-086): status, {@code WWW-Authenticate} challenge and
   * the configured error body — the same rendering the filters use.
   */
  public static void refuse(HttpExchange exchange, AuthorizationDecision decision) throws IOException {
    BufferedResponse response = new BufferedResponse();
    RestDecisionContext.mapperOrDefault().apply(decision, response);
    response.writeTo(exchange);
  }

  /** Writes a plain-text body with the given status. */
  public static void respond(HttpExchange exchange, int status, String body) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", MediaType.TEXT_PLAIN.withCharsetUtf8());
    exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
    if (bytes.length > 0) {
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(bytes);
      }
    }
  }

  /** Writes a JSON body with the given status. */
  public static void respondJson(HttpExchange exchange, int status, String json) throws IOException {
    byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", MediaType.APPLICATION_JSON.withCharsetUtf8());
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
