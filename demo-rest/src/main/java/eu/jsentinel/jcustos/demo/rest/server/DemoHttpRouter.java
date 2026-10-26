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
package eu.jsentinel.jcustos.demo.rest.server;

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.demo.rest.shared.DemoEndpoints;
import eu.jsentinel.jcustos.policy.api.ResourceRef;
import eu.jsentinel.jcustos.rest.RestAuthenticationFilter;
import eu.jsentinel.jcustos.rest.RestAuthorizationFilter;
import eu.jsentinel.jcustos.rest.RestJCustosVersionFilter;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Routes incoming {@link HttpExchange} requests to demo handlers and applies
 * the generic {@link RestAuthorizationFilter} for permission-protected paths.
 */
public final class DemoHttpRouter implements HttpHandler {

  private final DemoHandlers handlers;
  private final DemoBootstrapHandlers bootstrapHandlers;
  private final RestAuthorizationFilter filter;
  private final RestAuthenticationFilter authenticationFilter;
  private final RestJCustosVersionFilter versionFilter;

  private final Method listDocumentsMethod;
  private final Method createDocumentMethod;
  private final Method deleteDocumentMethod;
  private final Method inspectDocumentsMethod;
  private final Method createApiKeyMethod;
  private final Method revokeApiKeyMethod;
  private final Method inspectOwnedDocumentMethod;
  private final Method adminStatusMethod;
  private final Method auditEventsMethod;
  private final Method listUsersMethod;
  private final Method setUserRoleMethod;
  private final Method createUserMethod;
  private final Method deleteUserMethod;

  public DemoHttpRouter(
      DemoHandlers handlers,
      DemoBootstrapHandlers bootstrapHandlers,
      DemoSubjectResolver subjectResolver) {
    this(handlers, bootstrapHandlers, subjectResolver, null);
  }

  public DemoHttpRouter(
      DemoHandlers handlers,
      DemoBootstrapHandlers bootstrapHandlers,
      DemoSubjectResolver subjectResolver,
      RestJCustosVersionFilter versionFilter) {
    this.handlers = handlers;
    this.bootstrapHandlers = bootstrapHandlers;
    this.filter = new RestAuthorizationFilter(subjectResolver);
    this.authenticationFilter = new RestAuthenticationFilter(subjectResolver);
    this.versionFilter = versionFilter;
    try {
      Class<?>[] sig = {
          eu.jsentinel.jcustos.rest.RestRequest.class,
          eu.jsentinel.jcustos.rest.RestResponse.class
      };
      this.listDocumentsMethod = DemoHandlers.class.getDeclaredMethod("listDocuments", sig);
      this.createDocumentMethod = DemoHandlers.class.getDeclaredMethod("createDocument", sig);
      this.deleteDocumentMethod = DemoHandlers.class.getDeclaredMethod("deleteDocument", sig);
      this.inspectDocumentsMethod = DemoHandlers.class.getDeclaredMethod("inspectDocuments", sig);
      this.createApiKeyMethod = DemoHandlers.class.getDeclaredMethod("createApiKey", sig);
      this.revokeApiKeyMethod = DemoHandlers.class.getDeclaredMethod("revokeApiKey", sig);
      this.inspectOwnedDocumentMethod = DemoHandlers.class.getDeclaredMethod("inspectOwnedDocument", sig);
      this.adminStatusMethod = DemoHandlers.class.getDeclaredMethod("adminStatus", sig);
      this.auditEventsMethod = DemoHandlers.class.getDeclaredMethod("auditEvents", sig);
      this.listUsersMethod = DemoHandlers.class.getDeclaredMethod("listUsers", sig);
      this.setUserRoleMethod = DemoHandlers.class.getDeclaredMethod("setUserRole", sig);
      this.createUserMethod = DemoHandlers.class.getDeclaredMethod("createUser", sig);
      this.deleteUserMethod = DemoHandlers.class.getDeclaredMethod("deleteUser", sig);
    } catch (NoSuchMethodException e) {
      throw new IllegalStateException("Demo handler method missing", e);
    }
  }

  @Override
  public void handle(HttpExchange exchange) throws IOException {
    try {
      DemoHttpRequest request = readRequest(exchange);
      DemoHttpResponse response = new DemoHttpResponse();
      dispatch(request, response);
      writeResponse(exchange, response);
    } catch (RuntimeException e) {
      DemoHttpResponse fallback = new DemoHttpResponse();
      fallback.status(HttpStatus.INTERNAL_SERVER_ERROR.code());
      fallback.body(HttpStatus.INTERNAL_SERVER_ERROR.reason());
      writeResponse(exchange, fallback);
    } finally {
      exchange.close();
    }
  }

  private void dispatch(DemoHttpRequest request, DemoHttpResponse response) {
    String method = request.method();
    String path = request.path();

    if (DemoEndpoints.BOOTSTRAP_STATUS.equals(path) && "GET".equals(method)) {
      bootstrapHandlers.status(request, response);
      return;
    }
    if (DemoEndpoints.BOOTSTRAP_ADMIN.equals(path) && "POST".equals(method)) {
      bootstrapHandlers.createInitialAdmin(request, response);
      return;
    }
    if (DemoEndpoints.LOGIN.equals(path) && "POST".equals(method)) {
      handlers.login(request, response);
      return;
    }
    // V00.76: the JWT is self-authenticating, so this route is dispatched directly.
    if (DemoEndpoints.JWT_DEMO.equals(path) && "POST".equals(method)) {
      handlers.jwtDemo(request, response);
      return;
    }
    if (DemoEndpoints.PASSWORD_RESET_REQUEST.equals(path) && "POST".equals(method)) {
      handlers.requestPasswordReset(request, response);
      return;
    }
    if (DemoEndpoints.PASSWORD_RESET_CONSUME.equals(path) && "POST".equals(method)) {
      handlers.consumePasswordReset(request, response);
      return;
    }
    if (DemoEndpoints.AUTH_TOKEN_ISSUE.equals(path) && "POST".equals(method)) {
      handlers.issueTokenPair(request, response);
      return;
    }
    if (DemoEndpoints.AUTH_TOKEN_REFRESH.equals(path) && "POST".equals(method)) {
      handlers.rotateTokenPair(request, response);
      return;
    }
    if (DemoEndpoints.AUTH_TOKEN_REVOKE.equals(path) && "POST".equals(method)) {
      handlers.revokeTokenPair(request, response);
      return;
    }

    // Phase 4c — refuse drifted sessions ahead of authentication / authorization.
    // No filter (transient demo configurations) or unbound token → pass-through.
    if (versionFilter != null && !versionFilter.allow(request, response, path)) {
      return;
    }

    if (DemoEndpoints.ME.equals(path) && "GET".equals(method)) {
      authenticationFilter.requireAuthenticated(request, response, handlers::me);
      return;
    }
    if (DemoEndpoints.OPERATIONS.equals(path) && "GET".equals(method)) {
      authenticationFilter.requireAuthenticated(request, response, handlers::operations);
      return;
    }
    if (DemoEndpoints.LOGOUT.equals(path) && "POST".equals(method)) {
      authenticationFilter.requireAuthenticated(request, response, handlers::logout);
      return;
    }
    // The "/api/documents/inspect" endpoint must be matched ahead of the
    // generic "/api/documents/" prefix so the inspector handler is the one
    // that fires.
    if (DemoEndpoints.DOCUMENTS_INSPECT.equals(path) && "GET".equals(method)) {
      filter.authorizeAndHandle(request, response,
          handlers::inspectDocuments, inspectDocumentsMethod);
      return;
    }
    if (DemoEndpoints.DOCUMENTS.equals(path)) {
      switch (method) {
        case "GET" -> filter.authorizeAndHandle(request, response, handlers::listDocuments, listDocumentsMethod);
        case "POST" -> filter.authorizeAndHandle(request, response, handlers::createDocument, createDocumentMethod);
        default -> notAllowed(response);
      }
      return;
    }
    if (path.startsWith(DemoEndpoints.DOCUMENT_BY_ID) && "DELETE".equals(method)) {
      filter.authorizeAndHandle(request, response, handlers::deleteDocument, deleteDocumentMethod);
      return;
    }
    // V00.70 Policy-DSL — the /api/owned-documents/{id} path carries
    // the ResourceRef into AccessContext.attributes so the
    // @RequiresPolicy("document.owner-or-admin") evaluator can
    // resolve owner attributes via the registered ResourceResolver.
    if (path.startsWith(DemoEndpoints.OWNED_DOCUMENT_BY_ID) && "GET".equals(method)) {
      String id = path.substring(DemoEndpoints.OWNED_DOCUMENT_BY_ID.length());
      Map<String, Object> attributes = id.isBlank()
          ? Map.of()
          : Map.of(ResourceRef.ATTRIBUTE_KEY,
              new ResourceRef(DemoOwnedDocumentResolver.RESOURCE_TYPE,
                  id, TenantId.DEFAULT));
      filter.authorizeAndHandle(request, response,
          handlers::inspectOwnedDocument, inspectOwnedDocumentMethod,
          "get", attributes);
      return;
    }
    if (DemoEndpoints.ADMIN_STATUS.equals(path) && "GET".equals(method)) {
      filter.authorizeAndHandle(request, response, handlers::adminStatus, adminStatusMethod);
      return;
    }
    if (DemoEndpoints.AUDIT.equals(path) && "GET".equals(method)) {
      filter.authorizeAndHandle(request, response, handlers::auditEvents, auditEventsMethod);
      return;
    }
    if (DemoEndpoints.ADMIN_USERS.equals(path)) {
      switch (method) {
        case "GET" -> filter.authorizeAndHandle(request, response, handlers::listUsers, listUsersMethod);
        case "POST" -> filter.authorizeAndHandle(request, response, handlers::createUser, createUserMethod);
        default -> notAllowed(response);
      }
      return;
    }
    if (path.startsWith(DemoEndpoints.ADMIN_USER_BY_NAME)) {
      switch (method) {
        case "PUT" -> filter.authorizeAndHandle(request, response, handlers::setUserRole, setUserRoleMethod);
        case "DELETE" -> filter.authorizeAndHandle(request, response, handlers::deleteUser, deleteUserMethod);
        default -> notAllowed(response);
      }
      return;
    }
    // Phase-7b API-key admin endpoints. Match the more-specific
    // /revoke path before the bare /api-keys collection.
    if (DemoEndpoints.ADMIN_API_KEYS_REVOKE.equals(path) && "POST".equals(method)) {
      filter.authorizeAndHandle(request, response,
          handlers::revokeApiKey, revokeApiKeyMethod);
      return;
    }
    if (DemoEndpoints.ADMIN_API_KEYS.equals(path) && "POST".equals(method)) {
      filter.authorizeAndHandle(request, response,
          handlers::createApiKey, createApiKeyMethod);
      return;
    }
    response.status(HttpStatus.NOT_FOUND.code());
    response.body(HttpStatus.NOT_FOUND.reason());
  }

  private static void notAllowed(DemoHttpResponse response) {
    response.status(HttpStatus.METHOD_NOT_ALLOWED.code());
    response.body(HttpStatus.METHOD_NOT_ALLOWED.reason());
  }

  private static DemoHttpRequest readRequest(HttpExchange exchange) throws IOException {
    String body;
    try (InputStream in = exchange.getRequestBody()) {
      body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
    URI uri = exchange.getRequestURI();
    Map<String, String> headers = flattenHeaders(exchange.getRequestHeaders());
    return new DemoHttpRequest(
        exchange.getRequestMethod(),
        uri.getPath(),
        headers,
        parseQuery(uri.getRawQuery()),
        body,
        remoteAddress(exchange));
  }

  /** JS-SEC-061: the peer travels as request metadata, not as a forgeable header. */
  private static String remoteAddress(HttpExchange exchange) {
    try {
      var remote = exchange.getRemoteAddress();
      return remote == null || remote.getAddress() == null
          ? null : remote.getAddress().getHostAddress();
    } catch (RuntimeException ignored) {
      // never block the request because we can't determine the remote address
      return null;
    }
  }

  private static Map<String, String> flattenHeaders(Headers headers) {
    Map<String, String> map = new LinkedHashMap<>();
    for (var entry : headers.entrySet()) {
      if (!entry.getValue().isEmpty()) {
        map.put(entry.getKey(), entry.getValue().get(0));
      }
    }
    return map;
  }

  private static Map<String, String> parseQuery(String rawQuery) {
    Map<String, String> map = new LinkedHashMap<>();
    if (rawQuery == null || rawQuery.isEmpty()) return map;
    for (String pair : rawQuery.split("&")) {
      int eq = pair.indexOf('=');
      if (eq < 0) {
        map.put(URLDecoder.decode(pair, StandardCharsets.UTF_8), "");
      } else {
        String k = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
        String v = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
        map.put(k, v);
      }
    }
    return map;
  }

  private static void writeResponse(HttpExchange exchange, DemoHttpResponse response) throws IOException {
    byte[] payload = response.getBody().getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
    response.getHeaders().forEach((name, value) -> exchange.getResponseHeaders().add(name, value));
    int contentLength = payload.length == 0 ? -1 : payload.length;
    exchange.sendResponseHeaders(response.status(), contentLength);
    if (payload.length > 0) {
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(payload);
      }
    }
  }
}
