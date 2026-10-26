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
package eu.jsentinel.jcustos.rest;

import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("RestAuthorizationFilter")
class RestAuthorizationFilterTest {

  @AfterEach
  void resetDenyByDefault() {
    JCustosServiceResolver.setDenyByDefault(false);
  }

  @Test
  @DisplayName("request without subject receives 401 and handler is not executed")
  void withoutSubject_unauthorized() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(request -> Optional.empty());

    filter.authorizeAndHandle(
        request(),
        response,
        (request, restResponse) -> executed.set(true),
        securedMethod());

    assertEquals(401, response.status);
    assertEquals("Unauthorized", response.body);
    assertFalse(executed.get());
  }

  @Test
  @DisplayName("subject without permission receives 403 and handler is not executed")
  void missingPermission_forbidden() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(
        request -> Optional.of(subject(Set.of(new PermissionName("document:read")))));

    filter.authorizeAndHandle(
        request(),
        response,
        (request, restResponse) -> executed.set(true),
        securedMethod());

    assertEquals(403, response.status);
    assertEquals("Forbidden", response.body);
    assertFalse(executed.get());
  }

  @Test
  @DisplayName("subject with permission executes handler")
  void matchingPermission_executesHandler() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(
        request -> Optional.of(subject(Set.of(new PermissionName("document:delete")))));

    filter.authorizeAndHandle(
        request(),
        response,
        (request, restResponse) -> {
          executed.set(true);
          restResponse.status(204);
        },
        securedMethod());

    assertEquals(204, response.status);
    assertTrue(executed.get());
  }

  @Test
  @DisplayName("element without security annotation: handler runs without resolving a subject")
  void unannotatedElement_invokesHandlerDirectly() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    AtomicBoolean resolverCalled = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(request -> {
      resolverCalled.set(true);
      return Optional.empty();
    });

    Method unsecured = HandlerFixture.class.getDeclaredMethod("open");
    filter.authorizeAndHandle(
        request(),
        response,
        (request, restResponse) -> {
          executed.set(true);
          restResponse.status(200);
        },
        unsecured);

    assertTrue(executed.get(), "handler must run when element has no security annotation");
    assertEquals(200, response.status);
    assertFalse(resolverCalled.get(),
        "no subject resolution should happen when element is unsecured");
  }

  @Test
  @DisplayName("six-arg overload forwards null attributes to the access context")
  void nullAttributesAreAccepted() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(
        request -> Optional.of(subject(Set.of(new PermissionName("document:delete")))));

    filter.authorizeAndHandle(
        request(),
        response,
        (request, restResponse) -> executed.set(true),
        securedMethod(),
        "delete",
        null);

    assertTrue(executed.get());
    assertEquals(200, response.status);
  }

  @Test
  @DisplayName("JS-SEC-024 / RF: deny-by-default without a subject is 401, not 403")
  void denyByDefault_unannotatedHandler_noSubject_unauthorized() throws NoSuchMethodException {
    JCustosServiceResolver.setDenyByDefault(true);
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(request -> Optional.empty());

    filter.authorizeAndHandle(request(), response,
        (req, res) -> executed.set(true),
        HandlerFixture.class.getDeclaredMethod("open"), "read", Map.of());

    // RF (exit-review): a missing subject is Unauthenticated (401) so a client with an
    // expired/absent token still triggers its standard re-auth flow — was 403.
    assertEquals(401, response.status);
    assertFalse(executed.get(), "un-annotated handler must not run under deny-by-default");
  }

  @Test
  @DisplayName("JS-SEC-024 / RF: deny-by-default with a resolved subject is 403")
  void denyByDefault_unannotatedHandler_withSubject_forbidden() throws NoSuchMethodException {
    JCustosServiceResolver.setDenyByDefault(true);
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(
        request -> Optional.of(subject(Set.of(new PermissionName("document:read")))));

    filter.authorizeAndHandle(request(), response,
        (req, res) -> executed.set(true),
        HandlerFixture.class.getDeclaredMethod("open"), "read", Map.of());

    // A resolved-but-unauthorized subject on an un-annotated handler is Forbidden (403).
    assertEquals(403, response.status);
    assertFalse(executed.get(), "un-annotated handler must not run under deny-by-default");
  }

  @Test
  @DisplayName("JS-SEC-024 / RF: class-level @PublicRoute opts the endpoint back in even when a Method is passed")
  void denyByDefault_classLevelPublicRoute_allowsHandler() throws NoSuchMethodException {
    JCustosServiceResolver.setDenyByDefault(true);
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(request -> Optional.empty());

    // the handler METHOD carries no annotation; @PublicRoute lives on the declaring class.
    filter.authorizeAndHandle(request(), response,
        (req, res) -> { executed.set(true); res.status(200); },
        PublicClassFixture.class.getDeclaredMethod("open"), "read", Map.of());

    assertTrue(executed.get(),
        "a class-level @PublicRoute must keep the endpoint public even when the Method is the secured element");
    assertEquals(200, response.status);
  }

  @Test
  @DisplayName("JS-SEC-024: deny-by-default still allows a @PublicRoute handler")
  void denyByDefault_publicRoute_allowsHandler() throws NoSuchMethodException {
    JCustosServiceResolver.setDenyByDefault(true);
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(request -> Optional.empty());

    filter.authorizeAndHandle(request(), response,
        (req, res) -> { executed.set(true); res.status(200); },
        HandlerFixture.class.getDeclaredMethod("openPublic"), "read", Map.of());

    assertTrue(executed.get(), "@PublicRoute handler must run even under deny-by-default");
    assertEquals(200, response.status);
  }

  @Test
  @DisplayName("JS-SEC-024: with deny-by-default OFF (default) an un-annotated handler still runs")
  void denyByDefaultOff_unannotatedHandler_allowed() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(request -> Optional.empty());

    filter.authorizeAndHandle(request(), response,
        (req, res) -> { executed.set(true); res.status(200); },
        HandlerFixture.class.getDeclaredMethod("open"), "read", Map.of());

    assertTrue(executed.get());
    assertEquals(200, response.status);
  }

  private static Method securedMethod() throws NoSuchMethodException {
    return HandlerFixture.class.getDeclaredMethod("delete");
  }

  private static RestRequest request() {
    return new SimpleRestRequest("DELETE", "/api/documents/42", Map.of(), Map.of());
  }

  // ── JS-SEC-070 (CWE-862): class-level restriction with Method wiring ────────

  @Test
  @DisplayName("JS-SEC-070: class-level @RequiresPermission guards a Method-wired handler (403 without permission)")
  void classLevelAnnotation_methodWiring_forbiddenWithoutPermission() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(
        request -> Optional.of(subject(Set.of(new PermissionName("document:read")))));

    filter.authorizeAndHandle(request(), response,
        (request, restResponse) -> executed.set(true),
        ClassProtectedFixture.class.getDeclaredMethod("delete"));

    assertEquals(403, response.status);
    assertFalse(executed.get(), "the class-level restriction must reach enforcement");
  }

  @Test
  @DisplayName("JS-SEC-070: class-level @RequiresPermission admits a subject holding it")
  void classLevelAnnotation_methodWiring_executesWithPermission() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(
        request -> Optional.of(subject(Set.of(new PermissionName("document:delete")))));

    filter.authorizeAndHandle(request(), response,
        (request, restResponse) -> {
          executed.set(true);
          restResponse.status(204);
        },
        ClassProtectedFixture.class.getDeclaredMethod("delete"));

    assertEquals(204, response.status);
    assertTrue(executed.get());
  }

  @Test
  @DisplayName("JS-SEC-070: @PublicRoute on a method of a protected class stays public")
  void classLevelAnnotation_publicRouteMethod_staysPublic() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(request -> Optional.empty());

    filter.authorizeAndHandle(request(), response,
        (request, restResponse) -> {
          executed.set(true);
          restResponse.status(200);
        },
        ClassProtectedFixture.class.getDeclaredMethod("health"));

    assertEquals(200, response.status);
    assertTrue(executed.get(), "an explicit @PublicRoute on the method is the opt-out");
  }

  private static JCustosSubject subject(Set<PermissionName> permissions) {
    return new JCustosSubject("u1", "User", Set.of(), permissions);
  }

  static final class HandlerFixture {
    @RequiresPermission("document:delete")
    void delete() {
    }

    void open() {
    }

    @PublicRoute
    void openPublic() {
    }
  }

  /** RF (exit-review): {@code @PublicRoute} on the class, method carries no annotation. */
  @PublicRoute
  static final class PublicClassFixture {
    void open() {
    }
  }

  record SimpleRestRequest(
      String method,
      String path,
      Map<String, String> headers,
      Map<String, String> queryParameters
  ) implements RestRequest {
  }

  static final class RecordingResponse implements RestResponse {
    int status = 200;
    String body;

    @Override
    public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override
    public void body(String body) {
      this.body = body;
    }
  }

  /** JS-SEC-070 fixture: the restriction sits on the class, the handler methods carry none. */
  @RequiresPermission("document:delete")
  static final class ClassProtectedFixture {
    void delete() {
    }

    @PublicRoute
    void health() {
    }
  }
}
