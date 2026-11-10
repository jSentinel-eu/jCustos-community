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

import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-114 (CWE-862, CWE-863): handler methods that a handler class inherits or
 * overrides. The fixtures are the ones of the proof of concept - real classes, the real
 * filter, a resolver without a subject for the anonymous caller.
 */
@DisplayName("RestAuthorizationFilter - inherited and overriding handler methods (JS-SEC-114)")
class RestInheritedHandlerTest {

  private final RecordingAuditSink audit = new RecordingAuditSink();

  @BeforeEach
  void registerAudit() {
    JCustosServiceResolver.setJCustosAuditService(audit);
  }

  @AfterEach
  void reset() {
    JCustosServiceResolver.resetAll();
    RestDecisionContext.reset();
  }

  // ── variant 1: the method is declared by a base class of the handler class ──

  @Test
  @DisplayName("an anonymous request to an inherited method of a restricted handler class is answered 401; the handler does not run")
  void inheritedMethod_anonymous_isRefused() throws NoSuchMethodException {
    AdminHandlers admin = new AdminHandlers();
    Method inherited = AdminHandlers.class.getMethod("deleteAll", RestRequest.class, RestResponse.class);
    assertEquals(CrudHandlers.class, inherited.getDeclaringClass(), "the premise of the finding");
    Recording response = new Recording();

    anonymousFilter().authorizeAndHandle(
        request("/admin/all"), response, admin::deleteAll, inherited, AdminHandlers.class);

    assertEquals(401, response.status);
    assertNull(admin.deleted, "the handler must not run");
    assertTrue(audit.single(AccessDenied.class).reason().startsWith("Unauthenticated:"));
  }

  @Test
  @DisplayName("the inherited method demands the role of the handler class: 403 without it, the handler runs with it")
  void inheritedMethod_demandsTheRoleOfTheHandlerClass() throws NoSuchMethodException {
    Method inherited = AdminHandlers.class.getMethod("deleteAll", RestRequest.class, RestResponse.class);

    AdminHandlers refused = new AdminHandlers();
    Recording forbidden = new Recording();
    filterFor("USER").authorizeAndHandle(
        request("/admin/all"), forbidden, refused::deleteAll, inherited, AdminHandlers.class);
    assertEquals(403, forbidden.status);
    assertNull(refused.deleted);

    AdminHandlers served = new AdminHandlers();
    Recording ok = new Recording();
    filterFor("ADMIN").authorizeAndHandle(
        request("/admin/all"), ok, served::deleteAll, inherited, AdminHandlers.class);
    assertEquals(200, ok.status);
    assertEquals("deleted everything", served.deleted);
  }

  @Test
  @DisplayName("the handler class decides: the same base method is open on the base class and restricted on the subclass")
  void sameMethod_differentHandlerClasses() throws NoSuchMethodException {
    Method base = CrudHandlers.class.getMethod("deleteAll", RestRequest.class, RestResponse.class);

    CrudHandlers plain = new CrudHandlers();
    Recording open = new Recording();
    anonymousFilter().authorizeAndHandle(request("/crud/all"), open, plain::deleteAll, base, CrudHandlers.class);
    assertEquals(200, open.status, "CrudHandlers itself carries no restriction (allow-by-omission)");

    AdminHandlers admin = new AdminHandlers();
    Recording closed = new Recording();
    anonymousFilter().authorizeAndHandle(request("/admin/all"), closed, admin::deleteAll, base, AdminHandlers.class);
    assertEquals(401, closed.status);
    assertNull(admin.deleted);
  }

  @Test
  @DisplayName("the operation/attributes overload resolves the handler class in the same way")
  void inheritedMethod_longOverload() throws NoSuchMethodException {
    AdminHandlers admin = new AdminHandlers();
    Method inherited = AdminHandlers.class.getMethod("deleteAll", RestRequest.class, RestResponse.class);
    Recording response = new Recording();

    anonymousFilter().authorizeAndHandle(
        request("/admin/all"), response, admin::deleteAll, inherited, AdminHandlers.class,
        "delete", Map.of());

    assertEquals(401, response.status);
    assertNull(admin.deleted);
  }

  @Test
  @DisplayName("a method declared by the handler class itself behaves as before, with either overload")
  void ownMethod_unchanged() throws NoSuchMethodException {
    Method own = AdminHandlers.class.getMethod("own", RestRequest.class, RestResponse.class);
    AdminHandlers admin = new AdminHandlers();

    Recording viaElement = new Recording();
    anonymousFilter().authorizeAndHandle(request("/admin/own"), viaElement, admin::own, own);
    Recording viaHandlerClass = new Recording();
    anonymousFilter().authorizeAndHandle(request("/admin/own"), viaHandlerClass, admin::own, own, AdminHandlers.class);

    assertEquals(401, viaElement.status);
    assertEquals(401, viaHandlerClass.status);
  }

  // ── variant 2: the handler class overrides a restricted method ──

  @Test
  @DisplayName("an override without an annotation keeps the restriction of the overridden method - with either overload")
  void overridingMethod_anonymous_isRefused() throws NoSuchMethodException {
    Method override = TenantOps.class.getMethod("purge", RestRequest.class, RestResponse.class);
    assertEquals(TenantOps.class, override.getDeclaringClass());

    TenantOps first = new TenantOps();
    Recording viaElement = new Recording();
    anonymousFilter().authorizeAndHandle(request("/tenant/purge"), viaElement, first::purge, override);
    assertEquals(401, viaElement.status);
    assertNull(first.purged, "the handler must not run");

    TenantOps second = new TenantOps();
    Recording viaHandlerClass = new Recording();
    anonymousFilter().authorizeAndHandle(
        request("/tenant/purge"), viaHandlerClass, second::purge, override, TenantOps.class);
    assertEquals(401, viaHandlerClass.status);
    assertNull(second.purged);
  }

  @Test
  @DisplayName("the override is served to a subject with the role of the overridden method")
  void overridingMethod_withTheRole_isServed() throws NoSuchMethodException {
    Method override = TenantOps.class.getMethod("purge", RestRequest.class, RestResponse.class);
    TenantOps tenant = new TenantOps();
    Recording response = new Recording();

    filterFor("ADMIN").authorizeAndHandle(request("/tenant/purge"), response, tenant::purge, override, TenantOps.class);

    assertEquals(200, response.status);
    assertEquals("tenant purge", tenant.purged);
  }

  @Test
  @DisplayName("the base Method wired with the handler class is judged as the override that runs")
  void baseMethodWithHandlerClass_isTheOverride() throws NoSuchMethodException {
    Method base = BaseOps.class.getMethod("purge", RestRequest.class, RestResponse.class);
    OpenedOps opened = new OpenedOps();
    Recording response = new Recording();

    anonymousFilter().authorizeAndHandle(request("/opened/purge"), response, opened::purge, base, OpenedOps.class);

    assertEquals(200, response.status, "OpenedOps#purge is @PublicRoute - the explicit opt-out on the method that runs");
    assertEquals("opened purge", opened.purged);
  }

  // ── opt-out, deny-by-default, wiring errors ──

  @Test
  @DisplayName("deny-by-default: an inherited method of an un-annotated handler class is refused, a @PublicRoute handler class is served")
  void denyByDefault_usesTheHandlerClass() throws NoSuchMethodException {
    JCustosServiceResolver.setDenyByDefault(true);
    Method base = CrudHandlers.class.getMethod("deleteAll", RestRequest.class, RestResponse.class);

    PlainHandlers plain = new PlainHandlers();
    Recording refused = new Recording();
    anonymousFilter().authorizeAndHandle(request("/plain/all"), refused, plain::deleteAll, base, PlainHandlers.class);
    assertEquals(401, refused.status);
    assertNull(plain.deleted);
    assertEquals("Unauthenticated:deny-by-default:no-security-annotation",
        audit.single(AccessDenied.class).reason());

    PublicHandlers open = new PublicHandlers();
    Recording served = new Recording();
    anonymousFilter().authorizeAndHandle(request("/public/all"), served, open::deleteAll, base, PublicHandlers.class);
    assertEquals(200, served.status, "@PublicRoute on the handler class opts its inherited methods in");
  }

  @Test
  @DisplayName("isOpenByOmission gives the verdict the filter acts on")
  void isOpenByOmission_matchesTheFilter() throws NoSuchMethodException {
    Method deleteAll = CrudHandlers.class.getMethod("deleteAll", RestRequest.class, RestResponse.class);
    Method purge = BaseOps.class.getMethod("purge", RestRequest.class, RestResponse.class);

    assertFalse(RestAuthorizationFilter.isOpenByOmission(deleteAll, AdminHandlers.class), "restricted by the class");
    assertTrue(RestAuthorizationFilter.isOpenByOmission(deleteAll, CrudHandlers.class));
    assertTrue(RestAuthorizationFilter.isOpenByOmission(deleteAll, PlainHandlers.class));
    assertFalse(RestAuthorizationFilter.isOpenByOmission(deleteAll, PublicHandlers.class), "declared public");
    assertFalse(RestAuthorizationFilter.isOpenByOmission(purge, TenantOps.class), "restricted by the overridden method");
    assertFalse(RestAuthorizationFilter.isOpenByOmission(purge, OpenedOps.class), "declared public on the override");
  }

  @Test
  @DisplayName("a handler class that does not inherit the method is refused as a wiring error before anything runs")
  void unrelatedHandlerClass_isAWiringError() throws NoSuchMethodException {
    Method base = CrudHandlers.class.getMethod("deleteAll", RestRequest.class, RestResponse.class);
    TenantOps tenant = new TenantOps();

    assertThrows(IllegalArgumentException.class, () -> anonymousFilter().authorizeAndHandle(
        request("/tenant/purge"), new Recording(), tenant::purge, base, TenantOps.class));
    assertNull(tenant.purged);
  }

  // ── helpers and fixtures ──

  private static RestAuthorizationFilter anonymousFilter() {
    return new RestAuthorizationFilter(request -> Optional.empty());
  }

  private static RestAuthorizationFilter filterFor(String role) {
    return new RestAuthorizationFilter(request ->
        Optional.of(new JCustosSubject("u1", "User", Set.of(new RoleName(role)), Set.of())));
  }

  private static RestRequest request(String path) {
    return new RestAuthorizationFilterTest.SimpleRestRequest("DELETE", path, Map.of(), Map.of());
  }

  static final class Recording implements RestResponse {
    int status = 200;
    String body;

    @Override public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override public void body(String body) {
      this.body = body;
    }
  }

  /** Shared CRUD plumbing, no annotation of its own. */
  public static class CrudHandlers {
    String deleted;

    public void deleteAll(RestRequest request, RestResponse response) {
      deleted = "deleted everything";
      response.status(200);
    }
  }

  /** The admin API: the class-level restriction is meant to cover every endpoint. */
  @RequiresRole("ADMIN")
  public static final class AdminHandlers extends CrudHandlers {
    public void own(RestRequest request, RestResponse response) {
      response.status(200);
    }
  }

  /** No restriction anywhere. */
  public static final class PlainHandlers extends CrudHandlers {
  }

  @PublicRoute
  public static final class PublicHandlers extends CrudHandlers {
  }

  /** Variant 2: the restriction sits on the base method, the subclass overrides without repeating it. */
  public static class BaseOps {
    String purged;

    @RequiresRole("ADMIN")
    public void purge(RestRequest request, RestResponse response) {
      purged = "base purge";
      response.status(200);
    }
  }

  public static final class TenantOps extends BaseOps {
    @Override
    public void purge(RestRequest request, RestResponse response) {
      purged = "tenant purge";
      response.status(200);
    }
  }

  public static final class OpenedOps extends BaseOps {
    @Override
    @PublicRoute
    public void purge(RestRequest request, RestResponse response) {
      purged = "opened purge";
      response.status(200);
    }
  }
}
