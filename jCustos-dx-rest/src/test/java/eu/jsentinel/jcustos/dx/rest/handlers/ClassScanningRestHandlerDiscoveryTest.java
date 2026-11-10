/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.dx.rest.handlers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.rest.RestAuthorizationFilter;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestResponse;
import eu.jsentinel.jcustos.test.RecordingAuditSink;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * JS-SEC-114 (CWE-862): the start-up discovery has to reach the verdict the filter reaches
 * for a request - also for the methods a handler class inherits or overrides.
 */
@DisplayName("ClassScanningRestHandlerDiscovery - inherited and overriding handler methods (JS-SEC-114)")
class ClassScanningRestHandlerDiscoveryTest {

  private static final String DENIED_BY_DEFAULT = "deny-by-default:no-security-annotation";

  @AfterEach
  void reset() {
    JCustosServiceResolver.resetAll();
  }

  private static List<String> unprotected(Class<?>... handlerClasses) {
    return new ClassScanningRestHandlerDiscovery(handlerClasses).discoverUnannotatedHandlerNames().toList();
  }

  @Test
  @DisplayName("an unprotected method the handler class inherits is reported under the handler class")
  void inheritedUnprotectedMethod_isReported() {
    assertEquals(List.of(PlainHandlers.class.getName() + "#deleteAll"), unprotected(PlainHandlers.class),
        "PlainHandlers declares nothing itself - the inherited deleteAll is what it serves");
  }

  @Test
  @DisplayName("a restriction on the handler class covers its inherited methods: nothing is reported")
  void classRestriction_coversInheritedMethods() {
    assertEquals(List.of(), unprotected(AdminHandlers.class));
  }

  @Test
  @DisplayName("an override of a restricted method is protected; a sibling without any restriction is reported")
  void overrideOfRestrictedMethod_isProtected() {
    assertEquals(List.of(TenantOps.class.getName() + "#status"), unprotected(TenantOps.class));
  }

  @Test
  @DisplayName("@PublicRoute on the handler class or on the override is not a finding")
  void publicRoute_isNotAFinding() {
    assertEquals(List.of(), unprotected(PublicHandlers.class));
    assertEquals(List.of(OpenedOps.class.getName() + "#status"), unprotected(OpenedOps.class),
        "purge is @PublicRoute on the override; the inherited status carries nothing");
  }

  @Test
  @DisplayName("methods of java.lang.Object and static methods are no handlers")
  void objectAndStaticMethods_areSkipped() {
    List<String> names = unprotected(PlainHandlers.class);
    assertFalse(names.stream().anyMatch(n -> n.endsWith("#toString") || n.endsWith("#hashCode")
        || n.endsWith("#equals") || n.endsWith("#helper")), names.toString());
  }

  @Test
  @DisplayName("for every public method of every fixture the discovery and the filter reach the same verdict")
  void discoveryAndFilterAgree() {
    JCustosServiceResolver.setDenyByDefault(true);
    Class<?>[] fixtures = {
        CrudHandlers.class, PlainHandlers.class, AdminHandlers.class, PublicHandlers.class,
        BaseOps.class, TenantOps.class, OpenedOps.class};

    Set<String> reportedAtStartUp = new TreeSet<>(unprotected(fixtures));
    Set<String> deniedAtRunTime = new TreeSet<>();
    int checked = 0;
    for (Class<?> handlerClass : fixtures) {
      for (Method method : handlerClass.getMethods()) {
        if (method.getDeclaringClass() == Object.class || Modifier.isStatic(method.getModifiers())) {
          continue;
        }
        checked++;
        if (deniedByDefault(method, handlerClass)) {
          deniedAtRunTime.add(handlerClass.getName() + "#" + method.getName());
        }
      }
    }

    assertEquals(deniedAtRunTime, reportedAtStartUp,
        "the handlers reported at start-up must be exactly those a request finds denied by default");
    assertTrue(checked >= 10, "the comparison must have looked at the fixtures, checked=" + checked);
    assertFalse(reportedAtStartUp.isEmpty(), "the fixtures contain unprotected handlers");
  }

  /** Sends an anonymous request through the real filter and reads the reason of the refusal. */
  private static boolean deniedByDefault(Method method, Class<?> handlerClass) {
    RecordingAuditSink audit = new RecordingAuditSink();
    JCustosServiceResolver.setJCustosAuditService(audit);
    RestAuthorizationFilter filter = new RestAuthorizationFilter(request -> Optional.empty());
    filter.authorizeAndHandle(new Request(), new Response(), (request, response) -> { }, method, handlerClass);
    return audit.all(AccessDenied.class).stream().anyMatch(e -> e.reason().endsWith(DENIED_BY_DEFAULT));
  }

  private static final class Request implements RestRequest {
    @Override public String method() {
      return "DELETE";
    }

    @Override public String path() {
      return "/api/fixture";
    }

    @Override public Map<String, String> headers() {
      return Map.of();
    }

    @Override public Map<String, String> queryParameters() {
      return Map.of();
    }
  }

  private static final class Response implements RestResponse {
    @Override public void status(int statusCode) {
      // not asserted here
    }

    @Override public void body(String body) {
      // not asserted here
    }
  }

  // ── fixtures ────────────────────────────────────────────────────

  /** Shared CRUD plumbing, no annotation of its own. */
  public static class CrudHandlers {
    public void deleteAll(RestRequest request, RestResponse response) {
    }

    public static void helper() {
    }
  }

  public static final class PlainHandlers extends CrudHandlers {
  }

  @RequiresRole("ADMIN")
  public static final class AdminHandlers extends CrudHandlers {
    public void own(RestRequest request, RestResponse response) {
    }
  }

  @PublicRoute
  public static final class PublicHandlers extends CrudHandlers {
  }

  public static class BaseOps {
    @RequiresRole("ADMIN")
    public void purge(RestRequest request, RestResponse response) {
    }

    public void status(RestRequest request, RestResponse response) {
    }
  }

  public static final class TenantOps extends BaseOps {
    @Override
    public void purge(RestRequest request, RestResponse response) {
    }
  }

  public static final class OpenedOps extends BaseOps {
    @Override
    @PublicRoute
    public void purge(RestRequest request, RestResponse response) {
    }
  }
}
