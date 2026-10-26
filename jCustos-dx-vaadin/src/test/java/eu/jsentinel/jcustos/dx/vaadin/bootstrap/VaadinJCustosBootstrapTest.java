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
package eu.jsentinel.jcustos.dx.vaadin.bootstrap;

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.vaadin.VaadinSessionSubjectStore;
import eu.jsentinel.jcustos.dx.bootstrap.JCustosBootstrapException;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJCustosService;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class VaadinJCustosBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  void happyPath_registersBothServicesAndReturnsRuntime() {
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .install();

    assertEquals(JCustosBootstrapMode.COMMUNITY_DEFAULTS, runtime.mode());
    // V00.73: authn + authz + auto-wired VaadinSessionSubjectStore
    // V00.74: + auto-wired VaadinSessionTokenCredentialStore (SPI default)
    assertEquals(4, runtime.services().size());
    // V00.73: warnings may include INFO secure-route/discovery-disabled;
    // assert "no ERROR warnings" instead of "no warnings at all".
    assertTrue(runtime.warnings().stream()
        .noneMatch(w -> w.severity() == Severity.ERROR));

    RegisteredJCustosService first = runtime.services().get(0);
    assertEquals(AuthenticationService.class, first.spi());
    assertEquals(authn.getClass(), first.impl());
    assertEquals("bootstrap-explicit", first.source());
    assertFalse(first.defaulted());

    // Verify resolver was wired
    assertSame(authn, JCustosServiceResolver.findAuthenticationService().orElseThrow());
    assertSame(authz, JCustosServiceResolver.findAuthorizationService().orElseThrow());
  }

  @Test
  void strictMode_missingAuthn_throws() {
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JCustosBootstrapException ex = assertThrows(JCustosBootstrapException.class, () ->
        VaadinSecurity.bootstrap()
            .mode(JCustosBootstrapMode.STRICT)
            .authorization(authz)
            .install());

    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "missing-authentication-service".equals(w.code())));
  }

  @Test
  void strictMode_missingAuthz_throws() {
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);

    JCustosBootstrapException ex = assertThrows(JCustosBootstrapException.class, () ->
        VaadinSecurity.bootstrap()
            .mode(JCustosBootstrapMode.STRICT)
            .authentication(authn)
            .install());

    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "missing-authorization-service".equals(w.code())));
  }

  @Test
  void productionMode_missingAuthn_returnsWarning() {
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .mode(JCustosBootstrapMode.PRODUCTION)
        .authorization(authz)
        .install();

    assertNotNull(runtime);
    boolean found = runtime.warnings().stream()
        .anyMatch(w -> "missing-authentication-service".equals(w.code())
            && w.severity() == Severity.ERROR);
    assertTrue(found, "expected ERROR warning for missing authentication service");
  }

  @Test
  void constraintlessSecureRoute_surfacesNoConstraintsAdvisory() {
    // R035: a constraint-less @SecureRoute is fail-closed (deny anonymous) but a
    // missing constraint is often an oversight — the bootstrap must surface a
    // non-fatal secure-route/no-constraints WARNING when discovery is enabled.
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    eu.jsentinel.jcustos.dx.vaadin.routes.SecureRouteDiscovery discovery =
        new eu.jsentinel.jcustos.dx.vaadin.routes.SecureRouteDiscovery() {
          @Override public java.util.stream.Stream<String> discoverPolicyNames() {
            return java.util.stream.Stream.empty();
          }
          @Override public java.util.stream.Stream<String> discoverConstraintlessRouteNames() {
            return java.util.stream.Stream.of("OpenView");
          }
        };

    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .discoverSecureRoutes(discovery)
        .install();

    assertTrue(runtime.warnings().stream()
            .anyMatch(w -> "secure-route/no-constraints".equals(w.code())
                && w.severity() == Severity.WARNING
                && w.message().contains("OpenView")),
        "a constraint-less @SecureRoute must surface a secure-route/no-constraints advisory");
  }

  private static eu.jsentinel.jcustos.dx.vaadin.routes.SecureRouteDiscovery
      unannotatedDiscovery(String routeName) {
    return new eu.jsentinel.jcustos.dx.vaadin.routes.SecureRouteDiscovery() {
      @Override public java.util.stream.Stream<String> discoverPolicyNames() {
        return java.util.stream.Stream.empty();
      }
      @Override public java.util.stream.Stream<String> discoverUnannotatedRouteNames() {
        return java.util.stream.Stream.of(routeName);
      }
    };
  }

  @Test
  @DisplayName("JS-SEC-024: deny-by-default + un-annotated route → STRICT bootstrap exception")
  void denyByDefault_unannotatedRoute_strictThrows() {
    JCustosServiceResolver.setDenyByDefault(true);
    JCustosBootstrapException ex = assertThrows(JCustosBootstrapException.class, () ->
        VaadinSecurity.bootstrap()
            .authentication(FakeAuthenticationService.forType(String.class))
            .authorization(new FakeAuthorizationService<String>())
            .mode(JCustosBootstrapMode.STRICT)
            .discoverSecureRoutes(unannotatedDiscovery("ForgottenView"))
            .install());
    assertTrue(ex.warnings().stream()
            .anyMatch(w -> "deny-by-default/unannotated-route".equals(w.code())
                && w.message().contains("ForgottenView")),
        "STRICT must throw a deny-by-default/unannotated-route finding");
  }

  @Test
  @DisplayName("JS-SEC-024: deny-by-default + un-annotated route → PRODUCTION records the finding")
  void denyByDefault_unannotatedRoute_productionWarns() {
    JCustosServiceResolver.setDenyByDefault(true);
    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .mode(JCustosBootstrapMode.PRODUCTION)
        .discoverSecureRoutes(unannotatedDiscovery("ForgottenView"))
        .install();
    assertTrue(runtime.warnings().stream()
            .anyMatch(w -> "deny-by-default/unannotated-route".equals(w.code())
                && w.severity() == Severity.ERROR),
        "PRODUCTION must record the deny-by-default/unannotated-route finding");
  }

  @Test
  @DisplayName("JS-SEC-024: deny-by-default OFF → no unannotated-route finding is emitted")
  void denyByDefaultOff_unannotatedRoute_noFinding() {
    // deny-by-default defaults to off — the enumeration must not run.
    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .mode(JCustosBootstrapMode.PRODUCTION)
        .discoverSecureRoutes(unannotatedDiscovery("ForgottenView"))
        .install();
    assertFalse(runtime.warnings().stream()
            .anyMatch(w -> "deny-by-default/unannotated-route".equals(w.code())),
        "with deny-by-default off, no unannotated-route finding may be emitted");
  }

  @Test
  void loginRouteAndStepUpRoutePropagate() {
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .loginRoute("signin")
        .stepUpRoute("step-up")
        .install();

    assertEquals("step-up", JCustosServiceResolver.stepUpRouteName());
    // JS-SEC-084: .loginRoute(...) used to be discarded.
    assertEquals("signin", JCustosServiceResolver.loginRouteName(),
        "the configured login route must reach the resolver the listeners consult");
  }

  @Test
  void subjectTypeMismatch_isReported() {
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .subjectType(Integer.class)
        .audit(a -> a.logging())
        .install();

    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "bootstrap/subject-type-mismatch".equals(w.code())),
        "JS-SEC-084: .subjectType(...) is checked against the authentication service; got " + runtime.warnings());
  }

  @Test
  void matchingSubjectType_isSilent() {
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .subjectType(String.class)
        .audit(a -> a.logging())
        .install();

    assertTrue(runtime.warnings().stream()
        .noneMatch(w -> "bootstrap/subject-type-mismatch".equals(w.code())));
  }

  @Test
  void secondInstallCallThrows() {
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    VaadinJCustosBootstrap b = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz);

    b.install();
    try {
      b.install();
      fail("Expected IllegalStateException on second install()");
    } catch (IllegalStateException expected) {
      // ok
    }
  }

  @Test
  void subjectTypeAndFlagsAreOptional() {
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    // V00.73: .sessionManagementView() is no longer a no-op flag — it
    // requires .sessions(s -> s.storeBacked(...)). This test stays
    // narrow to subjectType + securedComponents, which remain optional.
    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .subjectType(String.class)
        .securedComponents()
        .install();

    assertTrue(runtime.warnings().stream()
        .noneMatch(w -> w.severity() == Severity.ERROR));
  }

  @Test
  @SuppressWarnings("deprecation")
  void sessionManagementView_withStore_publishesContextAndAddsRuntimeEntry() {
    eu.jsentinel.jcustos.dx.vaadin.routes.SessionManagementContext.reset();
    eu.jsentinel.jcustos.session.SessionStore store =
        new eu.jsentinel.jcustos.session.InMemorySessionStore();

    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .sessions(s -> s.storeBacked(store))
        .sessionManagementView()
        .install();

    boolean routeEntry = runtime.services().stream()
        .anyMatch(s -> eu.jsentinel.jcustos.dx.vaadin.routes.SessionManagementRoute.class.equals(s.spi())
            && "bootstrap-activated".equals(s.source()));
    assertTrue(routeEntry, "expected SessionManagementRoute entry in runtime");
    // The route's no-arg constructor needs Vaadin's Grid/Composite
    // (Jackson on classpath) which test classpath does not pull in.
    // The runtime-entry assertion above is the V00.73 install-time
    // contract; route instantiation happens at navigation time in
    // the real app.
  }

  @Test
  void sessionManagementView_withoutStore_strictThrows() {
    eu.jsentinel.jcustos.dx.vaadin.routes.SessionManagementContext.reset();
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JCustosBootstrapException ex = assertThrows(JCustosBootstrapException.class, () ->
        VaadinSecurity.bootstrap()
            .mode(JCustosBootstrapMode.STRICT)
            .authentication(authn)
            .authorization(authz)
            .sessionManagementView()
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "session-management-view-without-session-store".equals(w.code())));
  }

  @Test
  void sessionManagementView_withoutStore_productionWarns() {
    eu.jsentinel.jcustos.dx.vaadin.routes.SessionManagementContext.reset();
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .mode(JCustosBootstrapMode.PRODUCTION)
        .authentication(authn)
        .authorization(authz)
        .sessionManagementView()
        .install();
    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "session-management-view-without-session-store".equals(w.code())
            && w.severity() == Severity.ERROR));
  }

  @Test
  void vaadinSubjectStore_isPresentInRuntime() {
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .install();

    // P9: regardless of discovery mechanism (ServiceLoader-via-META-INF
    // in security-vaadin, or bootstrap-default fallback when no
    // ServiceLoader provider is on the classpath), VaadinSessionSubjectStore
    // is the wired SubjectStore and shows up in JCustosRuntime.
    boolean entryPresent = runtime.services().stream()
        .anyMatch(s -> SubjectStore.class.equals(s.spi())
            && VaadinSessionSubjectStore.class.equals(s.impl()));
    assertTrue(entryPresent, "expected VaadinSessionSubjectStore in runtime services");
    assertEquals(VaadinSessionSubjectStore.class,
        SubjectStores.findSubjectStore().orElseThrow().getClass());
  }

  @Test
  void vaadinSubjectStore_explicitWins() {
    SubjectStore explicit = new eu.jsentinel.jcustos.test.InMemorySubjectStore();
    SubjectStores.setSubjectStore(explicit);

    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .install();

    boolean explicitEntry = runtime.services().stream()
        .anyMatch(s -> SubjectStore.class.equals(s.spi())
            && explicit.getClass().equals(s.impl())
            && !s.defaulted()
            && "bootstrap-explicit".equals(s.source()));
    assertTrue(explicitEntry, "explicitly-registered SubjectStore must win");
    assertSame(explicit, SubjectStores.findSubjectStore().orElseThrow(),
        "auto-wire must not replace an explicit registration");
  }

  // ── V00.74 A2.1 errorView / afterLoginRoute / passwordResetRoute ──

  @Test
  void errorView_publishesToVaadinRouteContextAndRuntime() {
    eu.jsentinel.jcustos.dx.vaadin.routes.VaadinRouteContext.reset();
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .errorView(MyErrorView.class)
        .install();

    assertSame(MyErrorView.class,
        eu.jsentinel.jcustos.dx.vaadin.routes.VaadinRouteContext.errorView()
            .orElseThrow());
    assertTrue(runtime.services().stream()
        .anyMatch(s -> eu.jsentinel.jcustos.dx.vaadin.routes.VaadinRouteContext.class.equals(s.spi())
            && MyErrorView.class.equals(s.impl())
            && "bootstrap-error-view".equals(s.source())));
  }

  @Test
  void afterLoginRoute_publishesToContextAndRuntime() {
    eu.jsentinel.jcustos.dx.vaadin.routes.VaadinRouteContext.reset();
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .afterLoginRoute("dashboard")
        .install();

    assertEquals("dashboard",
        eu.jsentinel.jcustos.dx.vaadin.routes.VaadinRouteContext.afterLoginRoute()
            .orElseThrow());
    assertTrue(runtime.services().stream()
        .anyMatch(s -> eu.jsentinel.jcustos.dx.vaadin.routes.VaadinRouteContext.class.equals(s.spi())
            && "bootstrap-after-login=dashboard".equals(s.source())));
  }

  @Test
  void passwordResetRoute_publishesToContextAndRuntime() {
    eu.jsentinel.jcustos.dx.vaadin.routes.VaadinRouteContext.reset();
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .passwordResetRoute("password-reset")
        .install();

    assertEquals("password-reset",
        eu.jsentinel.jcustos.dx.vaadin.routes.VaadinRouteContext.passwordResetRoute()
            .orElseThrow());
    assertTrue(runtime.services().stream()
        .anyMatch(s -> eu.jsentinel.jcustos.dx.vaadin.routes.VaadinRouteContext.class.equals(s.spi())
            && "bootstrap-password-reset=password-reset".equals(s.source())));
  }

  @Test
  void afterLoginRoute_blankRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> VaadinSecurity.bootstrap().afterLoginRoute("   "));
  }

  @Test
  void passwordResetRoute_blankRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> VaadinSecurity.bootstrap().passwordResetRoute(""));
  }

  /** Test-only stand-in for a real Vaadin error view; class identity is all that matters here. */
  private static final class MyErrorView { }

  // ── JS-SEC-068 (CWE-306): the session-management route needs an access requirement ──

  @Test
  void sessionManagementView_withRequirement_publishesRequirementWithoutWarning() {
    eu.jsentinel.jcustos.dx.vaadin.routes.SessionManagementContext.reset();
    eu.jsentinel.jcustos.session.SessionStore store =
        new eu.jsentinel.jcustos.session.InMemorySessionStore();
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();
    var requirement = eu.jsentinel.jcustos.components.SecuredVisibility.Requirement.permission(
        new eu.jsentinel.jcustos.authorization.api.permissions.PermissionName("admin:sessions"));

    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .sessions(s -> s.storeBacked(store))
        .sessionManagementView(requirement)
        .install();

    assertEquals(java.util.Optional.of(requirement),
        eu.jsentinel.jcustos.dx.vaadin.routes.SessionManagementContext.requirement());
    assertTrue(runtime.warnings().stream()
        .noneMatch(w -> "session-management-view-without-requirement".equals(w.code())));
  }

  @Test
  @SuppressWarnings("deprecation")
  void sessionManagementView_withoutRequirement_strictThrows() {
    eu.jsentinel.jcustos.dx.vaadin.routes.SessionManagementContext.reset();
    eu.jsentinel.jcustos.session.SessionStore store =
        new eu.jsentinel.jcustos.session.InMemorySessionStore();
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JCustosBootstrapException ex = assertThrows(JCustosBootstrapException.class, () ->
        VaadinSecurity.bootstrap()
            .mode(JCustosBootstrapMode.STRICT)
            .authentication(authn)
            .authorization(authz)
            .sessions(s -> s.storeBacked(store))
            .sessionManagementView()
            .install());

    assertTrue(ex.warnings().stream().anyMatch(w ->
        w.severity() == Severity.ERROR
            && "session-management-view-without-requirement".equals(w.code())));
    assertTrue(eu.jsentinel.jcustos.dx.vaadin.routes.SessionManagementContext.requirement().isEmpty());
  }

  @Test
  @SuppressWarnings("deprecation")
  void sessionManagementView_withoutRequirement_defaultModeWarnsAndKeepsRouteClosed() {
    eu.jsentinel.jcustos.dx.vaadin.routes.SessionManagementContext.reset();
    eu.jsentinel.jcustos.session.SessionStore store =
        new eu.jsentinel.jcustos.session.InMemorySessionStore();
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .sessions(s -> s.storeBacked(store))
        .sessionManagementView()
        .install();

    assertTrue(runtime.warnings().stream().anyMatch(w ->
        w.severity() == Severity.WARNING
            && "session-management-view-without-requirement".equals(w.code())));
    assertTrue(eu.jsentinel.jcustos.dx.vaadin.routes.SessionManagementContext.requirement().isEmpty(),
        "no requirement published → SessionManagementAccess denies everyone");
  }

  @Test
  void sessionManagementView_emptyRequirement_rejected() {
    assertThrows(IllegalArgumentException.class, () ->
        VaadinSecurity.bootstrap().sessionManagementView(
            eu.jsentinel.jcustos.components.SecuredVisibility.Requirement.none()));
  }
}
