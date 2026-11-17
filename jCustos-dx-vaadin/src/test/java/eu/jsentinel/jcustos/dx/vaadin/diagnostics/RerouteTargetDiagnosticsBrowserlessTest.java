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
package eu.jsentinel.jcustos.dx.vaadin.diagnostics;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.dx.bootstrap.JCustosBootstrapException;
import eu.jsentinel.jcustos.dx.diagnostics.DiagnosticReportBuilder;
import eu.jsentinel.jcustos.dx.diagnostics.DiscoveredService;
import eu.jsentinel.jcustos.dx.diagnostics.DuplicateService;
import eu.jsentinel.jcustos.dx.diagnostics.MissingRecommendedService;
import eu.jsentinel.jcustos.dx.diagnostics.ServiceWarning;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinJCustosBootstrap;
import eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinSecurity;
import eu.jsentinel.jcustos.logout.SubjectClearingLogoutService;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.Route;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-152 (CWE-636, CWE-285): the login route name and the step-up route name must
 * resolve to registered routes. The authorisation listener reroutes a denied visitor to
 * these names; a name without a route ends in the error view. The diagnostics contributor
 * reports it, and the bootstrap carries the severity - a warning, an error in STRICT and
 * PRODUCTION.
 * <p>
 * Runs in the Browserless environment, so the checks read a real route registry.
 */
@DisplayName("JS-SEC-152 - diagnostics for a login / step-up route that is not registered")
class RerouteTargetDiagnosticsBrowserlessTest extends BrowserlessTest {

  private static final String SIGNIN = "sa52-diag/signin";
  private static final String VERIFY = "sa52-diag/verify";
  private static final String MISSING_LOGIN = "sa52-diag/no-such-login";
  private static final String MISSING_STEP_UP = "sa52-diag/no-such-step-up";

  @BeforeEach
  @AfterEach
  void resetSecurity() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
  }

  // ── RouteNameCheck ─────────────────────────────────────────────

  @Test
  @DisplayName("RouteNameCheck: registered, not registered, blank")
  void routeNameCheck() {
    assertEquals(RouteNameCheck.Result.REGISTERED, RouteNameCheck.check(SIGNIN));
    assertEquals(RouteNameCheck.Result.UNREGISTERED, RouteNameCheck.check(MISSING_LOGIN));
    assertEquals(RouteNameCheck.Result.UNREGISTERED, RouteNameCheck.check(" "));
    assertEquals(RouteNameCheck.Result.UNREGISTERED, RouteNameCheck.check(null));
  }

  // ── VaadinDiagnosticContributor ────────────────────────────────

  @Test
  @DisplayName("contributor: both route names resolve - no finding")
  void contributor_resolvedRoutes_noFinding() {
    JCustosServiceResolver.setLoginRouteName(SIGNIN);
    JCustosServiceResolver.setStepUpRouteName(VERIFY);

    List<ServiceWarning> warnings = contribute();

    assertFalse(hasCode(warnings, VaadinDiagnosticContributor.LOGIN_ROUTE_UNRESOLVED));
    assertFalse(hasCode(warnings, VaadinDiagnosticContributor.STEP_UP_ROUTE_UNRESOLVED));
  }

  @Test
  @DisplayName("contributor: login route not registered - vaadin/login-route-unresolved names the route")
  void contributor_unresolvedLoginRoute() {
    JCustosServiceResolver.setLoginRouteName(MISSING_LOGIN);
    JCustosServiceResolver.setStepUpRouteName(VERIFY);

    List<ServiceWarning> warnings = contribute();

    ServiceWarning finding = warnings.stream()
        .filter(w -> VaadinDiagnosticContributor.LOGIN_ROUTE_UNRESOLVED.equals(w.code()))
        .findFirst().orElseThrow();
    assertTrue(finding.message().contains(MISSING_LOGIN));
    assertFalse(hasCode(warnings, VaadinDiagnosticContributor.STEP_UP_ROUTE_UNRESOLVED));
  }

  @Test
  @DisplayName("contributor: step-up route not registered - vaadin/step-up-route-unresolved names the route")
  void contributor_unresolvedStepUpRoute() {
    JCustosServiceResolver.setLoginRouteName(SIGNIN);
    JCustosServiceResolver.setStepUpRouteName(MISSING_STEP_UP);

    List<ServiceWarning> warnings = contribute();

    ServiceWarning finding = warnings.stream()
        .filter(w -> VaadinDiagnosticContributor.STEP_UP_ROUTE_UNRESOLVED.equals(w.code()))
        .findFirst().orElseThrow();
    assertTrue(finding.message().contains(MISSING_STEP_UP));
    assertFalse(hasCode(warnings, VaadinDiagnosticContributor.LOGIN_ROUTE_UNRESOLVED));
  }

  // ── bootstrap: severity gate ───────────────────────────────────

  @ParameterizedTest(name = "{0}")
  @EnumSource(JCustosBootstrapMode.class)
  @DisplayName("bootstrap: both routes registered - no route finding in any mode")
  void bootstrap_resolvedRoutes_noFinding(JCustosBootstrapMode mode) {
    List<JCustosBootstrapWarning> warnings = install(mode, SIGNIN, VERIFY);

    assertTrue(severityOf(warnings, VaadinDiagnosticContributor.LOGIN_ROUTE_UNRESOLVED).isEmpty());
    assertTrue(severityOf(warnings, VaadinDiagnosticContributor.STEP_UP_ROUTE_UNRESOLVED).isEmpty());
    assertTrue(severityOf(warnings, "vaadin/route-check-unavailable").isEmpty(),
        "the registry is readable here, so the check must not report itself as skipped");
  }

  @ParameterizedTest(name = "{0}")
  @EnumSource(value = JCustosBootstrapMode.class, names = {"COMMUNITY_DEFAULTS", "DEVELOPMENT"})
  @DisplayName("bootstrap: login route not registered - WARNING outside STRICT and PRODUCTION")
  void bootstrap_unresolvedLoginRoute_warning(JCustosBootstrapMode mode) {
    List<JCustosBootstrapWarning> warnings = install(mode, MISSING_LOGIN, VERIFY);

    assertEquals(Optional.of(Severity.WARNING),
        severityOf(warnings, VaadinDiagnosticContributor.LOGIN_ROUTE_UNRESOLVED));
  }

  @ParameterizedTest(name = "{0}")
  @EnumSource(value = JCustosBootstrapMode.class, names = {"STRICT", "PRODUCTION"})
  @DisplayName("bootstrap: login route not registered - ERROR in STRICT and PRODUCTION")
  void bootstrap_unresolvedLoginRoute_error(JCustosBootstrapMode mode) {
    List<JCustosBootstrapWarning> warnings = install(mode, MISSING_LOGIN, VERIFY);

    assertEquals(Optional.of(Severity.ERROR),
        severityOf(warnings, VaadinDiagnosticContributor.LOGIN_ROUTE_UNRESOLVED));
  }

  @ParameterizedTest(name = "{0}")
  @EnumSource(value = JCustosBootstrapMode.class, names = {"COMMUNITY_DEFAULTS", "DEVELOPMENT"})
  @DisplayName("bootstrap: configured step-up route not registered - WARNING outside STRICT and PRODUCTION")
  void bootstrap_unresolvedConfiguredStepUpRoute_warning(JCustosBootstrapMode mode) {
    List<JCustosBootstrapWarning> warnings = install(mode, SIGNIN, MISSING_STEP_UP);

    assertEquals(Optional.of(Severity.WARNING),
        severityOf(warnings, VaadinDiagnosticContributor.STEP_UP_ROUTE_UNRESOLVED));
  }

  @ParameterizedTest(name = "{0}")
  @EnumSource(value = JCustosBootstrapMode.class, names = {"STRICT", "PRODUCTION"})
  @DisplayName("bootstrap: configured step-up route not registered - ERROR in STRICT and PRODUCTION")
  void bootstrap_unresolvedConfiguredStepUpRoute_error(JCustosBootstrapMode mode) {
    List<JCustosBootstrapWarning> warnings = install(mode, SIGNIN, MISSING_STEP_UP);

    assertEquals(Optional.of(Severity.ERROR),
        severityOf(warnings, VaadinDiagnosticContributor.STEP_UP_ROUTE_UNRESOLVED));
  }

  @ParameterizedTest(name = "{0}")
  @EnumSource(JCustosBootstrapMode.class)
  @DisplayName("bootstrap: default step-up route without a view - WARNING in every mode, never an ERROR")
  void bootstrap_unresolvedDefaultStepUpRoute_warningOnly(JCustosBootstrapMode mode) {
    // no .stepUpRoute(...): the application never asked for step-up
    List<JCustosBootstrapWarning> warnings = install(mode, SIGNIN, null);

    assertEquals(Optional.of(Severity.WARNING),
        severityOf(warnings, VaadinDiagnosticContributor.STEP_UP_ROUTE_UNRESOLVED),
        "STRICT must not force an unused step-up view into existence");
  }

  @Test
  @DisplayName("bootstrap STRICT: an unregistered login route alone fails the boot")
  void bootstrap_strict_unresolvedLoginRouteFailsTheBoot() {
    List<JCustosBootstrapWarning> resolved = install(JCustosBootstrapMode.STRICT, SIGNIN, VERIFY);
    assertTrue(resolved.stream().noneMatch(w -> w.severity() == Severity.ERROR),
        "precondition: this configuration boots green in STRICT; got " + resolved);
    assertFalse(lastInstallThrew, "precondition: no JCustosBootstrapException");

    List<JCustosBootstrapWarning> unresolved = install(JCustosBootstrapMode.STRICT, MISSING_LOGIN, VERIFY);

    assertTrue(lastInstallThrew, "STRICT must refuse to boot with a login route that is not registered");
    assertEquals(List.of(VaadinDiagnosticContributor.LOGIN_ROUTE_UNRESOLVED),
        unresolved.stream().filter(w -> w.severity() == Severity.ERROR)
            .map(JCustosBootstrapWarning::code).toList(),
        "the route finding is the only error");
  }

  // ── helpers ────────────────────────────────────────────────────

  private boolean lastInstallThrew;

  /** Runs a bootstrap that is otherwise complete, so the route findings stand alone. */
  private List<JCustosBootstrapWarning> install(JCustosBootstrapMode mode, String loginRoute, String stepUpRoute) {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    VaadinJCustosBootstrap bootstrap = VaadinSecurity.bootstrap()
        .mode(mode)
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .audit(a -> a.logging())
        // JS-SEC-124: without a LogoutService the bootstrap reports logout/missing-service
        .logout(new SubjectClearingLogoutService<>(new InMemorySubjectStore(), String.class))
        // JS-SEC-097: without a SubjectIdResolver STRICT reports audit/no-subject-id-resolver
        .sessions(s -> s.subjectIdResolver(subject -> SubjectId.of("diag-subject")))
        .denyByDefault(true)
        .discoverSecureRoutes(new NoRoutesDiscovery())
        .loginRoute(loginRoute);
    if (stepUpRoute != null) {
      bootstrap.stepUpRoute(stepUpRoute);
    }
    try {
      lastInstallThrew = false;
      return bootstrap.install().warnings();
    } catch (JCustosBootstrapException strict) {
      lastInstallThrew = true;
      return strict.warnings();
    }
  }

  private static Optional<Severity> severityOf(List<JCustosBootstrapWarning> warnings, String code) {
    return warnings.stream().filter(w -> code.equals(w.code()))
        .map(JCustosBootstrapWarning::severity).findFirst();
  }

  private static List<ServiceWarning> contribute() {
    Recorder recorder = new Recorder();
    new VaadinDiagnosticContributor().contribute(recorder);
    return recorder.warnings;
  }

  private static boolean hasCode(List<ServiceWarning> warnings, String code) {
    return warnings.stream().anyMatch(w -> code.equals(w.code()));
  }

  /** A discovery without findings - keeps the deny-by-default cross-check out of the picture. */
  private static final class NoRoutesDiscovery
      implements eu.jsentinel.jcustos.dx.vaadin.routes.SecureRouteDiscovery {
    @Override
    public java.util.stream.Stream<String> discoverPolicyNames() {
      return java.util.stream.Stream.empty();
    }
  }

  private static final class Recorder implements DiagnosticReportBuilder {
    final List<ServiceWarning> warnings = new ArrayList<>();

    @Override
    public DiagnosticReportBuilder addDiscovered(DiscoveredService entry) {
      return this;
    }

    @Override
    public DiagnosticReportBuilder addMissing(MissingRecommendedService entry) {
      return this;
    }

    @Override
    public DiagnosticReportBuilder addDuplicate(DuplicateService entry) {
      return this;
    }

    @Override
    public DiagnosticReportBuilder addWarning(ServiceWarning warning) {
      warnings.add(warning);
      return this;
    }
  }

  // ── Fixtures ───────────────────────────────────────────────────

  @Route(SIGNIN)
  public static class DiagSigninView extends Div {
  }

  @Route(VERIFY)
  public static class DiagVerifyView extends Div {
  }
}
