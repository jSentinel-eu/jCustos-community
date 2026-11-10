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
package eu.jsentinel.jcustos.authorization.impl;

import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.navigation.AccessDecision;
import eu.jsentinel.jcustos.authorization.navigation.NavigationAccessDecision;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.Location;
import com.vaadin.flow.router.NavigationTrigger;
import com.vaadin.flow.router.Route;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-152 (CWE-636, CWE-285): the post-condition of a denial and the two decision
 * mappers, exercised with a real {@link BeforeEnterEvent} over the real router and route
 * registry of the Browserless environment - no recording subclass, so what the test sees
 * is what Vaadin's navigation would act on.
 */
@DisplayName("JS-SEC-152 - a denial never leaves the event without a target")
class DenialPostConditionBrowserlessTest extends BrowserlessTest {

  private static final String MISSING = "fc-post/not-registered";

  private final VaadinAccessDecisionMapper mapper = new VaadinAccessDecisionMapper();
  private final VaadinNavigationAccessDecisionMapper navigationMapper =
      new VaadinNavigationAccessDecisionMapper();

  private static BeforeEnterEvent eventFor(Class<? extends Div> target) {
    UI ui = UI.getCurrent();
    return new BeforeEnterEvent(
        ui.getInternals().getRouter(),
        NavigationTrigger.PROGRAMMATIC,
        new Location("fc-post/protected"),
        target,
        ui,
        List.of());
  }

  private static void assertReroutedToSecurityError(BeforeEnterEvent event) {
    assertTrue(event.hasRerouteTarget(), "the event must carry a reroute target");
    assertTrue(event.hasErrorParameter(), "the reroute target must be an error view");
    assertInstanceOf(SecurityException.class, event.getErrorParameter().getException());
    assertEquals("Access denied", event.getErrorParameter().getCustomMessage(),
        "the user-facing message stays generic");
  }

  // ── the Vaadin behaviour the finding rests on ──────────────────

  @Test
  @DisplayName("Vaadin: rerouteTo(String) with an unknown route sets no target")
  void vaadinIgnoresRerouteToUnknownRoute() {
    BeforeEnterEvent event = eventFor(ProtectedTarget.class);

    event.rerouteTo(MISSING);

    assertTrue(event.hasUnknownReroute());
    assertFalse(event.hasRerouteTarget(),
        "this is why a denial must not rely on rerouteTo(String) alone");
  }

  // ── AuthorizationListener.failClosedIfUnhandled ────────────────

  @Test
  @DisplayName("post-condition: a denial that left no target is rerouted to the error view")
  void postCondition_unhandledDenial_isReroutedToError() {
    BeforeEnterEvent event = eventFor(ProtectedTarget.class);
    event.rerouteTo(MISSING); // what a mapper without the resolve-first step leaves behind

    AuthorizationListener.failClosedIfUnhandled(new AccessDecision.Reroute(MISSING, false), event);

    assertReroutedToSecurityError(event);
  }

  @Test
  @DisplayName("post-condition: a denial that was never applied at all is rerouted to the error view")
  void postCondition_unappliedDenial_isReroutedToError() {
    BeforeEnterEvent event = eventFor(ProtectedTarget.class);

    AuthorizationListener.failClosedIfUnhandled(
        AccessDecision.deniedWithError(SecurityException.class, "Access denied"), event);

    assertReroutedToSecurityError(event);
  }

  @Test
  @DisplayName("post-condition: Granted is left alone")
  void postCondition_granted_isLeftAlone() {
    BeforeEnterEvent event = eventFor(ProtectedTarget.class);

    AuthorizationListener.failClosedIfUnhandled(AccessDecision.granted(), event);

    assertFalse(event.hasRerouteTarget());
    assertFalse(event.hasForwardTarget());
    assertFalse(event.hasErrorParameter());
  }

  @Test
  @DisplayName("post-condition: a denial that already set a reroute target is left alone")
  void postCondition_handledDenial_isLeftAlone() {
    BeforeEnterEvent event = eventFor(ProtectedTarget.class);
    event.rerouteTo("fc-post/signin");

    AuthorizationListener.failClosedIfUnhandled(
        new AccessDecision.Reroute("fc-post/signin", false), event);

    assertSame(SigninTarget.class, event.getRerouteTargetType());
    assertFalse(event.hasErrorParameter(), "a working reroute must not be replaced");
  }

  @Test
  @DisplayName("post-condition: a denial that already set a forward target is left alone")
  void postCondition_forwardedDenial_isLeftAlone() {
    BeforeEnterEvent event = eventFor(ProtectedTarget.class);
    event.forwardTo("fc-post/signin");

    AuthorizationListener.failClosedIfUnhandled(
        new AccessDecision.Reroute("fc-post/signin", true), event);

    assertSame(SigninTarget.class, event.getForwardTargetType());
    assertFalse(event.hasRerouteTarget());
  }

  // ── VaadinAccessDecisionMapper ─────────────────────────────────

  @Test
  @DisplayName("mapper: Reroute to a registered route sets that route as the reroute target")
  void mapper_rerouteToRegisteredRoute() {
    BeforeEnterEvent event = eventFor(ProtectedTarget.class);

    mapper.apply(new AccessDecision.Reroute("fc-post/signin", false), event);

    assertSame(SigninTarget.class, event.getRerouteTargetType());
    assertFalse(event.hasErrorParameter());
  }

  @Test
  @DisplayName("mapper: Reroute(asForward) to a registered route sets that route as the forward target")
  void mapper_forwardToRegisteredRoute() {
    BeforeEnterEvent event = eventFor(ProtectedTarget.class);

    mapper.apply(new AccessDecision.Reroute("fc-post/signin", true), event);

    assertSame(SigninTarget.class, event.getForwardTargetType());
  }

  @Test
  @DisplayName("mapper: Reroute to a route that is not registered ends in the error view")
  void mapper_rerouteToUnregisteredRoute() {
    BeforeEnterEvent event = eventFor(ProtectedTarget.class);

    mapper.apply(new AccessDecision.Reroute(MISSING, false), event);

    assertReroutedToSecurityError(event);
  }

  @Test
  @DisplayName("mapper: Reroute(asForward) to a route that is not registered ends in the error view")
  void mapper_forwardToUnregisteredRoute() {
    BeforeEnterEvent event = eventFor(ProtectedTarget.class);

    mapper.apply(new AccessDecision.Reroute(MISSING, true), event);

    assertFalse(event.hasForwardTarget());
    assertReroutedToSecurityError(event);
  }

  @Test
  @DisplayName("mapper: RerouteWithParameter to a route that is not registered ends in the error view")
  void mapper_rerouteWithParameterToUnregisteredRoute() {
    BeforeEnterEvent event = eventFor(ProtectedTarget.class);

    mapper.apply(new AccessDecision.RerouteWithParameter<>(MISSING, 42), event);

    assertReroutedToSecurityError(event);
  }

  @Test
  @DisplayName("mapper: RerouteWithParameters to a route that is not registered ends in the error view")
  void mapper_rerouteWithParametersToUnregisteredRoute() {
    BeforeEnterEvent event = eventFor(ProtectedTarget.class);

    mapper.apply(new AccessDecision.RerouteWithParameters<>(MISSING, List.of("a", "b")), event);

    assertReroutedToSecurityError(event);
  }

  // ── VaadinNavigationAccessDecisionMapper ───────────────────────

  @Test
  @DisplayName("navigation mapper: AccessDenied to a registered route reroutes there")
  void navigationMapper_accessDeniedToRegisteredRoute() {
    BeforeEnterEvent event = eventFor(ProtectedTarget.class);

    navigationMapper.apply(NavigationAccessDecision.accessDenied("fc-post/signin", false), event,
        () -> UnroutedLoginView.class, () -> SigninTarget.class);

    assertSame(SigninTarget.class, event.getRerouteTargetType());
  }

  @Test
  @DisplayName("navigation mapper: AccessDenied to a route that is not registered ends in the error view")
  void navigationMapper_accessDeniedToUnregisteredRoute() {
    BeforeEnterEvent event = eventFor(ProtectedTarget.class);

    navigationMapper.apply(NavigationAccessDecision.accessDenied(MISSING, false), event,
        () -> UnroutedLoginView.class, () -> SigninTarget.class);

    assertReroutedToSecurityError(event);
  }

  @Test
  @DisplayName("navigation mapper: LoginRequired with a login view that is not a route ends in the error view")
  void navigationMapper_loginRequiredWithUnroutedLoginView() {
    BeforeEnterEvent event = eventFor(ProtectedTarget.class);

    navigationMapper.apply(NavigationAccessDecision.loginRequired(), event,
        () -> UnroutedLoginView.class, () -> SigninTarget.class);

    assertFalse(event.hasForwardTarget());
    assertReroutedToSecurityError(event);
  }

  @Test
  @DisplayName("navigation mapper: LoginRequired without a login view ends in the error view")
  void navigationMapper_loginRequiredWithoutLoginView() {
    BeforeEnterEvent event = eventFor(ProtectedTarget.class);

    navigationMapper.apply(NavigationAccessDecision.loginRequired(), event,
        () -> null, () -> SigninTarget.class);

    assertReroutedToSecurityError(event);
  }

  // ── Fixtures ───────────────────────────────────────────────────

  @Route("fc-post/protected")
  public static class ProtectedTarget extends Div {
  }

  @Route("fc-post/signin")
  public static class SigninTarget extends Div {
  }

  /** A login view that is deliberately not registered as a route. */
  public static class UnroutedLoginView extends LoginView {
    @Override public boolean checkCredentials() { return false; }
    @Override public void navigateToApp() { /* not used */ }
    @Override public void reactOnFailedLogin() { /* not used */ }
  }
}
