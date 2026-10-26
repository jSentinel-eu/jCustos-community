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

import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.audit.AccessGranted;
import eu.jsentinel.jcustos.authorization.annotations.JCustosAnnotation;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.api.AccessEvaluator;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.authorization.navigation.AccessDecision;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.Route;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives {@link AuthorizationListener#beforeEnter} through real Vaadin
 * navigation in Browserless. Pins the audit emission (AccessGranted +
 * AccessDenied with the right route/reason) and the {@code ifPresent}
 * branch on the scanner result (unannotated route → no listener side
 * effects, no audit event).
 */
@DisplayName("AuthorizationListener — navigation-driven audit emission")
class AuthorizationListenerNavigationTest extends BrowserlessTest {

  private final RecordingAuditSink audit = new RecordingAuditSink();

  @org.junit.jupiter.api.BeforeEach
  @Override
  protected void initVaadinEnvironment() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    JCustosServiceResolver.setJCustosAuditService(audit);
    super.initVaadinEnvironment();
  }

  @AfterEach
  void cleanUp() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
  }

  @Test
  @DisplayName("JS-SEC-083: AccessGranted carries the resolver's subject id - no identity hash, no toString(), no credential")
  void granted_subjectIdComesFromResolver() {
    String subject = "carol:secret-password"; // toString() carries a credential
    SubjectStores.subjectStore().setCurrentSubject(subject, String.class);
    JCustosServiceResolver.<String>setSubjectIdResolver(s -> SubjectId.of("user-42"));

    navigate(GrantedFixture.class);

    AccessGranted event = audit.single(AccessGranted.class);
    assertEquals("user-42", event.subjectId(), "the audit subject id must correlate with LoginSucceeded");
    assertFalse(event.subjectId().contains("@"), "no identity-hash suffix");
    for (var recorded : audit.events()) {
      assertFalse(recorded.toString().contains("secret-password"),
          "no audit field may carry the credential: " + recorded);
    }
  }

  @Test
  @DisplayName("Granted decision publishes AccessGranted with the request path as the route")
  void granted_publishesAccessGranted() {
    navigate(GrantedFixture.class);

    AccessGranted event = audit.single(AccessGranted.class);
    assertEquals("GrantedFixture", event.route(),
        "AccessGranted must carry the navigation target's simple name as the route");
  }

  @Test
  @DisplayName("Reroute decision publishes AccessDenied with reason prefixed 'Reroute:'")
  void reroute_publishesAccessDenied() {
    try {
      navigate(RerouteFixture.class);
    } catch (IllegalArgumentException expected) {
      // navigate() throws when reroute redirects to a different target —
      // we still want to assert the audit was emitted before the
      // redirect happened.
    } catch (RuntimeException unexpected) {
      // ignore — any navigation-time exception is fine, we only care
      // that the audit was emitted before things blew up.
    }

    AccessDenied event = audit.single(AccessDenied.class);
    assertTrue(event.reason().startsWith("Reroute:"),
        "Reroute decision must produce a reason prefixed 'Reroute:'; got: "
            + event.reason());
  }

  @Test
  @DisplayName("Unannotated route: scanner returns empty → no audit event, no listener side effect")
  void unannotatedRoute_noAuditEvent() {
    navigate(PlainFixture.class);

    assertEquals(0, audit.events().size(),
        "unannotated routes must not produce any audit event; got: " + audit.events());
  }

  @Test
  @DisplayName("JS-SEC-024: deny-by-default denies an un-annotated route (AccessDenied audited)")
  void denyByDefault_unannotatedRoute_denied() {
    JCustosServiceResolver.setDenyByDefault(true);
    try {
      navigate(PlainFixture.class);
    } catch (RuntimeException expected) {
      // rerouteToError may throw in the browserless harness; the denial is
      // audited before the redirect, which is what we assert.
    }
    // The un-annotated PlainFixture is denied. (RF exit-review: the reroute target — a
    // Vaadin error view (HasErrorParameter) — is now exempt from deny-by-default, so the
    // denial no longer cascades into a second denial. We assert the PlainFixture denial.)
    boolean deniedPlain = audit.events().stream()
        .filter(AccessDenied.class::isInstance)
        .map(AccessDenied.class::cast)
        .anyMatch(d -> "PlainFixture".equals(d.route()) && d.reason().startsWith("Error:"));
    assertTrue(deniedPlain,
        "deny-by-default must deny the un-annotated PlainFixture route; got: " + audit.events());
  }

  @Test
  @DisplayName("JS-SEC-024: deny-by-default still allows a @PublicRoute route (no denial)")
  void denyByDefault_publicRoute_allowed() {
    JCustosServiceResolver.setDenyByDefault(true);
    navigate(PublicFixture.class);
    assertEquals(0, audit.events().size(),
        "@PublicRoute must stay reachable under deny-by-default; got: " + audit.events());
  }

  // ── Fixtures ──────────────────────────────────────────────────

  @Retention(RetentionPolicy.RUNTIME)
  @Target(ElementType.TYPE)
  @JCustosAnnotation(GrantingEvaluator.class)
  public @interface Granting { }

  public static final class GrantingEvaluator implements AccessEvaluator<Granting> {
    @Override public AccessDecision evaluate(AccessContext context, Granting annotation) {
      return AccessDecision.granted();
    }
  }

  @Retention(RetentionPolicy.RUNTIME)
  @Target(ElementType.TYPE)
  @JCustosAnnotation(ReroutingEvaluator.class)
  public @interface Rerouting { }

  public static final class ReroutingEvaluator implements AccessEvaluator<Rerouting> {
    @Override public AccessDecision evaluate(AccessContext context, Rerouting annotation) {
      return AccessDecision.reroute("plain", false);
    }
  }

  @Route("test/auth-listener-granted")
  @Granting
  public static class GrantedFixture extends Composite<Div> { }

  @Route("test/auth-listener-rerouted")
  @Rerouting
  public static class RerouteFixture extends Composite<Div> { }

  @Route("plain")
  public static class PlainFixture extends Composite<Div> { }

  @Route("public-plain")
  @PublicRoute
  public static class PublicFixture extends Composite<Div> { }
}
