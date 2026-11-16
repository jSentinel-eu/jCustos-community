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
package eu.jsentinel.jcustos.authorization.impl.failclosed.self;

import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.authorization.LoginListeners;
import eu.jsentinel.jcustos.authorization.annotations.JCustosAnnotation;
import eu.jsentinel.jcustos.authorization.api.AccessEvaluator;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.authorization.navigation.AccessDecision;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.browserless.ViewPackages;
import com.vaadin.flow.component.HasElement;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.InternalServerError;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.router.RouterLayout;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * JS-SEC-158 (CWE-636, CWE-285): a denial that reroutes or forwards to the navigation target
 * itself. Vaadin carries out a reroute or forward only when its target differs from the
 * navigation in progress ({@code AbstractNavigationStateRenderer.handleTriggeredBeforeEvent});
 * a target with the same class and route parameters is skipped and the denied view rendered.
 * The post-condition of JS-SEC-152 let it pass because the event carried a target.
 * <p>
 * Driven through {@code UI.navigate} over the real router and the route registry of this
 * package ({@link ViewPackages}); the evaluator of {@link DenyTo} denies every visitor and
 * names the route the annotation carries.
 */
@DisplayName("JS-SEC-158 - a denial that points to the denied view itself ends in the error view")
@ViewPackages
class SelfTargetDenialBrowserlessTest extends BrowserlessTest {

  private final RecordingAuditSink audit = new RecordingAuditSink();

  @BeforeEach
  @Override
  protected void initVaadinEnvironment() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    LoginListeners.reset();
    JCustosServiceResolver.setJCustosAuditService(audit);
    RerouteToItselfView.INSTANCES.set(0);
    ForwardToItselfView.INSTANCES.set(0);
    DeniedToLandingView.INSTANCES.set(0);
    LandingView.INSTANCES.set(0);
    RestrictedArea.INSTANCES.set(0);
    AreaPage.INSTANCES.set(0);
    AreaDeniedPage.INSTANCES.set(0);
    super.initVaadinEnvironment();
  }

  @AfterEach
  void cleanUp() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    LoginListeners.reset();
  }

  private static HasElement activeView() {
    List<HasElement> chain = UI.getCurrent().getInternals().getActiveRouterTargetsChain();
    assertFalse(chain.isEmpty(), "a view must be active after the navigation");
    return chain.get(0);
  }

  @Test
  @DisplayName("a reroute to the denied view itself ends in the error view; the view is never instantiated")
  void rerouteToItself_endsInErrorView() {
    UI.getCurrent().navigate(RerouteToItselfView.ROUTE);

    assertEquals(0, RerouteToItselfView.INSTANCES.get(),
        "the denied view must never be instantiated");
    assertInstanceOf(InternalServerError.class, activeView());
    assertEquals("RerouteToItselfView", audit.single(AccessDenied.class).route());
  }

  @Test
  @DisplayName("a forward to the denied view itself ends in the error view; the view is never instantiated")
  void forwardToItself_endsInErrorView() {
    UI.getCurrent().navigate(ForwardToItselfView.ROUTE);

    assertEquals(0, ForwardToItselfView.INSTANCES.get(),
        "the denied view must never be instantiated");
    assertInstanceOf(InternalServerError.class, activeView());
    assertEquals("ForwardToItselfView", audit.single(AccessDenied.class).route());
  }

  @Test
  @DisplayName("a layout restriction that reroutes into its own layout ends in the error view; nothing of the layout is instantiated")
  void layoutDenialIntoTheSameLayout_endsInErrorView() {
    UI.getCurrent().navigate(AreaPage.ROUTE);

    // The first denial points to another route and is carried out; that route lives in the
    // same restricted layout, so its own navigation is denied with a reroute to itself.
    assertEquals(0, RestrictedArea.INSTANCES.get(),
        "the restricted layout must never be instantiated for a denied visitor");
    assertEquals(0, AreaPage.INSTANCES.get());
    assertEquals(0, AreaDeniedPage.INSTANCES.get());
    assertInstanceOf(InternalServerError.class, activeView());
    assertEquals(List.of("AreaPage", "AreaDeniedPage"),
        audit.all(AccessDenied.class).stream().map(AccessDenied::route).toList());
  }

  @Test
  @DisplayName("control: a denial that forwards to another route lands there")
  void forwardToAnotherRoute_landsThere() {
    UI.getCurrent().navigate(DeniedToLandingView.ROUTE);

    assertEquals(0, DeniedToLandingView.INSTANCES.get());
    assertEquals(1, LandingView.INSTANCES.get());
    assertInstanceOf(LandingView.class, activeView());
  }

  // ── Fixtures ───────────────────────────────────────────────────

  /** Denies every visitor and sends them to {@link #route()}. */
  @Retention(RetentionPolicy.RUNTIME)
  @Target(ElementType.TYPE)
  @JCustosAnnotation(DenyToEvaluator.class)
  public @interface DenyTo {
    String route();

    boolean forward();
  }

  /** Evaluator of {@link DenyTo}; instantiated by Vaadin's instantiator. */
  public static class DenyToEvaluator implements AccessEvaluator<DenyTo> {
    @Override
    public AccessDecision evaluate(AccessContext context, DenyTo annotation) {
      return AccessDecision.denied(annotation.route(), annotation.forward());
    }
  }

  @Route(RerouteToItselfView.ROUTE)
  @DenyTo(route = RerouteToItselfView.ROUTE, forward = false)
  public static class RerouteToItselfView extends Div {
    static final String ROUTE = "fc-self/reroute";
    static final AtomicInteger INSTANCES = new AtomicInteger();

    public RerouteToItselfView() {
      INSTANCES.incrementAndGet();
    }
  }

  @Route(ForwardToItselfView.ROUTE)
  @DenyTo(route = ForwardToItselfView.ROUTE, forward = true)
  public static class ForwardToItselfView extends Div {
    static final String ROUTE = "fc-self/forward";
    static final AtomicInteger INSTANCES = new AtomicInteger();

    public ForwardToItselfView() {
      INSTANCES.incrementAndGet();
    }
  }

  @Route(DeniedToLandingView.ROUTE)
  @DenyTo(route = LandingView.ROUTE, forward = true)
  public static class DeniedToLandingView extends Div {
    static final String ROUTE = "fc-self/denied-to-landing";
    static final AtomicInteger INSTANCES = new AtomicInteger();

    public DeniedToLandingView() {
      INSTANCES.incrementAndGet();
    }
  }

  @Route(LandingView.ROUTE)
  public static class LandingView extends Div {
    static final String ROUTE = "fc-self/landing";
    static final AtomicInteger INSTANCES = new AtomicInteger();

    public LandingView() {
      INSTANCES.incrementAndGet();
    }
  }

  /** A restricted layout whose denial points to a route inside the same layout. */
  @DenyTo(route = AreaDeniedPage.ROUTE, forward = false)
  public static class RestrictedArea extends Div implements RouterLayout {
    static final AtomicInteger INSTANCES = new AtomicInteger();

    public RestrictedArea() {
      INSTANCES.incrementAndGet();
    }
  }

  @Route(value = AreaPage.ROUTE, layout = RestrictedArea.class)
  public static class AreaPage extends Div {
    static final String ROUTE = "fc-self/area/page";
    static final AtomicInteger INSTANCES = new AtomicInteger();

    public AreaPage() {
      INSTANCES.incrementAndGet();
    }
  }

  @Route(value = AreaDeniedPage.ROUTE, layout = RestrictedArea.class)
  public static class AreaDeniedPage extends Div {
    static final String ROUTE = "fc-self/area/denied";
    static final AtomicInteger INSTANCES = new AtomicInteger();

    public AreaDeniedPage() {
      INSTANCES.incrementAndGet();
    }
  }
}
