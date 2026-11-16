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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.audit.AccessGranted;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.StepUpChallenged;
import eu.jsentinel.jcustos.authorization.LoginListener;
import eu.jsentinel.jcustos.authorization.LoginListeners;
import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.api.AccessEvaluator;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.AuthorizationEvaluator;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.authorization.navigation.AccessDecision;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterListener;
import com.vaadin.flow.router.HasErrorParameter;
import com.vaadin.flow.router.ListenerPriority;
import com.vaadin.flow.router.RouteParameters;
import com.vaadin.flow.router.RouterLayout;
import com.vaadin.flow.server.*;
import com.vaadin.flow.shared.Registration;

import java.io.Serial;
import java.io.Serializable;
import java.lang.annotation.Annotation;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Vaadin adapter for the authorization phase.
 * <p>
 * This listener intercepts navigation events, delegates annotation
 * scanning to {@link JCustosAnnotationScanner}, evaluator resolution
 * to the Vaadin instantiator, and decision evaluation to
 * {@link AccessEvaluator#evaluate}. It then maps the resulting
 * {@link AccessDecision} to the {@link BeforeEnterEvent}.
 * <p>
 * <strong>Authorization model (JS-SEC-024 / CWE-862):</strong> this is an
 * <em>allow-by-omission</em> model — authorization is only enforced when the
 * scanner finds a restriction annotation on the navigation target. A
 * {@code @Route} that carries <em>no</em> restriction annotation is public by
 * design, so a forgotten annotation on a sensitive view exposes it silently
 * rather than failing closed. To defend against a forgotten annotation, mark
 * views that must require authentication with a constraint-less
 * {@code @SecureRoute()} (fail-closed, R035), and treat "no annotation = public"
 * as an explicit decision. Opt-in deny-by-default is now available (JS-SEC-024):
 * enable it with {@code JCustosServiceResolver.setDenyByDefault(true)} and an
 * un-annotated route then fails closed unless it is marked {@link PublicRoute};
 * a STRICT startup diagnostic enumerates the routes it would deny.
 * <p>
 * <strong>Layout chain (JS-SEC-154 / CWE-862):</strong> a restriction may be declared on the
 * navigation target or on any {@link RouterLayout} the target is rendered in
 * ({@code @Route(layout = AdminLayout.class)}, {@code @ParentLayout}, an automatic
 * {@code @Layout}). The listener evaluates the restriction of every layout in the chain
 * and the restriction of the target - outermost layout first, the target last - and
 * <em>all</em> of them must grant; the first denial ends the navigation. {@link PublicRoute}
 * on the target does <strong>not</strong> lift a restriction declared on a layout: it only
 * opts a target that carries no restriction at all out of deny-by-default. A view that must
 * stay public has to live outside the restricted layout. {@link RouteRestrictionResolver}
 * holds this decision; the start-up discovery asks the same class.
 * <p>
 * <strong>Fail closed (JS-SEC-152 / CWE-636, CWE-285):</strong> a denial always leaves the
 * event with a reroute or forward target. When the route a decision points to - the login
 * route for {@code Unauthenticated}, the step-up route for {@code StepUpRequired} - is not
 * registered, the visitor is sent to the error view for {@link SecurityException}; Vaadin
 * would otherwise render the protected view. A denial that points to the denied view
 * itself ends in the error view as well (JS-SEC-158): Vaadin skips a reroute or forward to
 * the navigation in progress. The login view and the step-up view have to
 * be reachable for the visitors who are sent there: no restriction of their own that
 * those visitors fail, and not inside a layout that carries one. One exception keeps
 * existing applications
 * working: an anonymous visitor is forwarded to the login view of the registered
 * {@link LoginListener} when the login route name does not resolve.
 * <p>
 * Registered as a {@link VaadinServiceInitListener} via
 * {@code META-INF/services}.
 */
@ListenerPriority(Integer.MAX_VALUE - 1)
public class AuthorizationListener
    implements VaadinServiceInitListener, UIInitListener, BeforeEnterListener, HasLogger, Serializable {

  @Serial
  private static final long serialVersionUID = 974589421761348380L;

  /** Cached scanner for restriction annotations. */
  private final JCustosAnnotationScanner scanner = new JCustosAnnotationScanner();

  /** JS-SEC-154: resolves the restrictions of the navigation target and its layout chain. */
  private final RouteRestrictionResolver restrictionResolver = new RouteRestrictionResolver(scanner);

  /** Creates core contexts from Vaadin events. */
  private final VaadinAccessContextFactory contextFactory = new VaadinAccessContextFactory();

  /** Maps core decisions back to Vaadin navigation calls. */
  private final VaadinAccessDecisionMapper decisionMapper = new VaadinAccessDecisionMapper();

  /** Creates a new instance. */
  public AuthorizationListener() {
  }

  @Override
  public void serviceInit(ServiceInitEvent event) {
    event.getSource().addUIInitListener(this);
  }

  @Override
  public void uiInit(UIInitEvent event) {
    UI ui = event.getUI();
    Registration reg = ui.addBeforeEnterListener(this);
    ui.addDetachListener(e -> reg.remove());
  }

  @Override
  public void beforeEnter(BeforeEnterEvent event) {
    Class<?> navigationTarget = event.getNavigationTarget();
    List<Class<? extends RouterLayout>> layouts = event.getLayouts();

    // JS-SEC-154 (CWE-862): the restriction of the navigation target AND the restriction of
    // every layout in its chain apply. Only the target used to be scanned, so
    // `@RequiresRole("ADMIN")` on a parent layout protected none of its child routes.
    List<RouteRestrictionResolver.Restriction> restrictions =
        restrictionResolver.resolve(navigationTarget, layouts);
    if (restrictions.isEmpty()) {
      // JS-SEC-024 (CWE-862): no security annotation — allow-by-omission unless
      // deny-by-default is enabled (then fail closed unless @PublicRoute).
      denyByDefaultIfEnabled(navigationTarget, layouts, event);
      return;
    }

    AccessContext context = contextFactory.create(event);
    EvaluatedDecision granted = null;
    for (RouteRestrictionResolver.Restriction restriction : restrictions) {
      // 1. Resolve evaluator via Vaadin instantiator
      Class<?> evaluatorClass = restriction.evaluatorClass();
      requireNonNull(evaluatorClass,
          "AccessEvaluator class must not be null for " + restriction.source().getName());

      Object evaluator = VaadinService.getCurrent()
          .getInstantiator()
          .getOrCreate(evaluatorClass);
      requireNonNull(evaluator,
          "Could not instantiate AccessEvaluator: " + evaluatorClass.getName());

      // 2. Evaluate — obtain a Vaadin-free decision plus the original
      //    AuthorizationDecision (when the evaluator produced one), so
      //    audit can record StepUp specifics that get lost in the
      //    AccessDecision mapping.
      Annotation annotation = restriction.annotation();
      logger().info("Evaluating access for {} with {} (declared for {})",
          event.getLocation(), annotation, restriction.source().getSimpleName());
      EvaluatedDecision evaluated = evaluateWithOriginal(evaluator, context, annotation);

      if (!(evaluated.mapped() instanceof AccessDecision.Granted)) {
        // 3. Audit the denial - the first restriction that does not grant ends the navigation
        audit(evaluated, context);

        // 4. Apply the decision to the Vaadin event
        applyDenial(evaluated.mapped(), event);
        return;
      }
      granted = evaluated;
    }

    // 3. Audit the decision - one AccessGranted per navigation, once every restriction granted
    audit(granted, context);
  }

  /**
   * JS-SEC-024 (CWE-862): when deny-by-default is enabled and neither the target nor a
   * layout carries a security annotation and the target is not {@link PublicRoute}, fail
   * closed — reroute to the generic error view exactly as an
   * {@link AuthorizationDecision.Forbidden} would, and audit the denial. When
   * deny-by-default is off (the default) this is a no-op, preserving
   * allow-by-omission and full backward compatibility.
   */
  private void denyByDefaultIfEnabled(Class<?> navigationTarget,
                                      List<Class<? extends RouterLayout>> layouts,
                                      BeforeEnterEvent event) {
    // JS-SEC-154: the same classification the start-up discovery reports.
    if (!JCustosServiceResolver.isDenyByDefault()
        || !restrictionResolver.isOpenByOmission(navigationTarget, layouts)) {
      return;
    }
    logger().warn(
        "deny-by-default: {} has no security annotation and is not @PublicRoute — denying",
        navigationTarget.getName());
    AccessContext context = contextFactory.create(event);
    AccessDecision denied = AccessDecision.deniedWithError(SecurityException.class, "Access denied");
    audit(new EvaluatedDecision(denied, Optional.empty()), context);
    applyDenial(denied, event);
  }

  /**
   * Applies a denial to the event and enforces the post-condition that it took effect.
   */
  private void applyDenial(AccessDecision denied, BeforeEnterEvent event) {
    if (forwardToLoginListenerTarget(denied, event)) {
      return;
    }
    decisionMapper.apply(denied, event);
    failClosedIfUnhandled(denied, event);
  }

  /**
   * JS-SEC-152 (CWE-636, CWE-285) - the post-condition of every denial, independent of the
   * mapper: a decision other than {@link AccessDecision.Granted} that left the event
   * without a reroute or forward target ends in the error view for
   * {@link SecurityException}. {@code BeforeEvent.rerouteTo(String)} with a route that is
   * not registered only records an "unknown reroute"; Vaadin then goes on to instantiate
   * and render the protected view while the audit trail already says {@code AccessDenied}.
   * <p>
   * The post-condition checks that a target is set, not where it points - with one exception
   * (JS-SEC-158, CWE-636, CWE-285): a reroute or forward to the navigation target itself, the
   * same class with the same route parameters, counts as no target. Vaadin skips such a
   * target and renders the navigation target, so a decision that denies a view by sending the
   * visitor to that very view rendered it. The event carried a target, and the check let it
   * pass.
   *
   * @param decision the decision that was applied to the event
   * @param event    the navigation event
   */
  static void failClosedIfUnhandled(AccessDecision decision, BeforeEnterEvent event) {
    if (decision instanceof AccessDecision.Granted || VaadinAccessDecisionMapper.hasTarget(event)) {
      return;
    }
    HasLogger.staticLogger().warn(
        "Access to {} was denied, but the decision {} left the navigation without a target "
            + "- rerouting to the error view", event.getNavigationTarget().getName(), decision);
    VaadinAccessDecisionMapper.failClosed(event);
  }

  /**
   * JS-SEC-152: keeps a configuration working that was valid before the fail-closed
   * post-condition. An application whose login view is registered under another name than
   * {@link JCustosServiceResolver#loginRouteName()} used to be rescued by its
   * {@link LoginListener}, which runs after this listener and forwards an anonymous
   * visitor to its login view by class. The listener now ends the navigation itself, so it
   * takes that step on the login listener's behalf - only for a visitor without a bound
   * subject (the login listener's own condition) and only when the login route name does
   * not resolve. In every other case the mapper and the post-condition decide.
   *
   * @return {@code true} when the event was forwarded to the login listener's login view
   */
  private boolean forwardToLoginListenerTarget(AccessDecision denied, BeforeEnterEvent event) {
    if (!(denied instanceof AccessDecision.Reroute(String route, boolean _))
        || !route.equals(JCustosServiceResolver.loginRouteName())
        || VaadinAccessDecisionMapper.resolves(event, route)) {
      return false;
    }
    try {
      Optional<LoginListener<Object>> loginListener = LoginListeners.findLoginListener();
      if (loginListener.isEmpty() || subjectBound()) {
        return false;
      }
      Class<? extends LoginView> loginTarget = loginListener.get().loginNavigationTarget();
      if (!VaadinAccessDecisionMapper.isRegistered(event, loginTarget)
          // JS-SEC-158: Vaadin skips a forward to the navigation in progress
          || VaadinAccessDecisionMapper.isNavigationTarget(
              event, loginTarget, RouteParameters.empty())) {
        return false;
      }
      event.forwardTo(loginTarget);
      logger().warn("The login route '{}' is not registered - forwarded the anonymous visitor "
          + "to the login view of the LoginListener ({}). Publish the route name with "
          + "VaadinSecurity.bootstrap().loginRoute(...).", route, loginTarget.getName());
      return VaadinAccessDecisionMapper.hasTarget(event);
    } catch (RuntimeException unresolvable) {
      // no usable login listener, or its login view is not a registered route:
      // the mapper answers with the error view
      return false;
    }
  }

  /** Mirrors the subject check of {@link LoginListener}; "cannot tell" counts as bound. */
  @SuppressWarnings({"rawtypes", "unchecked"})
  private static boolean subjectBound() {
    try {
      Class subjectType = JCustosServiceResolver.<Object, Object>authenticationService().subjectType();
      return SubjectStores.subjectStore().currentSubject(subjectType).isPresent();
    } catch (RuntimeException unknown) {
      return true;
    }
  }

  /**
   * RF (exit-review): deny-by-default must not deny the navigation targets the framework
   * itself reroutes to.
   * <ul>
   *   <li><strong>Error views</strong> ({@link HasErrorParameter}) are the reroute target
   *   of a denial. Denying them cascades into a second denial and a broken/blank page
   *   instead of the intended access-denied view, and Vaadin's built-in
   *   {@code RouteNotFoundError} / {@code InternalServerError} cannot be annotated by the
   *   integrator at all — so the documented "mark it @PublicRoute" remedy is impossible.</li>
   * </ul>
   * The framework's own {@code SessionManagementRoute} used to be exempt as well; since
   * 00.84.00 it carries {@code @ProtectedBy} and is evaluated like any consumer route
   * (JS-SEC-068, CWE-306).
   */
  static boolean isDenyByDefaultExempt(Class<?> navigationTarget) {
    // JS-SEC-068 (CWE-306): SessionManagementView subclasses are no longer exempt.
    // The framework's own route now carries @ProtectedBy and evaluates the requirement
    // configured at bootstrap; consumer subclasses carry their own annotation.
    return RouteRestrictionResolver.isDenyByDefaultExempt(navigationTarget);
  }

  /**
   * Internal result of running an evaluator: the {@link AccessDecision}
   * that drives navigation, plus the original {@link AuthorizationDecision}
   * if the evaluator produced one (legacy {@link AccessEvaluator}s
   * return only an {@code AccessDecision}, so {@code original} is
   * empty in that branch).
   */
  record EvaluatedDecision(AccessDecision mapped, Optional<AuthorizationDecision> original) {
  }

  private void audit(EvaluatedDecision evaluated, AccessContext context) {
    String subjectId = context.subject().map(JCustosSubject::subjectId).orElse(null);
    String route = context.resourceName();
    Instant now = Instant.now(Clock.systemUTC());

    AccessDecision decision = evaluated.mapped();
    AuditEvent event;
    if (decision instanceof AccessDecision.Granted) {
      event = new AccessGranted(now, subjectId, route);
    } else {
      String reason = originalReasonIfApplicable(evaluated)
          .orElseGet(() -> switch (decision) {
            case AccessDecision.Granted ignored -> "Granted";
            case AccessDecision.Reroute reroute -> "Reroute:" + reroute.target();
            case AccessDecision.RerouteToError err -> "Error:" + err.type().getSimpleName();
            case AccessDecision.RerouteWithParameter<?> r -> "ReroutePARAM:" + r.target();
            case AccessDecision.RerouteWithParameters<?> r -> "ReroutePARAMS:" + r.target();
          });
      event = new AccessDenied(now, subjectId, route, reason);
    }

    JCustosAuditService sink = JCustosServiceResolver.securityAuditService();
    try {
      sink.publish(event);
    } catch (RuntimeException auditFailure) {
      // never block navigation because the audit sink failed
    }

    // Emit a structured StepUpChallenged event alongside the coarse
    // AccessDenied. Mirrors the REST adapter; audit consumers can
    // pivot on method/reason without parsing the AccessDenied.reason
    // string.
    evaluated.original()
        .filter(AuthorizationDecision.StepUpRequired.class::isInstance)
        .map(AuthorizationDecision.StepUpRequired.class::cast)
        .ifPresent(stepUp -> {
          try {
            sink.publish(new StepUpChallenged(
                now, subjectId, route, stepUp.method(), stepUp.reason()));
          } catch (RuntimeException auditFailure) {
            // never block navigation because the audit sink failed
          }
        });
  }

  /**
   * Derives the audit reason from the original {@link AuthorizationDecision}
   * when the evaluator produced one. For {@code StepUpRequired} this is the
   * structured {@code StepUpRequired:<method>[:<reason>]} string; for
   * {@code Forbidden} it is {@code Forbidden[:<reason>]} — the evaluator's
   * internal reason is preserved <em>here, in the audit channel only</em>, even
   * though it is deliberately withheld from the user-facing error view (R018).
   * Returns {@link Optional#empty()} for every other shape (and for legacy
   * {@link AccessEvaluator}s, which carry no original) so the caller falls back
   * to the {@link AccessDecision}-based reason.
   */
  private static Optional<String> originalReasonIfApplicable(EvaluatedDecision evaluated) {
    return evaluated.original().flatMap(original -> switch (original) {
      case AuthorizationDecision.StepUpRequired stepUp ->
          Optional.of("StepUpRequired:" + stepUp.method()
              + (stepUp.reason().isEmpty() ? "" : ":" + stepUp.reason()));
      case AuthorizationDecision.Forbidden(String reason) ->
          Optional.of(reason.isEmpty() ? "Forbidden" : "Forbidden:" + reason);
      default -> Optional.empty();
    });
  }

  @SuppressWarnings("unchecked")
  private EvaluatedDecision evaluateWithOriginal(
      Object evaluator, AccessContext context, Annotation annotation) {
    if (evaluator instanceof AccessEvaluator<?> accessEvaluator) {
      return new EvaluatedDecision(
          ((AccessEvaluator<Annotation>) accessEvaluator).evaluate(context, annotation),
          Optional.empty());
    }
    if (evaluator instanceof AuthorizationEvaluator<?> authorizationEvaluator) {
      AuthorizationDecision decision =
          ((AuthorizationEvaluator<Annotation>) authorizationEvaluator).evaluate(context, annotation);
      return new EvaluatedDecision(map(decision), Optional.of(decision));
    }
    throw new IllegalStateException(
        "Unsupported evaluator type: " + evaluator.getClass().getName());
  }

  /**
   * Legacy helper kept for test reflection — delegates to
   * {@link #evaluateWithOriginal} and discards the original. New
   * callers should use {@link #evaluateWithOriginal} so audit can
   * surface step-up specifics.
   */
  @SuppressWarnings("unchecked")
  private AccessDecision evaluate(Object evaluator, AccessContext context, Annotation annotation) {
    return evaluateWithOriginal(evaluator, context, annotation).mapped();
  }

  /**
   * Maps a core {@link AuthorizationDecision} to the Vaadin-navigation
   * {@link AccessDecision}. This is the Vaadin row of the canonical
   * cross-adapter mapping — see {@link AuthorizationDecision} for the full
   * table (R024). The switch is exhaustive over the sealed type;
   * {@code StepUpRequired} reroutes to the configured step-up route rather
   * than emitting an HTTP challenge or throwing, because navigation is the
   * Vaadin-native way to present a step-up screen.
   */
  private AccessDecision map(AuthorizationDecision decision) {
    return switch (decision) {
      case AuthorizationDecision.Granted() -> AccessDecision.granted();
      case AuthorizationDecision.Unauthenticated _ ->
          // R025: resolve the login route through JCustosServiceResolver
          // (default "login") instead of a hardcoded literal, so apps that name
          // their login route differently are not silently broken.
          AccessDecision.denied(JCustosServiceResolver.loginRouteName(), false);
      case AuthorizationDecision.Forbidden _ ->
          // R018: never surface the evaluator's internal reason to the user-facing
          // error view (it may carry subject ids, policy names, SQL). Use a generic
          // message, mirroring the REST adapter's generic "Forbidden" body; the real
          // reason is recorded only in the audit channel (see audit()).
          AccessDecision.deniedWithError(SecurityException.class, "Access denied");
      case AuthorizationDecision.StepUpRequired stepUp ->
          // Reroute to the configured step-up route — the consuming
          // application registers a Route under that name to render
          // the MFA / re-auth challenge.
          AccessDecision.reroute(JCustosServiceResolver.stepUpRouteName(), false);
    };
  }
}
