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
import eu.jsentinel.jcustos.authorization.api.AccessEvaluator;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.AuthorizationEvaluator;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.authorization.navigation.AccessDecision;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterListener;
import com.vaadin.flow.router.HasErrorParameter;
import com.vaadin.flow.router.ListenerPriority;
import com.vaadin.flow.server.*;
import com.vaadin.flow.shared.Registration;

import java.io.Serial;
import java.io.Serializable;
import java.lang.annotation.Annotation;
import java.time.Clock;
import java.time.Instant;
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

    var scanned = scanner.scan(navigationTarget);
    if (scanned.isEmpty()) {
      // JS-SEC-024 (CWE-862): no security annotation — allow-by-omission unless
      // deny-by-default is enabled (then fail closed unless @PublicRoute).
      denyByDefaultIfEnabled(navigationTarget, event);
      return;
    }
    var pair = scanned.get();

    // 1. Resolve evaluator via Vaadin instantiator
    Class<?> evaluatorClass = pair.evaluatorClass();
    requireNonNull(evaluatorClass,
        "AccessEvaluator class must not be null for " + navigationTarget.getName());

    Object evaluator = VaadinService.getCurrent()
        .getInstantiator()
        .getOrCreate(evaluatorClass);
    requireNonNull(evaluator,
        "Could not instantiate AccessEvaluator: " + evaluatorClass.getName());

    // 2. Evaluate — obtain a Vaadin-free decision plus the original
    //    AuthorizationDecision (when the evaluator produced one), so
    //    audit can record StepUp specifics that get lost in the
    //    AccessDecision mapping.
    Annotation annotation = pair.annotation();
    logger().info("Evaluating access for {} with {}", event.getLocation(), annotation);
    AccessContext context = contextFactory.create(event);
    EvaluatedDecision evaluated = evaluateWithOriginal(evaluator, context, annotation);

    // 3. Audit the decision
    audit(evaluated, context);

    // 4. Apply the decision to the Vaadin event
    decisionMapper.apply(evaluated.mapped(), event);
  }

  /**
   * JS-SEC-024 (CWE-862): when deny-by-default is enabled and the target carries
   * neither a security annotation (scanner empty) nor {@link PublicRoute}, fail
   * closed — reroute to the generic error view exactly as an
   * {@link AuthorizationDecision.Forbidden} would, and audit the denial. When
   * deny-by-default is off (the default) this is a no-op, preserving
   * allow-by-omission and full backward compatibility.
   */
  private void denyByDefaultIfEnabled(Class<?> navigationTarget, BeforeEnterEvent event) {
    if (!JCustosServiceResolver.isDenyByDefault()
        || navigationTarget.isAnnotationPresent(PublicRoute.class)
        || isDenyByDefaultExempt(navigationTarget)) {
      return;
    }
    logger().warn(
        "deny-by-default: {} has no security annotation and is not @PublicRoute — denying",
        navigationTarget.getName());
    AccessContext context = contextFactory.create(event);
    AccessDecision denied = AccessDecision.deniedWithError(SecurityException.class, "Access denied");
    audit(new EvaluatedDecision(denied, Optional.empty()), context);
    decisionMapper.apply(denied, event);
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
    return HasErrorParameter.class.isAssignableFrom(navigationTarget);
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
