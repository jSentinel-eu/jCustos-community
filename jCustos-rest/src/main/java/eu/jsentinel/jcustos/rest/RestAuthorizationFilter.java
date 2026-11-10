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
import eu.jsentinel.jcustos.audit.AccessGranted;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.SessionExpired;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.StepUpChallenged;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.AuthorizationEvaluator;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.impl.JCustosAnnotationScanner;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.session.SessionMetadata;
import eu.jsentinel.jcustos.session.SessionPolicy;
import eu.jsentinel.jcustos.session.SessionPolicyDecision;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.time.Clock;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Authorizes a REST request before the protected handler is executed.
 */
public final class RestAuthorizationFilter {

  private final RestSubjectResolver subjectResolver;
  private final JCustosAnnotationScanner scanner;
  private final RestAccessContextFactory contextFactory;
  /**
   * Explicit override, or {@code null} to consult
   * {@link RestDecisionContext} per request (JS-SEC-026).
   */
  private final RestDecisionMapping decisionMapper;
  private final JCustosAuditService auditService;

  /**
   * Creates a REST authorization filter.
   *
   * @param subjectResolver subject resolver
   */
  public RestAuthorizationFilter(RestSubjectResolver subjectResolver) {
    this(
        subjectResolver,
        new JCustosAnnotationScanner(),
        new RestAccessContextFactory(),
        null,
        null);
  }

  /**
   * Creates a filter that renders denials through {@code decisionMapper}
   * instead of consulting {@link RestDecisionContext}.
   *
   * @param subjectResolver subject resolver
   * @param decisionMapper  the mapper to enforce through (non-null)
   * @since 00.83.00
   */
  public RestAuthorizationFilter(RestSubjectResolver subjectResolver,
                                 RestDecisionMapping decisionMapper) {
    this(
        subjectResolver,
        new JCustosAnnotationScanner(),
        new RestAccessContextFactory(),
        java.util.Objects.requireNonNull(decisionMapper, "decisionMapper"),
        null);
  }

  RestAuthorizationFilter(
      RestSubjectResolver subjectResolver,
      JCustosAnnotationScanner scanner,
      RestAccessContextFactory contextFactory,
      RestDecisionMapping decisionMapper) {
    this(subjectResolver, scanner, contextFactory, decisionMapper, null);
  }

  RestAuthorizationFilter(
      RestSubjectResolver subjectResolver,
      JCustosAnnotationScanner scanner,
      RestAccessContextFactory contextFactory,
      RestDecisionMapping decisionMapper,
      JCustosAuditService auditService) {
    this.subjectResolver = subjectResolver;
    this.scanner = scanner;
    this.contextFactory = contextFactory;
    this.decisionMapper = decisionMapper;
    this.auditService = auditService;
  }

  /**
   * Authorizes and executes the handler when access is granted.
   *
   * @param request        request
   * @param response       response
   * @param handler        protected handler
   * @param securedElement method or class carrying a security annotation
   */
  public void authorizeAndHandle(
      RestRequest request,
      RestResponse response,
      RestHandler handler,
      AnnotatedElement securedElement) {
    authorizeAndHandle(
        request,
        response,
        handler,
        securedElement,
        operationOf(request),
        Map.of());
  }

  /**
   * Derives the operation token from the request method. R006: a malformed
   * request may carry a {@code null} method (must not NPE before authorization
   * runs), and the lowercasing uses {@link Locale#ROOT} so the token is stable
   * across JVM default locales — on a Turkish-locale JVM
   * {@code "I".toLowerCase()} is {@code "ı"}, which would distort the operation
   * used in policy decisions.
   */
  static String operationOf(RestRequest request) {
    String method = request.method();
    return method == null ? "" : method.toLowerCase(Locale.ROOT);
  }

  /**
   * Authorizes and executes the handler when access is granted.
   *
   * @param request        request
   * @param response       response
   * @param handler        protected handler
   * @param securedElement method or class carrying a security annotation
   * @param operation      operation name
   * @param attributes     additional attributes
   */
  public void authorizeAndHandle(
      RestRequest request,
      RestResponse response,
      RestHandler handler,
      AnnotatedElement securedElement,
      String operation,
      Map<String, Object> attributes) {
    var pair = scanner.scan(securedElement);
    if (pair.isEmpty()) {
      // JS-SEC-024 (CWE-862): fail closed on an un-annotated handler when
      // deny-by-default is enabled, unless the element opts back in via
      // @PublicRoute. The default (allow-by-omission) keeps the handler public.
      if (JCustosServiceResolver.isDenyByDefault() && !isPublicRoute(securedElement)) {
        Optional<JCustosSubject> denySubject = subjectResolver.resolveSubject(request);
        AccessContext denyContext =
            contextFactory.create(request, denySubject, operation, attributes);
        // RF (exit-review): a missing subject is Unauthenticated (401 + a re-auth
        // signal), not Forbidden (403) — matching every annotated endpoint, so a
        // client with an expired/absent token still triggers its standard re-auth
        // flow. Only a resolved-but-unauthorized subject maps to 403.
        AuthorizationDecision denied = denySubject.isPresent()
            ? AuthorizationDecision.forbidden("deny-by-default:no-security-annotation")
            : AuthorizationDecision.unauthenticated("deny-by-default:no-security-annotation");
        audit(denied, denyContext, denySubject);
        decisionMapper().apply(denied, response);
        return;
      }
      handler.handle(request, response);
      return;
    }

    Optional<JCustosSubject> subject = subjectResolver.resolveSubject(request);

    if (subject.isPresent()) {
      Optional<SessionMetadata> metadata = subjectResolver.resolveSessionMetadata(request);
      if (metadata.isPresent()) {
        SessionPolicy<Object> policy = JCustosServiceResolver.sessionPolicy();
        SessionPolicyDecision sessionDecision = policy.evaluate(metadata.get());
        if (!(sessionDecision instanceof SessionPolicyDecision.Active)) {
          auditSessionExpired(metadata.get(), subject.get(), sessionDecision);
          // JS-SEC-026: route the third denial path through the same mapper
          // as the other two. Writing status and body directly here meant a
          // configured strategy (problem+json, say) rendered two of three
          // denials and left this one as plain text.
          decisionMapper().apply(
              AuthorizationDecision.unauthenticated("session-expired"), response);
          return;
        }
      }
    }

    AccessContext context = contextFactory.create(request, subject, operation, attributes);
    AuthorizationDecision decision = evaluate(pair.get().evaluatorClass(), context, pair.get().annotation());
    audit(decision, context, subject);
    if (decisionMapper().apply(decision, response)) {
      handler.handle(request, response);
    }
  }

  /**
   * Resolves the mapper for this request: an explicit constructor
   * argument wins, otherwise whatever the bootstrap published, otherwise
   * the conservative default. Read per call rather than cached so a
   * filter constructed before {@code install()} still picks up the
   * configured mapper.
   */
  private RestDecisionMapping decisionMapper() {
    if (decisionMapper != null) {
      return decisionMapper;
    }
    // JS-SEC-086: the same seam the authentication and version filters render through.
    return RestDecisionContext.mapperOrDefault();
  }

  private void auditSessionExpired(SessionMetadata metadata,
                                   JCustosSubject subject,
                                   SessionPolicyDecision decision) {
    String reason = switch (decision) {
      case SessionPolicyDecision.Active ignored -> "Active";
      case SessionPolicyDecision.IdleTimeout ignored -> SessionExpired.REASON_IDLE_TIMEOUT;
      case SessionPolicyDecision.AbsoluteLifetimeExceeded ignored -> SessionExpired.REASON_ABSOLUTE_LIFETIME;
    };
    JCustosAuditService sink = auditService != null
        ? auditService
        : JCustosServiceResolver.securityAuditService();
    try {
      sink.publish(new SessionExpired(
          Instant.now(Clock.systemUTC()),
          metadata.subjectId() == null ? "" : metadata.subjectId(),
          null,
          reason));
    } catch (RuntimeException auditFailure) {
      // never block the filter because the audit sink failed
    }
  }

  private void audit(AuthorizationDecision decision,
                     AccessContext context,
                     Optional<JCustosSubject> subject) {
    JCustosAuditService sink = auditService != null
        ? auditService
        : JCustosServiceResolver.securityAuditService();

    String subjectId = subject.map(JCustosSubject::subjectId).orElse(null);
    String route = context.resourceName();
    Instant now = Instant.now(Clock.systemUTC());

    AuditEvent event = switch (decision) {
      case AuthorizationDecision.Granted ignored -> new AccessGranted(now, subjectId, route);
      case AuthorizationDecision.Unauthenticated unauth ->
          new AccessDenied(now, subjectId, route,
              "Unauthenticated:" + (unauth.reason() == null ? "" : unauth.reason()));
      case AuthorizationDecision.Forbidden forbidden ->
          new AccessDenied(now, subjectId, route,
              "Forbidden:" + (forbidden.reason() == null ? "" : forbidden.reason()));
      case AuthorizationDecision.StepUpRequired stepUp ->
          new AccessDenied(now, subjectId, route,
              "StepUpRequired:" + stepUp.method()
                  + (stepUp.reason().isEmpty() ? "" : ":" + stepUp.reason()));
    };

    try {
      sink.publish(event);
    } catch (RuntimeException auditFailure) {
      // never block authorization because the audit sink failed
    }

    // Emit a structured StepUpChallenged event alongside the coarse
    // AccessDenied so audit consumers can pivot on method/reason
    // without parsing the AccessDenied.reason string.
    if (decision instanceof AuthorizationDecision.StepUpRequired stepUp) {
      try {
        sink.publish(new StepUpChallenged(
            now, subjectId, route, stepUp.method(), stepUp.reason()));
      } catch (RuntimeException auditFailure) {
        // never block authorization because the audit sink failed
      }
    }
  }

  @SuppressWarnings("unchecked")
  private static AuthorizationDecision evaluate(
      Class<?> evaluatorClass,
      AccessContext context,
      Annotation annotation) {
    Object evaluator = instantiate(evaluatorClass);
    if (!(evaluator instanceof AuthorizationEvaluator<?> authorizationEvaluator)) {
      throw new IllegalStateException(
          "REST security requires AuthorizationEvaluator: " + evaluatorClass.getName());
    }
    return ((AuthorizationEvaluator<Annotation>) authorizationEvaluator).evaluate(context, annotation);
  }

  /**
   * RF (exit-review): {@code @PublicRoute} is {@code @Target({TYPE, METHOD})}, so a
   * handler class marked {@code @PublicRoute} must opt the endpoint back in even when the
   * call site passes the individual handler {@link Method} (the common wiring shape).
   * {@link Method#isAnnotationPresent} does not consult the declaring class, so check both
   * — otherwise a class-level {@code @PublicRoute} is invisible and deny-by-default would
   * 403 an intentionally-public endpoint (health check, login).
   */
  private static boolean isPublicRoute(AnnotatedElement securedElement) {
    if (securedElement.isAnnotationPresent(PublicRoute.class)) {
      return true;
    }
    return securedElement instanceof Method method
        && method.getDeclaringClass().isAnnotationPresent(PublicRoute.class);
  }

  private static Object instantiate(Class<?> evaluatorClass) {
    try {
      return evaluatorClass.getDeclaredConstructor().newInstance();
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(
          "Could not instantiate authorization evaluator " + evaluatorClass.getName(), e);
    }
  }
}
