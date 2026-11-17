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
package eu.jsentinel.jcustos.dx.rest.bootstrap;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.dx.bootstrap.JCustosBootstrapException;
import eu.jsentinel.jcustos.dx.internal.AbstractJCustosBootstrap;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJCustosService;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import eu.jsentinel.jcustos.rest.RestOriginGuard;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestSessionRevocation;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;
import eu.jsentinel.jcustos.session.SessionStore;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.function.Consumer;
import eu.jsentinel.jcustos.dx.rest.handlers.RestHandlerDiscovery;

/**
 * Package-private implementation of {@link RestJCustosBootstrap}.
 *
 * @since 00.72.00
 */
final class RestJCustosBootstrapImpl
    extends AbstractJCustosBootstrap<RestJCustosBootstrap>
    implements RestJCustosBootstrap {

  /**
   * WARNING: {@code .storeBacked(...)} wires the REST revocation check, but the subject
   * resolver keeps the default {@code resolveSessionId}, so the check never finds a session.
   *
   * @since 00.84.00
   */
  static final String CODE_SESSION_REVOCATION_INERT = "rest/session-revocation-inert";

  /**
   * CORS allows credentials, so browsers call the API with a cookie from other origins, and no
   * {@link RestOriginGuard} is installed: WARNING in PRODUCTION and STRICT, INFO otherwise.
   *
   * @since 00.84.00
   */
  static final String CODE_CREDENTIALED_CORS_WITHOUT_ORIGIN_GUARD =
      "rest/credentialed-cors-without-origin-guard";

  /**
   * CORS allows credentials for an origin the installed {@link RestOriginGuard} does not
   * accept: the browser sends that origin's state-changing requests with the cookie, and the
   * guard refuses every one of them with {@code 403}. WARNING in every mode.
   *
   * @since 00.84.00
   */
  static final String CODE_CREDENTIALED_CORS_ORIGIN_NOT_ACCEPTED =
      "rest/credentialed-cors-origin-not-accepted";

  /** CORS origin values that are no origin; {@code cors/wildcard-with-credentials} reports them. */
  private static final String CORS_WILDCARD = "*";
  private static final String CORS_NULL_ORIGIN = "null";

  /** Source under which {@code .originGuard(...)} lists the installed guard. */
  static final String SOURCE_ORIGIN_GUARD = "bootstrap-origin-guard";

  private static final String RESOLVE_SESSION_ID = "resolveSessionId";

  private RestSubjectResolver subjectResolver;
  private RestHandlerDiscovery handlerDiscovery;
  private RestDecisionMapper decisionMapper;
  private RestErrorBodyStrategy errorBodies;
  private RestCorsConfiguration corsConfiguration;
  private RestOpenApiMetadata openApiMetadata;
  private RestOriginGuard originGuard;
  private boolean installed;

  @Override
  public RestJCustosBootstrap subjectResolver(RestSubjectResolver resolver) {
    this.subjectResolver = Objects.requireNonNull(resolver, "resolver");
    return this;
  }

  /**
   * Registers a custom {@link RestDecisionMapper}.
   *
   * <p>Since V00.83 this reaches the enforcing {@code RestAuthorizationFilter}:
   * {@code install()} publishes the effective mapper to
   * {@code RestDecisionContext}, and the filter consults it per request
   * (JS-SEC-026 closed). A filter constructed with an explicit mapper still
   * wins over the published one.
   */
  @Override
  public RestJCustosBootstrap decisionMapper(RestDecisionMapper mapper) {
    this.decisionMapper = Objects.requireNonNull(mapper, "mapper");
    return this;
  }

  /**
   * Registers a custom {@link RestErrorBodyStrategy}.
   *
   * <p>Since V00.83 the default decision mapper renders denials through this
   * strategy, so it reaches the wire (JS-SEC-026 closed). All three denial
   * paths — including session expiry — use it. Supplying an explicit
   * {@link #decisionMapper(RestDecisionMapper)} takes over rendering entirely,
   * and that mapper is then responsible for the bodies.
   */
  @Override
  public RestJCustosBootstrap errorBodies(RestErrorBodyStrategy strategy) {
    this.errorBodies = Objects.requireNonNull(strategy, "strategy");
    return this;
  }

  @Override
  public RestJCustosBootstrap cors(Consumer<RestCorsConfigurationBuilder> consumer) {
    Objects.requireNonNull(consumer, "consumer");
    RestCorsConfigurationBuilder builder = new RestCorsConfigurationBuilder();
    consumer.accept(builder);
    this.corsConfiguration = builder.toConfiguration();
    return this;
  }

  @Override
  public RestJCustosBootstrap openApiMetadata(Consumer<RestOpenApiMetadataBuilder> consumer) {
    Objects.requireNonNull(consumer, "consumer");
    RestOpenApiMetadataBuilder builder = new RestOpenApiMetadataBuilder();
    consumer.accept(builder);
    this.openApiMetadata = builder.toMetadata();
    return this;
  }


  @Override
  public RestJCustosBootstrap discoverHandlers(RestHandlerDiscovery discovery) {
    this.handlerDiscovery = Objects.requireNonNull(discovery, "discovery");
    return this;
  }

  @Override
  public RestJCustosBootstrap originGuard(RestOriginGuard guard) {
    this.originGuard = Objects.requireNonNull(guard, "guard");
    return this;
  }

  /**
   * CSRF (CWE-352): installs the guard configured through {@code .originGuard(...)}. Without
   * one nothing is touched - an application may have installed a guard itself.
   */
  private void installOriginGuard(List<RegisteredJCustosService> services) {
    if (originGuard == null) {
      return;
    }
    RestOriginGuard.install(originGuard);
    services.add(new RegisteredJCustosService(
        RestOriginGuard.class, RestOriginGuard.class, SOURCE_ORIGIN_GUARD, false));
  }

  /**
   * CSRF (CWE-352): {@code allowCredentials(true)} says that browsers call this API from the
   * pages of other origins and send their cookies along. If the session rides on such a
   * cookie, every state-changing endpoint can be triggered by any page the user visits - CORS
   * decides who may <em>read</em> a response, not who may <em>send</em> a request. Reported
   * when no {@link RestOriginGuard} is installed, by {@code .originGuard(...)} or by the
   * application.
   */
  private void reportCredentialedCorsWithoutOriginGuard(List<JCustosBootstrapWarning> warnings) {
    if (!corsConfiguration.allowCredentials() || RestOriginGuard.installed().isPresent()) {
      return;
    }
    Severity severity = switch (state.mode()) {
      case PRODUCTION, STRICT -> Severity.WARNING;
      default -> Severity.INFO;
    };
    warnings.add(new JCustosBootstrapWarning(
        severity,
        CODE_CREDENTIALED_CORS_WITHOUT_ORIGIN_GUARD,
        "CORS allows credentials, but no RestOriginGuard is installed: if the REST session "
            + "rides on a cookie, any web page can send state-changing requests in the "
            + "user's name (CSRF).",
        "Install the guard with .originGuard(RestOriginGuard.sameOrigin().withAllowedOrigins("
            + "Set.of(...))), naming the API's own public origin and the allowed CORS origins; "
            + "with bearer tokens only, drop allowCredentials(true)."));
  }

  /**
   * CSRF (CWE-352), RF30: the other side of {@link #reportCredentialedCorsWithoutOriginGuard}.
   * With a guard installed, every origin of a credentialed CORS configuration has to be one the
   * guard accepts as a cross-origin caller - in practice, one of its allowed origins. A guard
   * that compares with {@code Host} ({@code sameOrigin()} without an allowlist) accepts none:
   * a browser applies CORS only to requests from another origin. Until the exit review of
   * 00.84.00 such a configuration booted without a word and every state-changing request from
   * the partner origin got {@code 403}. The wildcard and the {@code null} origin are left to
   * {@code cors/wildcard-with-credentials}.
   */
  private void reportCredentialedCorsOriginsTheGuardRefuses(
      List<JCustosBootstrapWarning> warnings) {
    if (!corsConfiguration.allowCredentials()) {
      return;
    }
    RestOriginGuard guard = RestOriginGuard.installed().orElse(null);
    if (guard == null) {
      return;
    }
    List<String> refused = corsConfiguration.allowedOrigins().stream()
        .filter(origin -> !CORS_WILDCARD.equals(origin)
            && !CORS_NULL_ORIGIN.equalsIgnoreCase(origin))
        .filter(origin -> !guard.acceptsCrossOrigin(origin))
        .toList();
    if (refused.isEmpty()) {
      return;
    }
    warnings.add(new JCustosBootstrapWarning(
        Severity.WARNING,
        CODE_CREDENTIALED_CORS_ORIGIN_NOT_ACCEPTED,
        "CORS allows credentials for " + refused + ", but the installed RestOriginGuard does "
            + "not accept " + (refused.size() == 1 ? "this origin" : "these origins") + " ("
            + guard + "): every state-changing request from there is refused with 403.",
        "List the origins in .originGuard(RestOriginGuard.sameOrigin().withAllowedOrigins("
            + "Set.of(...))) together with the API's own public origin, or remove them from "
            + "the CORS configuration."));
  }

  /**
   * Deny-by-default startup check (CWE-862). Mirrors what Vaadin does from its
   * router; REST needs the application to supply the handler list because it
   * has no registry to walk.
   *
   * <p>Only consulted when deny-by-default is on — without it an unannotated
   * handler is served by design, and reporting it would be noise.
   */
  private void crossCheckHandlers(List<JCustosBootstrapWarning> warnings) {
    if (!JCustosServiceResolver.isDenyByDefault()) {
      return;
    }
    if (handlerDiscovery == null) {
      warnings.add(new JCustosBootstrapWarning(
          Severity.INFO,
          "deny-by-default/discovery-disabled",
          "Deny-by-default is on, but no handler discovery is configured — unprotected "
              + "handlers surface on the first request instead of at startup.",
          "Pass .discoverHandlers(new ClassScanningRestHandlerDiscovery(YourHandlers.class))."));
      return;
    }
    if (!handlerDiscovery.handlersAvailable()) {
      // "Could not check" must not look like "checked, nothing found".
      warnings.add(new JCustosBootstrapWarning(
          Severity.ERROR,
          "deny-by-default/discovery-unavailable",
          "Handler discovery reported it could not enumerate handlers, so unprotected "
              + "handlers cannot be ruled out.",
          "Ensure the discovery has the handler classes available at bootstrap time."));
      return;
    }
    handlerDiscovery.discoverUnannotatedHandlerNames().forEach(name ->
        warnings.add(new JCustosBootstrapWarning(
            Severity.ERROR,
            "deny-by-default/unannotated-handler",
            "Handler '" + name + "' carries no security annotation and is not marked "
                + "@PublicRoute — deny-by-default refuses every request to it.",
            "Annotate it (@RequiresPermission / @RequiresRole / …) or mark it @PublicRoute "
                + "if it is meant to be reachable without a subject.")));
  }

  /**
   * JS-SEC-131 (CWE-613): hands the store configured through
   * {@code .sessions(s -> s.storeBacked(...))} to the REST filters, which refuse a request
   * whose session record was revoked. The shared base lists the store itself; this adds the
   * revocation wiring, as the Vaadin bootstrap does. Without a configured store nothing is
   * touched: an application may have registered its store with
   * {@link RestSessionRevocation} itself.
   *
   * <p>The check reads the session of a request through
   * {@link RestSubjectResolver#resolveSessionId}, whose default answers "no session". A
   * resolver that keeps the default leaves the check inert - every request passes, a
   * revoked session keeps working - although the bootstrap lists the wiring. That is
   * reported as {@value #CODE_SESSION_REVOCATION_INERT} (WARNING) since 00.84.00.
   */
  private void publishSessionStore(List<RegisteredJCustosService> services,
                                   List<JCustosBootstrapWarning> warnings) {
    SessionStore sessionStore = state.sessionState().sessionStore();
    if (sessionStore == null) {
      return;
    }
    RestSessionRevocation.useSessionStore(sessionStore);
    services.add(new RegisteredJCustosService(
        RestSessionRevocation.class, sessionStore.getClass(),
        "bootstrap-session-revocation", false));
    services.stream()
        .filter(service -> service.spi() == RestSubjectResolver.class)
        .map(RegisteredJCustosService::impl)
        .findFirst()
        .filter(resolverClass -> !resolvesSessionIds(resolverClass))
        .ifPresent(resolverClass -> warnings.add(new JCustosBootstrapWarning(
            Severity.WARNING,
            CODE_SESSION_REVOCATION_INERT,
            "A session store is configured, but the RestSubjectResolver "
                + resolverClass.getName() + " does not override resolveSessionId(...): the "
                + "REST revocation check finds no session for any request, so a revoked "
                + "session keeps working over REST.",
            "Override RestSubjectResolver.resolveSessionId(...) to return the SessionId the "
                + "session record is saved under, or drop .storeBacked(...) if REST does not "
                + "record sessions.")));
  }

  /**
   * Whether {@code resolverClass} replaces the default
   * {@link RestSubjectResolver#resolveSessionId}, itself or through a supertype.
   */
  private static boolean resolvesSessionIds(Class<?> resolverClass) {
    try {
      return resolverClass.getMethod(RESOLVE_SESSION_ID, RestRequest.class)
          .getDeclaringClass() != RestSubjectResolver.class;
    } catch (NoSuchMethodException | SecurityException unknown) {
      // Not inspectable: do not claim the check is inert.
      return true;
    }
  }

  /**
   * The {@link RestSubjectResolver} registered through {@code META-INF/services}, which the
   * finding's own hint names as an alternative to {@code .subjectResolver(...)}: exactly one
   * is recorded, none is {@code missing-rest-subject-resolver}, several are
   * {@code ambiguous-rest-subject-resolver} (both ERROR). The filters take their resolver
   * from the application; the bootstrap only records which one is registered.
   */
  private static void registeredSubjectResolver(List<RegisteredJCustosService> services,
                                                List<JCustosBootstrapWarning> warnings) {
    List<Class<?>> registered = new ArrayList<>();
    try {
      for (RestSubjectResolver resolver : ServiceLoader.load(RestSubjectResolver.class)) {
        registered.add(resolver.getClass());
      }
    } catch (ServiceConfigurationError unloadable) {
      warnings.add(new JCustosBootstrapWarning(
          Severity.ERROR,
          "missing-rest-subject-resolver",
          "The registered RestSubjectResolver cannot be loaded: " + unloadable.getMessage(),
          "Fix the META-INF/services entry, or call .subjectResolver(...)."));
      return;
    }
    if (registered.size() == 1) {
      services.add(new RegisteredJCustosService(
          RestSubjectResolver.class, registered.getFirst(), SOURCE_SPI_REGISTERED, false));
    } else if (registered.isEmpty()) {
      warnings.add(new JCustosBootstrapWarning(
          Severity.ERROR,
          "missing-rest-subject-resolver",
          "No RestSubjectResolver configured for RestSecurity.bootstrap().",
          "Call .subjectResolver(...) or register an implementation via "
              + "@JCustosAutoService(RestSubjectResolver.class)."));
    } else {
      warnings.add(new JCustosBootstrapWarning(
          Severity.ERROR,
          "ambiguous-rest-subject-resolver",
          "Several RestSubjectResolver implementations are registered and none was passed "
              + "explicitly: " + registered,
          "Register exactly one via @JCustosAutoService(RestSubjectResolver.class), or call "
              + ".subjectResolver(...)."));
    }
  }

  @Override
  public JCustosRuntime install() {
    if (installed) {
      throw new IllegalStateException("install() may only be called once on the same builder");
    }
    installed = true;

    List<RegisteredJCustosService> services = new ArrayList<>();
    List<JCustosBootstrapWarning> warnings = new ArrayList<>();

    // The explicit service wins; otherwise the one registered through META-INF/services, as
    // the resolver finds it at run time. Until 00.84.00 an SPI-registered service was
    // reported as missing (ERROR) although the hint itself called the registration enough.
    applyAuthenticationAndAuthorization("RestSecurity.bootstrap()", services, warnings);

    if (subjectResolver != null) {
      services.add(new RegisteredJCustosService(
          RestSubjectResolver.class, subjectResolver.getClass(), "bootstrap-explicit", false));
    } else {
      registeredSubjectResolver(services, warnings);
    }

    // Bodies first: the default mapper renders through them, so the
    // strategy has to be known before the mapper is built.
    RestErrorBodyStrategy effectiveErrorBodies = errorBodies;
    boolean errorBodiesDefaulted = false;
    if (effectiveErrorBodies == null) {
      effectiveErrorBodies = new DefaultRestErrorBodyStrategy();
      errorBodiesDefaulted = true;
    }
    services.add(new RegisteredJCustosService(
        RestErrorBodyStrategy.class,
        effectiveErrorBodies.getClass(),
        errorBodiesDefaulted ? "bootstrap-default" : "bootstrap-explicit",
        errorBodiesDefaulted));

    RestDecisionMapper effectiveDecisionMapper = decisionMapper;
    boolean decisionMapperDefaulted = false;
    if (effectiveDecisionMapper == null) {
      effectiveDecisionMapper = new DefaultRestDecisionMapper(effectiveErrorBodies);
      decisionMapperDefaulted = true;
    }
    services.add(new RegisteredJCustosService(
        RestDecisionMapper.class,
        effectiveDecisionMapper.getClass(),
        decisionMapperDefaulted ? "bootstrap-default" : "bootstrap-explicit",
        decisionMapperDefaulted));

    // JS-SEC-026: publish so the enforcing filter can pick it up. Until
    // V00.83 both values were recorded for diagnostics and never reached
    // RestAuthorizationFilter, which hard-wired its own mapper.
    eu.jsentinel.jcustos.rest.RestDecisionContext.publish(effectiveDecisionMapper);

    // R05-Rest (V00.76.10): the shared per-concern sub-builder consumption is
    // hoisted into the base. REST symmetry is preserved inside the applyX
    // methods.
    applyCommonConfiguration(AdapterKind.REST, services, warnings);

    publishSessionStore(services, warnings);

    installOriginGuard(services);

    // V00.74 (A2.2): publish CORS configuration when configured.
    if (corsConfiguration != null) {
      // R009: a wildcard origin combined with allowCredentials(true) is an
      // invalid/insecure CORS combination — browsers reject
      // "Access-Control-Allow-Origin: *" together with
      // "Access-Control-Allow-Credentials: true". Flag it as an ERROR so STRICT
      // mode rejects it; other modes record the warning.
      boolean credentialedWildcard = corsConfiguration.isCredentialedWildcard();
      if (credentialedWildcard) {
        warnings.add(new JCustosBootstrapWarning(
            Severity.ERROR,
            "cors/wildcard-with-credentials",
            "CORS is configured with a wildcard origin (\"*\") together with "
                + "allowCredentials(true).",
            "Browsers reject this combination. List explicit allowedOrigins(...) "
                + "instead of \"*\", or disable allowCredentials."));
      }
      // R15 (V00.76.10): in PRODUCTION, do NOT publish the dangerous
      // credentialed-wildcard config live — leave CORS unconfigured (no
      // cross-origin headers, the safe default) and rely on the ERROR warning
      // above, mirroring how the JWKS trust-root is refused in PRODUCTION (R11).
      // STRICT throws on the ERROR below; DEVELOPMENT / COMMUNITY_DEFAULTS still
      // publish so local cross-origin testing keeps working with the warning.
      boolean refusePublish = credentialedWildcard
          && state.mode() == JCustosBootstrapMode.PRODUCTION;
      if (refusePublish) {
        services.add(new RegisteredJCustosService(
            RestCorsContext.class, RestCorsConfiguration.class,
            "bootstrap-cors-refused-credentialed-wildcard", false));
      } else {
        RestCorsContext.publish(corsConfiguration);
        services.add(new RegisteredJCustosService(
            RestCorsContext.class, RestCorsConfiguration.class,
            "bootstrap-cors", false));
      }
      reportCredentialedCorsWithoutOriginGuard(warnings);
      reportCredentialedCorsOriginsTheGuardRefuses(warnings);
    }
    // V00.74 (A2.2): publish OpenAPI metadata when configured.
    if (openApiMetadata != null) {
      RestOpenApiContext.publish(openApiMetadata);
      services.add(new RegisteredJCustosService(
          RestOpenApiContext.class, RestOpenApiMetadata.class,
          "bootstrap-openapi-metadata", false));
    }

    crossCheckHandlers(warnings);

    JCustosBootstrapMode mode = state.mode();
    if (mode == JCustosBootstrapMode.STRICT && warningsContainError(warnings)) {
      throw new JCustosBootstrapException(warnings);
    }

    return new JCustosRuntime(services, warnings, mode);
  }
}
