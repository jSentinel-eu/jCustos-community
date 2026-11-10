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

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.dx.bootstrap.JCustosBootstrapException;
import eu.jsentinel.jcustos.dx.internal.AbstractJCustosBootstrap;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJCustosService;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import eu.jsentinel.jcustos.rest.RestSessionRevocation;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;
import eu.jsentinel.jcustos.session.SessionStore;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
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

  /** Finding the shared base records for {@code .storeBacked(...)} on a REST bootstrap. */
  private static final String SESSION_STORE_UNUSED = "rest/session-store-unused";

  private RestSubjectResolver subjectResolver;
  private RestHandlerDiscovery handlerDiscovery;
  private RestDecisionMapper decisionMapper;
  private RestErrorBodyStrategy errorBodies;
  private RestCorsConfiguration corsConfiguration;
  private RestOpenApiMetadata openApiMetadata;
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
   * whose session record was revoked. Until 00.84.00 REST did not read the store at all
   * and the shared base reported it as {@code rest/session-store-unused}; that finding is
   * no longer true and is taken out again. Without a configured store nothing is touched:
   * an application may have registered its store with {@link RestSessionRevocation}
   * itself.
   */
  private void publishSessionStore(List<RegisteredJCustosService> services,
                                   List<JCustosBootstrapWarning> warnings) {
    SessionStore sessionStore = state.sessionState().sessionStore();
    if (sessionStore == null) {
      return;
    }
    RestSessionRevocation.useSessionStore(sessionStore);
    warnings.removeIf(warning -> SESSION_STORE_UNUSED.equals(warning.code()));
    services.add(new RegisteredJCustosService(
        SessionStore.class, sessionStore.getClass(), "bootstrap-explicit", false));
  }

  @Override
  public JCustosRuntime install() {
    if (installed) {
      throw new IllegalStateException("install() may only be called once on the same builder");
    }
    installed = true;

    List<RegisteredJCustosService> services = new ArrayList<>();
    List<JCustosBootstrapWarning> warnings = new ArrayList<>();

    AuthenticationService<?, ?> authn = state.authenticationService();
    AuthorizationService<?> authz = state.authorizationService();

    if (authn != null) {
      JCustosServiceResolver.setAuthenticationService(authn);
      services.add(new RegisteredJCustosService(
          AuthenticationService.class, authn.getClass(), "bootstrap-explicit", false));
    } else {
      warnings.add(new JCustosBootstrapWarning(
          Severity.ERROR,
          "missing-authentication-service",
          "No AuthenticationService configured for RestSecurity.bootstrap().",
          "Call .authentication(...) or register an implementation via "
              + "@JCustosAutoService(AuthenticationService.class)."));
    }

    if (authz != null) {
      JCustosServiceResolver.setAuthorizationService(authz);
      services.add(new RegisteredJCustosService(
          AuthorizationService.class, authz.getClass(), "bootstrap-explicit", false));
    } else {
      warnings.add(new JCustosBootstrapWarning(
          Severity.ERROR,
          "missing-authorization-service",
          "No AuthorizationService configured for RestSecurity.bootstrap().",
          "Call .authorization(...) or register an implementation via "
              + "@JCustosAutoService(AuthorizationService.class)."));
    }

    if (subjectResolver != null) {
      services.add(new RegisteredJCustosService(
          RestSubjectResolver.class, subjectResolver.getClass(), "bootstrap-explicit", false));
    } else {
      warnings.add(new JCustosBootstrapWarning(
          Severity.ERROR,
          "missing-rest-subject-resolver",
          "No RestSubjectResolver configured for RestSecurity.bootstrap().",
          "Call .subjectResolver(...) or register an implementation via "
              + "@JCustosAutoService(RestSubjectResolver.class)."));
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
