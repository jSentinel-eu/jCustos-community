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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.dx.bootstrap.CommonJCustosBootstrap;
import eu.jsentinel.jcustos.rest.RestOriginGuard;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;

import java.util.function.Consumer;
import eu.jsentinel.jcustos.dx.rest.handlers.RestHandlerDiscovery;

/**
 * REST-specific fluent bootstrap. Entry point:
 * {@link RestSecurity#bootstrap()}.
 *
 * @since 00.72.00
 */
public interface RestJCustosBootstrap
    extends CommonJCustosBootstrap<RestJCustosBootstrap> {

  RestJCustosBootstrap subjectResolver(RestSubjectResolver resolver);

  RestJCustosBootstrap decisionMapper(RestDecisionMapper mapper);

  RestJCustosBootstrap errorBodies(RestErrorBodyStrategy strategy);

  /**
   * V00.74: Convenience for
   * {@code .errorBodies(ProblemJsonErrorBodyStrategy.INSTANCE)} —
   * emits RFC 7807 {@code application/problem+json} bodies for
   * denial decisions.
   *
   * @return this builder
   * @since 00.74.00
   */
  default RestJCustosBootstrap problemJsonErrors() {
    return errorBodies(ProblemJsonErrorBodyStrategy.INSTANCE);
  }

  /**
   * V00.74: Configures CORS for the REST adapter. The published
   * {@link RestCorsConfiguration} is consumed by downstream REST
   * glue (a servlet filter, embedded server, etc.) — the library
   * does not ship a CORS filter itself.
   *
   * @param consumer non-null consumer that configures the
   *                 {@link RestCorsConfigurationBuilder}
   * @return this builder
   * @since 00.74.00
   */
  RestJCustosBootstrap cors(Consumer<RestCorsConfigurationBuilder> consumer);

  /**
   * V00.74: Configures OpenAPI document metadata
   * ({@code Info.title} / {@code Info.version} /
   * {@code Info.description} / {@code servers[]}). The published
   * {@link RestOpenApiMetadata} is consumed by
   * {@code OpenApiSecurityMetadataGenerator} at document-generation
   * time.
   *
   * @param consumer non-null consumer that configures the
   *                 {@link RestOpenApiMetadataBuilder}
   * @return this builder
   * @since 00.74.00
   */
  RestJCustosBootstrap openApiMetadata(Consumer<RestOpenApiMetadataBuilder> consumer);

  /**
   * V00.82: Registers the handler enumeration used for the deny-by-default
   * startup check (CWE-862).
   *
   * <p>With deny-by-default on, a handler carrying no security annotation is
   * refused at runtime. That is the right outcome, but a REST application only
   * discovered it when a request arrived — Vaadin reports it at startup because
   * its router can enumerate routes, and REST has no such registry. Naming your
   * handler classes here restores the startup check:
   *
   * <pre>{@code
   * RestSecurity.bootstrap()
   *     .discoverHandlers(new ClassScanningRestHandlerDiscovery(DocumentHandlers.class))
   *     .mode(JCustosBootstrapMode.STRICT)
   *     .install();
   * }</pre>
   *
   * <p>Each unprotected handler becomes an ERROR finding, so STRICT refuses to
   * boot rather than serving an unguarded endpoint. Without deny-by-default the
   * enumeration is not consulted at all.
   *
   * @param discovery non-null enumeration of the application's handlers
   * @return this builder
   * @since 00.82.00
   */
  RestJCustosBootstrap discoverHandlers(RestHandlerDiscovery discovery);

  /**
   * Installs a {@link RestOriginGuard} for the process (CSRF, CWE-352): state-changing
   * requests ({@code POST}, {@code PUT}, {@code PATCH}, {@code DELETE}, …) that a browser
   * sends on behalf of another origin are refused with {@code 403} through the published
   * decision mapper and audited as {@code AccessDenied} with reason
   * {@value RestOriginGuard#REASON_ORIGIN_MISMATCH}.
   *
   * <p>{@code install()} calls {@link RestOriginGuard#install(RestOriginGuard)} and lists the
   * guard as {@code bootstrap-origin-guard}. jCustos ships no request pipeline, so the guard
   * is registered, not wired: the application's router runs it as its outermost filter, the
   * first step of every route, in front of the jCustos filters and the handler:
   * <pre>{@code
   * if (RestOriginGuard.installed().map(guard -> !guard.allow(request, response)).orElse(false)) {
   *   return;                      // 403 written and audited
   * }
   * }</pre>
   * The skill templates' {@code Router} does this. The jCustos REST filters run the installed
   * guard before their own checks as well; a route that passes neither the router step nor a
   * jCustos filter is not protected.
   *
   * <pre>{@code
   * RestSecurity.bootstrap()
   *     .cors(c -> c.allowedOrigins("https://app.example").allowCredentials(true))
   *     .originGuard(RestOriginGuard.sameOrigin()
   *         .withAllowedOrigins(Set.of("https://api.example", "https://app.example")))
   *     .install();
   * }</pre>
   *
   * <p>Only for cookie-based sessions: a bearer token is not sent by the browser on its own.
   * Without the guard, a CORS configuration that allows credentials is reported as
   * {@code rest/credentialed-cors-without-origin-guard} (WARNING in PRODUCTION and STRICT,
   * INFO otherwise); with a guard, a credentialed CORS origin the guard does not accept is
   * reported as {@code rest/credentialed-cors-origin-not-accepted} (WARNING) - its
   * state-changing requests would all be refused. Without this call nothing is touched: a guard
   * the application installed itself stays.
   *
   * @param guard the guard; non-null
   * @return this builder
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  RestJCustosBootstrap originGuard(RestOriginGuard guard);
}
