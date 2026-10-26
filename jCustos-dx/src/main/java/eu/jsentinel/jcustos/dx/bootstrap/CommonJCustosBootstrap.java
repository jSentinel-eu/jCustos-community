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
package eu.jsentinel.jcustos.dx.bootstrap;

import eu.jsentinel.jcustos.authentication.ApiKeyAuthenticationService;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authentication.TokenService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.net.ClientAddressResolver;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.logout.LogoutService;
import eu.jsentinel.jcustos.ratelimiting.RateLimitPolicy;

import java.util.function.Consumer;

/**
 * Common fluent contract shared by every adapter-specific bootstrap
 * facade ({@code VaadinSecurity.bootstrap()}, {@code RestSecurity.bootstrap()},
 * {@code StandaloneSecurity.bootstrap()}).
 * <p>
 * The recursive self-type parameter {@code B} keeps the chain typed: a
 * Vaadin-specific call still returns a {@code VaadinJCustosBootstrap},
 * not the bare common type.
 *
 * @param <B> the concrete builder type (recursive)
 *
 * @since 00.72.00
 */
public interface CommonJCustosBootstrap<B extends CommonJCustosBootstrap<B>> {

  B authentication(AuthenticationService<?, ?> service);

  B authorization(AuthorizationService<?> service);

  B audit(Consumer<AuditBootstrap> config);

  B sessions(Consumer<SessionBootstrap> config);

  B policies(Consumer<PolicyBootstrap> config);

  B roles(Consumer<RoleBootstrap> config);

  B credentials(Consumer<CredentialBootstrap> config);

  /**
   * V00.74: declarative token-propagation sub-builder. The Konzept §10
   * sub-builder shape — adapter-symmetric (Vaadin / REST / Standalone
   * each install the recorded state in their {@code install()} pass).
   *
   * @param config non-null lambda recording into a
   *               {@link PropagationBootstrap}
   * @return this builder
   * @since 00.74.00
   */
  B propagation(Consumer<PropagationBootstrap> config);

  /**
   * V00.76: declarative JWT-validation sub-builder. Adapter-symmetric — each
   * adapter installs the recorded state in its {@code install()} pass via the
   * ServiceLoader-discovered {@code JwtValidatorFactory} (or the explicit
   * {@code .validator(...)}). JWT validation is format work, not UI work, so all
   * three facades share it.
   *
   * @param config non-null lambda recording into a {@link JwtBootstrap}
   * @return this builder
   * @since 00.76.00
   */
  B jwt(Consumer<JwtBootstrap> config);

  /**
   * V00.77: declarative OAuth2 Relying-Party sub-builder. Adapter-symmetric —
   * each adapter installs the recorded RP configuration in its {@code install()}
   * pass (Vaadin: redirect/callback route; REST: callback handler; Standalone:
   * device grant). The DX layer only records + STRICT-validates; the HTTP clients
   * are assembled in the {@code jCustos-oauth2-*} modules, so this facade stays
   * JOSE-free.
   *
   * @param config non-null lambda recording into an {@link OAuth2Bootstrap}
   * @return this builder
   * @since 00.77.00
   */
  B oauth2(Consumer<OAuth2Bootstrap> config);

  /**
   * V00.78: declarative OIDC Relying-Party sub-builder (identity layer over the
   * V00.77 OAuth2 flows). Adapter-symmetric. The DX layer only records +
   * STRICT-validates; the HTTP clients are assembled in the
   * {@code jCustos-identity-oidc(-*)} modules, so this facade stays JOSE-free.
   *
   * @param config non-null lambda recording into an {@link OidcBootstrap}
   * @return this builder
   * @since 00.78.00
   */
  B oidc(Consumer<OidcBootstrap> config);

  /**
   * V00.74: registers a logout service. Wired through
   * {@code JCustosServiceResolver.setLogoutService(...)} by
   * {@code install()}.
   *
   * @param service non-null logout service
   * @return this builder
   * @since 00.74.00
   */
  B logout(LogoutService service);

  /**
   * V00.74: registers the brute-force / login-attempt policy.
   * Wired through {@code JCustosServiceResolver.setLoginAttemptPolicy(...)}
   * by {@code install()}.
   *
   * @param policy non-null login-attempt policy
   * @return this builder
   * @since 00.74.00
   */
  B bruteForce(LoginAttemptPolicy policy);

  /**
   * V00.84 (JS-SEC-061, CWE-348): registers how the client address is resolved.
   * Behind a reverse proxy pass {@code ClientAddressResolver.trustedProxies(...)}
   * with the proxy addresses so {@code X-Forwarded-For} is honoured from those
   * peers only; without this call the connection peer is the client. Wired
   * through {@code JCustosServiceResolver.setClientAddressResolver(...)} by
   * {@code install()}.
   *
   * @param resolver non-null resolver
   * @return this builder
   * @since 00.84.00
   */
  B clientAddress(ClientAddressResolver resolver);

  /**
   * V00.74: registers a rate-limit policy. Stored in DX state /
   * {@code JCustosRuntime} and consumed by adapter-DX modules
   * (e.g. REST handlers) — no global resolver setter exists for
   * this type.
   *
   * @param policy non-null rate-limit policy
   * @return this builder
   * @since 00.74.00
   */
  B rateLimit(RateLimitPolicy policy);

  /**
   * V00.74: registers an API-key authentication service. Stored in
   * DX state / {@code JCustosRuntime}; consumed by REST adapters
   * that wire the resolver themselves.
   *
   * @param service non-null API-key auth service
   * @return this builder
   * @since 00.74.00
   */
  B apiKeys(ApiKeyAuthenticationService service);

  /**
   * V00.74: registers a refresh-token service. Stored in DX state /
   * {@code JCustosRuntime}; consumed by REST adapters that wire
   * the rotation flow themselves.
   *
   * @param service non-null token service
   * @return this builder
   * @since 00.74.00
   */
  B refreshTokens(TokenService service);

  B mode(JCustosBootstrapMode mode);

  /**
   * Switches deny-by-default on or off for the whole application (JS-SEC-085,
   * CWE-1188): with {@code true} an element without a security annotation is
   * denied unless it carries {@code @PublicRoute}; with {@code false} it is
   * served to everyone (allow-by-omission). {@code install()} publishes the
   * value through {@code JCustosServiceResolver.setDenyByDefault}. When the
   * flag is off at install time, STRICT reports
   * {@code authorization/allow-by-omission} as an ERROR and refuses to boot,
   * PRODUCTION as a WARNING.
   *
   * @param enabled {@code true} for deny-by-default
   * @return this builder
   * @since 00.84.00
   */
  B denyByDefault(boolean enabled);

  JCustosRuntime install();
}
