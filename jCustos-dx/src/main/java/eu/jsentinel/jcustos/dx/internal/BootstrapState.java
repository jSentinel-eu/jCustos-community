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
package eu.jsentinel.jcustos.dx.internal;

import eu.jsentinel.jcustos.authentication.ApiKeyAuthenticationService;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authentication.TokenService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.net.ClientAddressResolver;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.logout.LogoutService;
import eu.jsentinel.jcustos.ratelimiting.RateLimitPolicy;

/**
 * Mutable aggregate of accumulated configuration during a fluent
 * bootstrap call. Reset to a fresh instance per bootstrap call.
 * <p>
 * <strong>Internal API.</strong> Used by {@link AbstractJCustosBootstrap}
 * and adapter-DX module subclasses; not part of the V00.72 public surface.
 *
 * @since 00.72.00
 */
public final class BootstrapState {

  private AuthenticationService<?, ?> authenticationService;
  private AuthorizationService<?> authorizationService;
  private JCustosBootstrapMode mode = JCustosBootstrapMode.COMMUNITY_DEFAULTS;

  private boolean auditConfigured;
  private boolean sessionsConfigured;
  private boolean policiesConfigured;
  private boolean rolesConfigured;
  private boolean credentialsConfigured;
  private boolean propagationConfigured;

  // V00.74: direct-set services on CommonJCustosBootstrap
  private LogoutService logoutService;
  private LoginAttemptPolicy loginAttemptPolicy;
  // V00.84 (JS-SEC-061): client-address resolution.
  private ClientAddressResolver clientAddressResolver;
  private RateLimitPolicy rateLimitPolicy;
  private ApiKeyAuthenticationService apiKeyAuthenticationService;
  private TokenService tokenService;

  private final AuditState auditState = new AuditState();
  private final SessionState sessionState = new SessionState();
  private final RoleState roleState = new RoleState();
  private final CredentialState credentialState = new CredentialState();
  private final PolicyState policyState = new PolicyState();
  private final PropagationState propagationState = new PropagationState();
  // V00.76: JWT validation sub-aggregate.
  private boolean jwtConfigured;
  private final JwtState jwtState = new JwtState();
  // V00.77: OAuth2 Relying-Party sub-aggregate.
  private boolean oauth2Configured;
  private final OAuth2State oauth2State = new OAuth2State();
  // V00.78: OIDC Relying-Party sub-aggregate.
  private boolean oidcConfigured;
  private final OidcState oidcState = new OidcState();

  /** @return the typed audit sub-aggregate (V00.73) */
  public AuditState auditState() {
    return auditState;
  }

  /** @return the typed sessions sub-aggregate (V00.73) */
  public SessionState sessionState() {
    return sessionState;
  }

  /** @return the typed roles sub-aggregate (V00.73) */
  public RoleState roleState() {
    return roleState;
  }

  /** @return the typed credentials sub-aggregate (V00.73) */
  public CredentialState credentialState() {
    return credentialState;
  }

  /** @return the typed policies sub-aggregate (V00.73) */
  public PolicyState policyState() {
    return policyState;
  }

  public AuthenticationService<?, ?> authenticationService() {
    return authenticationService;
  }

  public void authenticationService(AuthenticationService<?, ?> service) {
    this.authenticationService = service;
  }

  public AuthorizationService<?> authorizationService() {
    return authorizationService;
  }

  public void authorizationService(AuthorizationService<?> service) {
    this.authorizationService = service;
  }

  public JCustosBootstrapMode mode() {
    return mode;
  }

  public void mode(JCustosBootstrapMode mode) {
    if (mode != null) {
      this.mode = mode;
    }
  }

  /** JS-SEC-085: {@code null} until {@code denyByDefault(boolean)} was called. */
  private Boolean denyByDefault;

  public Boolean denyByDefault() {
    return denyByDefault;
  }

  public void denyByDefault(boolean enabled) {
    this.denyByDefault = enabled;
  }

  public boolean auditConfigured() {
    return auditConfigured;
  }

  public void markAuditConfigured() {
    this.auditConfigured = true;
  }

  public boolean sessionsConfigured() {
    return sessionsConfigured;
  }

  public void markSessionsConfigured() {
    this.sessionsConfigured = true;
  }

  public boolean policiesConfigured() {
    return policiesConfigured;
  }

  public void markPoliciesConfigured() {
    this.policiesConfigured = true;
  }

  public boolean rolesConfigured() {
    return rolesConfigured;
  }

  public void markRolesConfigured() {
    this.rolesConfigured = true;
  }

  public boolean credentialsConfigured() {
    return credentialsConfigured;
  }

  public void markCredentialsConfigured() {
    this.credentialsConfigured = true;
  }

  /** V00.74 — typed propagation sub-aggregate. */
  public PropagationState propagationState() {
    return propagationState;
  }

  /** V00.74 — true if {@code .propagation(...)} was called. */
  public boolean propagationConfigured() {
    return propagationConfigured;
  }

  /** V00.74 — call after consuming {@code .propagation(...)}. */
  public void markPropagationConfigured() {
    this.propagationConfigured = true;
  }

  /** V00.76 — typed JWT sub-aggregate. */
  public JwtState jwtState() {
    return jwtState;
  }

  /** V00.76 — true if {@code .jwt(...)} was called. */
  public boolean jwtConfigured() {
    return jwtConfigured;
  }

  /** V00.76 — call after consuming {@code .jwt(...)}. */
  public void markJwtConfigured() {
    this.jwtConfigured = true;
  }

  /** V00.77 — typed OAuth2 RP sub-aggregate. */
  public OAuth2State oauth2State() {
    return oauth2State;
  }

  /** V00.77 — true if {@code .oauth2(...)} was called. */
  public boolean oauth2Configured() {
    return oauth2Configured;
  }

  /** V00.77 — call after consuming {@code .oauth2(...)}. */
  public void markOAuth2Configured() {
    this.oauth2Configured = true;
  }

  /** V00.78 — typed OIDC RP sub-aggregate. */
  public OidcState oidcState() {
    return oidcState;
  }

  /** V00.78 — true if {@code .oidc(...)} was called. */
  public boolean oidcConfigured() {
    return oidcConfigured;
  }

  /** V00.78 — call after consuming {@code .oidc(...)}. */
  public void markOidcConfigured() {
    this.oidcConfigured = true;
  }

  // V00.74 accessors

  public LogoutService logoutService() {
    return logoutService;
  }

  public void logoutService(LogoutService service) {
    this.logoutService = service;
  }

  public LoginAttemptPolicy loginAttemptPolicy() {
    return loginAttemptPolicy;
  }

  public void loginAttemptPolicy(LoginAttemptPolicy policy) {
    this.loginAttemptPolicy = policy;
  }

  public ClientAddressResolver clientAddressResolver() {
    return clientAddressResolver;
  }

  public void clientAddressResolver(ClientAddressResolver resolver) {
    this.clientAddressResolver = resolver;
  }

  public RateLimitPolicy rateLimitPolicy() {
    return rateLimitPolicy;
  }

  public void rateLimitPolicy(RateLimitPolicy policy) {
    this.rateLimitPolicy = policy;
  }

  public ApiKeyAuthenticationService apiKeyAuthenticationService() {
    return apiKeyAuthenticationService;
  }

  public void apiKeyAuthenticationService(ApiKeyAuthenticationService service) {
    this.apiKeyAuthenticationService = service;
  }

  public TokenService tokenService() {
    return tokenService;
  }

  public void tokenService(TokenService service) {
    this.tokenService = service;
  }
}
