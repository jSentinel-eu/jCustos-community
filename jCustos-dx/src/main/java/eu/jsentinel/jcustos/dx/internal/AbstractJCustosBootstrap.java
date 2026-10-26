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

import eu.jsentinel.jcustos.audit.AuditSink;
import eu.jsentinel.jcustos.audit.NoopJCustosAuditService;
import eu.jsentinel.jcustos.audit.LoggingAuditSink;
import eu.jsentinel.jcustos.audit.RingBufferAuditSink;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.StoreBackedJCustosAuditService;
import eu.jsentinel.jcustos.authentication.ApiKeyAuthenticationService;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authentication.PasswordHasher;
import eu.jsentinel.jcustos.authentication.Pbkdf2PasswordHasher;
import eu.jsentinel.jcustos.authentication.TokenService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.authorization.api.roles.RoleHierarchy;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.net.ClientAddressResolver;
import eu.jsentinel.jcustos.logout.LogoutService;
import eu.jsentinel.jcustos.ratelimiting.RateLimitPolicy;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.policy.api.Policy;
import eu.jsentinel.jcustos.policy.spi.PolicyRegistry;
import eu.jsentinel.jcustos.policy.spi.ResourceResolver;
import eu.jsentinel.jcustos.policy.spi.ResourceResolverRegistry;
import eu.jsentinel.jcustos.session.JCustosVersionStore;
import eu.jsentinel.jcustos.session.SessionPolicy;
import eu.jsentinel.jcustos.session.SessionStore;
import eu.jsentinel.jcustos.session.TimeoutSessionPolicy;
import eu.jsentinel.jcustos.dx.bootstrap.AuditBootstrap;
import eu.jsentinel.jcustos.dx.bootstrap.CommonJCustosBootstrap;
import eu.jsentinel.jcustos.dx.bootstrap.CredentialBootstrap;
import eu.jsentinel.jcustos.dx.bootstrap.PolicyBootstrap;
import eu.jsentinel.jcustos.dx.bootstrap.RoleBootstrap;
import eu.jsentinel.jcustos.dx.bootstrap.SessionBootstrap;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJCustosService;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.runtime.Severity;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Skeleton implementation of {@link CommonJCustosBootstrap} shared by
 * the three adapter-specific bootstrap classes. Accumulates configuration
 * into a {@link BootstrapState}; the adapter subclass owns {@link #install()}
 * and supplies the concrete return type via the recursive type parameter.
 * <p>
 * <strong>Internal API.</strong> Not part of the public V00.72 surface.
 *
 * @param <B> the concrete adapter builder type
 *
 * @since 00.72.00
 */
public abstract class AbstractJCustosBootstrap<B extends CommonJCustosBootstrap<B>>
    implements CommonJCustosBootstrap<B> {

  protected final BootstrapState state = new BootstrapState();

  /**
   * @return {@code this} narrowed to the concrete builder type
   */
  @SuppressWarnings("unchecked")
  protected final B self() {
    return (B) this;
  }

  @Override
  public B authentication(AuthenticationService<?, ?> service) {
    state.authenticationService(Objects.requireNonNull(service, "service"));
    return self();
  }

  @Override
  public B authorization(AuthorizationService<?> service) {
    state.authorizationService(Objects.requireNonNull(service, "service"));
    return self();
  }

  @Override
  public B audit(Consumer<AuditBootstrap> config) {
    Objects.requireNonNull(config, "config").accept(new AuditBootstrapImpl(state.auditState()));
    state.markAuditConfigured();
    return self();
  }

  @Override
  public B sessions(Consumer<SessionBootstrap> config) {
    Objects.requireNonNull(config, "config").accept(new SessionBootstrapImpl(state.sessionState()));
    state.markSessionsConfigured();
    return self();
  }

  @Override
  public B policies(Consumer<PolicyBootstrap> config) {
    Objects.requireNonNull(config, "config")
        .accept(new PolicyBootstrapImpl(state.policyState()));
    state.markPoliciesConfigured();
    return self();
  }

  @Override
  public B roles(Consumer<RoleBootstrap> config) {
    Objects.requireNonNull(config, "config").accept(new RoleBootstrapImpl(state.roleState()));
    state.markRolesConfigured();
    return self();
  }

  @Override
  public B credentials(Consumer<CredentialBootstrap> config) {
    Objects.requireNonNull(config, "config")
        .accept(new CredentialBootstrapImpl(state.credentialState()));
    state.markCredentialsConfigured();
    return self();
  }

  @Override
  public B propagation(
      Consumer<eu.jsentinel.jcustos.dx.bootstrap.PropagationBootstrap> config) {
    Objects.requireNonNull(config, "config")
        .accept(new RecordingPropagationBootstrap(state.propagationState()));
    state.markPropagationConfigured();
    return self();
  }

  @Override
  public B jwt(Consumer<eu.jsentinel.jcustos.dx.bootstrap.JwtBootstrap> config) {
    Objects.requireNonNull(config, "config")
        .accept(new RecordingJwtBootstrap(state.jwtState()));
    state.markJwtConfigured();
    return self();
  }

  @Override
  public B oauth2(Consumer<eu.jsentinel.jcustos.dx.bootstrap.OAuth2Bootstrap> config) {
    Objects.requireNonNull(config, "config")
        .accept(new RecordingOAuth2Bootstrap(state.oauth2State()));
    state.markOAuth2Configured();
    return self();
  }

  @Override
  public B oidc(Consumer<eu.jsentinel.jcustos.dx.bootstrap.OidcBootstrap> config) {
    Objects.requireNonNull(config, "config")
        .accept(new RecordingOidcBootstrap(state.oidcState()));
    state.markOidcConfigured();
    return self();
  }

  @Override
  public B logout(LogoutService service) {
    state.logoutService(Objects.requireNonNull(service, "service"));
    return self();
  }

  @Override
  public B bruteForce(LoginAttemptPolicy policy) {
    state.loginAttemptPolicy(Objects.requireNonNull(policy, "policy"));
    return self();
  }

  @Override
  public B clientAddress(ClientAddressResolver resolver) {
    state.clientAddressResolver(Objects.requireNonNull(resolver, "resolver"));
    return self();
  }

  @Override
  public B rateLimit(RateLimitPolicy policy) {
    state.rateLimitPolicy(Objects.requireNonNull(policy, "policy"));
    return self();
  }

  @Override
  public B apiKeys(ApiKeyAuthenticationService service) {
    state.apiKeyAuthenticationService(Objects.requireNonNull(service, "service"));
    return self();
  }

  @Override
  public B refreshTokens(TokenService service) {
    state.tokenService(Objects.requireNonNull(service, "service"));
    return self();
  }

  @Override
  public B mode(JCustosBootstrapMode mode) {
    state.mode(Objects.requireNonNull(mode, "mode"));
    return self();
  }

  @Override
  public B denyByDefault(boolean enabled) {
    state.denyByDefault(enabled);
    return self();
  }

  /**
   * Default skeleton implementation: throws {@link UnsupportedOperationException}.
   * Adapter subclasses (Prompts 004-006) override this to perform the
   * actual {@code JCustosServiceResolver} registration and produce the
   * runtime result.
   */
  @Override
  public JCustosRuntime install() {
    throw new UnsupportedOperationException(
        "install() must be overridden by an adapter-specific bootstrap class");
  }

  /**
   * R05-Rest (V00.76.10): the shared {@code install()} body. Each adapter's
   * {@code install()} performs its own adapter-specific pre-steps (the
   * once-only guard, mandatory authn/authz resolution) and post-steps (REST CORS
   * / OpenAPI, Vaadin secure-route discovery, the STRICT-mode error gate, the
   * {@link JCustosRuntime} result) — but the per-concern sub-builder
   * consumption in between was duplicated verbatim across all three adapters.
   * This template hoists that identical sequence into one place; the only
   * adapter-specific variation is the {@link AdapterKind} passed to
   * {@link #applySessionConfiguration}. Behaviour and ordering are unchanged.
   *
   * @param adapter  the adapter kind (drives session-store applicability)
   * @param services the running service registry to append to
   * @param warnings the running warning list to append to
   */
  protected final void applyCommonConfiguration(AdapterKind adapter,
      List<RegisteredJCustosService> services,
      List<JCustosBootstrapWarning> warnings) {
    // JS-SEC-085: first, so the adapters' deny-by-default cross-checks see the flag
    applyDenyByDefaultConfiguration(services, warnings);
    // direct-set services from CommonJCustosBootstrap
    // (logout / bruteForce / rateLimit / apiKeys / refreshTokens)
    applyDirectServiceConfiguration(services, warnings);
    applyAuditConfiguration(services, warnings);
    applySessionConfiguration(adapter, services, warnings);
    applyRoleConfiguration(services, warnings);
    applyCredentialConfiguration(services, warnings);
    applyPolicyConfiguration(services, warnings);
    applyPropagationConfiguration(services, warnings);
    applyJwtConfiguration(services, warnings);
    applyOAuth2Configuration(services, warnings);
    applyOidcConfiguration(services, warnings);
  }

  /**
   * V00.74 — consume the {@link PropagationState} accumulated by
   * {@code .propagation(...)}. Registers the chosen credential store
   * (or the SPI default), the named strategies and the default
   * strategy via {@link JCustosServiceResolver}. Surfaces every
   * registration in {@code services} so {@link JCustosRuntime} lists
   * them.
   *
   * <p>Called by each adapter's {@code install()}.
   */
  protected final void applyPropagationConfiguration(
      List<RegisteredJCustosService> services,
      List<JCustosBootstrapWarning> warnings) {
    eu.jsentinel.jcustos.dx.internal.PropagationState propagation = state.propagationState();

    // Credential store: explicit chain wins over SPI default.
    if (propagation.credentialStore() != null) {
      JCustosServiceResolver.setTokenCredentialStore(propagation.credentialStore());
      services.add(new RegisteredJCustosService(
          eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore.class,
          propagation.credentialStore().getClass(),
          "bootstrap-explicit",
          false));
    } else {
      // SPI default — best-effort. Demos that bring two adapter
      // modules (e.g. Vaadin starter + in-process REST backend) will
      // see multiple SPI providers; rather than abort the bootstrap
      // we silently skip the auto-default and let the consumer choose
      // explicitly via .propagation(p -> p.credentialStore(...)).
      try {
        JCustosServiceResolver.findTokenCredentialStore().ifPresent(spi ->
            services.add(new RegisteredJCustosService(
                eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore.class,
                spi.getClass(),
                "spi-default",
                true)));
      } catch (IllegalStateException multipleSpi) {
        // Multiple SPI providers — leave the store unset.
      }
    }

    // Default strategy under "default" + "pass-through" alias when
    // .passThrough() was set explicitly.
    if (propagation.defaultStrategy() != null) {
      JCustosServiceResolver.registerOutboundTokenStrategy(
          "default", propagation.defaultStrategy());
      JCustosServiceResolver.registerOutboundTokenStrategy(
          propagation.defaultStrategy().name(), propagation.defaultStrategy());
      services.add(new RegisteredJCustosService(
          eu.jsentinel.jcustos.credential.propagation.OutboundTokenStrategy.class,
          propagation.defaultStrategy().getClass(),
          "bootstrap-default-strategy",
          false));
    }

    // Named strategies.
    propagation.namedStrategies().forEach((name, strategy) -> {
      JCustosServiceResolver.registerOutboundTokenStrategy(name, strategy);
      services.add(new RegisteredJCustosService(
          eu.jsentinel.jcustos.credential.propagation.OutboundTokenStrategy.class,
          strategy.getClass(),
          "bootstrap-strategy:" + name,
          false));
    });
  }

  /**
   * V00.76 — consume the {@link eu.jsentinel.jcustos.dx.internal.JwtState}
   * accumulated by {@code .jwt(...)}. The explicit {@code .validator(...)} wins;
   * otherwise a Nimbus validator is assembled from the {@code .jwksUri(...)} path
   * via the ServiceLoader-discovered {@code JwtValidatorFactory} (keeping this DX
   * layer free of any JOSE compile dependency). Emits the §13.2 STRICT codes.
   * Called by each adapter's {@code install()}.
   */
  protected final void applyJwtConfiguration(
      List<RegisteredJCustosService> services,
      List<JCustosBootstrapWarning> warnings) {
    if (!state.jwtConfigured()) {
      return;
    }
    eu.jsentinel.jcustos.dx.internal.JwtState jwt = state.jwtState();
    if (!jwt.hasAnySelection()) {
      // empty .jwt(j -> {}) — silent on purpose
      return;
    }

    // Explicit validator wins.
    if (jwt.validator() != null) {
      JCustosServiceResolver.setJwtValidator(jwt.validator());
      services.add(new RegisteredJCustosService(
          eu.jsentinel.jcustos.jwt.api.JwtValidator.class,
          jwt.validator().getClass(), "bootstrap-explicit", false));
      return;
    }

    // jwksUri path.
    if (jwt.jwksUri() == null) {
      warnings.add(new JCustosBootstrapWarning(Severity.ERROR,
          "jwt/missing-jwks-uri-or-validator",
          ".jwt(...) needs either .jwksUri(...) or .validator(...).",
          "Add .jwksUri(URI.create(\"https://idp/.well-known/jwks.json\")) or pass .validator(...)."));
      return;
    }

    eu.jsentinel.jcustos.jwt.api.AlgorithmAllowList allowList;
    if (jwt.allowList() != null) {
      allowList = jwt.allowList();
    } else if (jwt.profile() != null) {
      if (jwt.profile() == eu.jsentinel.jcustos.jwt.api.AlgorithmProfile.CUSTOM) {
        // RF02: CUSTOM has no intrinsic allow-list (toAllowList() would throw) — fail
        // gracefully as a STRICT-class warning instead of an uncaught exception.
        warnings.add(new JCustosBootstrapWarning(Severity.ERROR,
            "jwt/custom-profile-needs-allow-list",
            ".algorithmProfile(CUSTOM) has no intrinsic allow-list.",
            "Pass an explicit .algorithmAllowList(...) instead of the CUSTOM profile."));
        return;
      }
      allowList = jwt.profile().toAllowList();
    } else {
      warnings.add(new JCustosBootstrapWarning(Severity.ERROR,
          "jwt/no-algorithm-allow-list",
          ".jwt(...) was configured without an algorithm profile or allow-list.",
          "Add .algorithmProfile(AlgorithmProfile.STRICT_MODERN) or .algorithmAllowList(...)."));
      return;
    }

    if (!"https".equalsIgnoreCase(jwt.jwksUri().getScheme())) {
      // R11 (V00.76.10): a non-https JWKS URI fetches the entire JWT trust root
      // over cleartext, where a MITM can substitute its own JWKS and forge
      // tokens that pass the allow-list + family + signature checks against the
      // attacker's key. That must not be a mere warning in PRODUCTION — it is an
      // ERROR there too (was WARNING). Only the local dev modes (DEVELOPMENT /
      // COMMUNITY_DEFAULTS) keep it at INFO so loopback http works for local IdPs.
      Severity severity = switch (state.mode()) {
        case STRICT, PRODUCTION -> Severity.ERROR;
        default -> Severity.INFO;
      };
      warnings.add(new JCustosBootstrapWarning(severity, "jwks/uri-not-https",
          "JWKS URI is not https (" + jwt.jwksUri().getScheme() + ").",
          "Use an https JWKS endpoint."));
      if (severity == Severity.ERROR) {
        return;
      }
    }

    if (jwt.issuer() == null) {
      warnings.add(new JCustosBootstrapWarning(Severity.INFO, "jwt/issuer-missing",
          ".jwt(...) has no .issuer(...); inbound tokens will not be issuer-checked.",
          "Add .issuer(\"https://idp/\")."));
    }

    if (jwt.audiences() == null || jwt.audiences().isEmpty()) {
      // JS-SEC-005 (CWE-345): an empty acceptedAudiences accepts any aud. Surface
      // it (Konzept §567 / ClaimExpectations JavaDoc promised this INFO). Not an
      // ERROR — RFC 7519 makes aud validation conditional; STRICT stays on .oidc().
      warnings.add(new JCustosBootstrapWarning(Severity.INFO, "claims/audience-empty",
          ".jwt(...) has no .audience(...); inbound tokens will not be audience-checked "
              + "(any aud is accepted). Unsafe behind a multi-RP shared IdP.",
          "Add .audience(\"<your-client-id>\")."));
    }

    eu.jsentinel.jcustos.jwt.api.ClaimExpectations expectations =
        new eu.jsentinel.jcustos.jwt.api.ClaimExpectations(
            java.util.Optional.ofNullable(jwt.issuer()), jwt.audiences(),
            true, false, false, false,
            jwt.clockSkew() != null
                ? new eu.jsentinel.jcustos.jwt.api.ClockSkewPolicy(jwt.clockSkew())
                : eu.jsentinel.jcustos.jwt.api.ClockSkewPolicy.DEFAULT,
            // F4 (V00.76.10): optional typ-header check via .jwt(j -> j.tokenType(...)).
            java.util.Optional.ofNullable(jwt.tokenType()));

    java.util.Optional<eu.jsentinel.jcustos.jwt.api.JwtValidatorFactory> factory =
        java.util.ServiceLoader.load(eu.jsentinel.jcustos.jwt.api.JwtValidatorFactory.class)
            .findFirst();
    if (factory.isEmpty()) {
      warnings.add(new JCustosBootstrapWarning(Severity.ERROR, "jwt/factory-missing",
          "No JwtValidatorFactory on the classpath (the jCustos-jwt module).",
          "Add the jCustos-jwt dependency, or pass a pre-built .validator(...)."));
      return;
    }
    eu.jsentinel.jcustos.jwt.api.JwtValidator validator = factory.get().create(
        new eu.jsentinel.jcustos.jwt.api.JwtValidatorSpec(jwt.jwksUri(), allowList, expectations));
    JCustosServiceResolver.setJwtValidator(validator);
    services.add(new RegisteredJCustosService(
        eu.jsentinel.jcustos.jwt.api.JwtValidator.class,
        validator.getClass(), "bootstrap-jwks", false));
  }

  /**
   * V00.77 — validate the {@link OAuth2State} recorded by {@code .oauth2(...)}
   * and emit the Konzept §11.3 codes. The DX layer does not construct the HTTP
   * clients (that is adapter-side in {@code jCustos-oauth2-*}); it only
   * enforces that a usable RP configuration was supplied. STRICT raises on
   * {@code oauth2/missing-client-id}, {@code oauth2/missing-token-endpoint} and
   * {@code oauth2/redirect-uri-not-https}; an empty scope is INFO only.
   */
  protected final void applyOAuth2Configuration(
      List<RegisteredJCustosService> services,
      List<JCustosBootstrapWarning> warnings) {
    if (!state.oauth2Configured()) {
      return;
    }
    OAuth2State oauth2 = state.oauth2State();
    if (!oauth2.hasAnySelection()) {
      // empty .oauth2(o -> {}) — silent on purpose
      return;
    }

    if (oauth2.clientId() == null || oauth2.clientId().isBlank()) {
      warnings.add(new JCustosBootstrapWarning(Severity.ERROR, "oauth2/missing-client-id",
          ".oauth2(...) was configured without a .clientId(...).",
          "Add .oauth2(o -> o.clientId(\"my-rp\") ...)."));
      return;
    }
    if (oauth2.tokenEndpoint() == null) {
      warnings.add(new JCustosBootstrapWarning(Severity.ERROR, "oauth2/missing-token-endpoint",
          ".oauth2(...) has no .tokenEndpoint(...).",
          "Add .tokenEndpoint(URI.create(\"https://idp.example/token\"))."));
      return;
    }
    if (oauth2.redirectUri() != null && !isHttpsOrLoopback(oauth2.redirectUri())) {
      warnings.add(new JCustosBootstrapWarning(Severity.ERROR, "oauth2/redirect-uri-not-https",
          ".redirectUri(" + oauth2.redirectUri() + ") is neither https nor http://localhost*.",
          "Use an https redirect URI (or http://localhost... for local development)."));
      return;
    }
    if (oauth2.scopes().isEmpty()) {
      warnings.add(new JCustosBootstrapWarning(Severity.INFO, "oauth2/scope-empty",
          ".oauth2(...) requested no scopes.",
          "Add .scope(\"openid\", \"profile\") if the IdP expects scopes."));
    }

    // Publish a non-secret snapshot for OAuth2DiagnosticContributor (Konzept §13.3).
    boolean publicClient = oauth2.clientAuthentication() == null
        || oauth2.clientAuthentication()
            instanceof eu.jsentinel.jcustos.oauth2.api.ClientAuthentication.NoneAuthentication;
    boolean introspectionCacheDisabled = oauth2.introspectionCacheTtl() != null
        && oauth2.introspectionCacheTtl().isZero();
    eu.jsentinel.jcustos.dx.diagnostics.OAuth2DiagnosticState.publish(
        new eu.jsentinel.jcustos.dx.diagnostics.OAuth2DiagnosticState.Snapshot(
            publicClient, oauth2.pkceRequired(),
            oauth2.introspectionEndpoint() != null, introspectionCacheDisabled));

    // JS-SEC-056 (CWE-1188): a public client with PKCE disabled is exposed to authorization-code
    // interception (RFC 7636). Every other security misconfig in this method is an ERROR that STRICT
    // turns into a boot failure; PKCE-off was only surfaced via the separately-called
    // JCustosDiagnostics.inspect(), so STRICT could boot green on a deliberate opt-out of a secure
    // default. Gate it the same mode-dependent way (ERROR in STRICT/PRODUCTION, INFO in local dev).
    if (publicClient && !oauth2.pkceRequired()) {
      Severity sev = switch (state.mode()) {
        case STRICT, PRODUCTION -> Severity.ERROR;
        default -> Severity.INFO;
      };
      warnings.add(new JCustosBootstrapWarning(sev, "oauth2/public-client-without-pkce",
          "OAuth2 public client (no client authentication) has PKCE disabled.",
          "Enable PKCE with .pkceRequired(true) — a public client without PKCE is exposed to "
              + "authorization-code interception (RFC 7636)."));
    }

    services.add(new RegisteredJCustosService(
        OAuth2State.class, OAuth2State.class, "bootstrap-oauth2", false));
  }

  private static boolean isHttpsOrLoopback(java.net.URI uri) {
    if ("https".equalsIgnoreCase(uri.getScheme())) {
      return true;
    }
    String host = uri.getHost();
    return "http".equalsIgnoreCase(uri.getScheme())
        && host != null
        && ("localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "[::1]".equals(host));
  }

  /**
   * V00.78 — validate the {@link OidcState} recorded by {@code .oidc(...)} and emit
   * the Konzept §11.4 codes. The DX layer does not construct the OIDC clients (that
   * is adapter-side in {@code jCustos-identity-oidc-*}); it only enforces that a
   * usable RP configuration was supplied. STRICT raises for {@code oidc/missing-issuer},
   * {@code oidc/missing-client-id}, {@code oidc/scope-without-openid},
   * {@code oidc/redirect-uri-not-https} and
   * {@code oidc/logout-without-post-logout-redirect-uri}.
   */
  protected final void applyOidcConfiguration(
      List<RegisteredJCustosService> services,
      List<JCustosBootstrapWarning> warnings) {
    if (!state.oidcConfigured()) {
      return;
    }
    OidcState oidc = state.oidcState();
    if (!oidc.hasAnySelection()) {
      // empty .oidc(o -> {}) — silent on purpose
      return;
    }

    if (oidc.issuer() == null || oidc.issuer().isBlank()) {
      warnings.add(new JCustosBootstrapWarning(Severity.ERROR, "oidc/missing-issuer",
          ".oidc(...) was configured without an .issuer(...).",
          "Add .oidc(o -> o.issuer(\"https://idp.example/realm\") ...)."));
      return;
    }
    if (oidc.clientId() == null || oidc.clientId().isBlank()) {
      warnings.add(new JCustosBootstrapWarning(Severity.ERROR, "oidc/missing-client-id",
          ".oidc(...) has no .clientId(...).",
          "Add .clientId(\"my-app\")."));
      return;
    }
    if (!oidc.scopes().contains("openid")) {
      warnings.add(new JCustosBootstrapWarning(Severity.ERROR, "oidc/scope-without-openid",
          ".oidc(...) scope must include \"openid\" (it is an OIDC spec requirement).",
          "Add .scope(\"openid\", ...)."));
      return;
    }
    if (oidc.redirectUri() != null && !isHttpsOrLoopback(oidc.redirectUri())) {
      warnings.add(new JCustosBootstrapWarning(Severity.ERROR, "oidc/redirect-uri-not-https",
          ".redirectUri(" + oidc.redirectUri() + ") is neither https nor http://localhost*.",
          "Use an https redirect URI (or http://localhost... for local development)."));
      return;
    }
    if (oidc.logoutEnabled() && oidc.postLogoutRedirectUri() == null) {
      warnings.add(new JCustosBootstrapWarning(Severity.ERROR,
          "oidc/logout-without-post-logout-redirect-uri",
          ".logoutEnabled(true) needs a .postLogoutRedirectUri(...).",
          "Add .postLogoutRedirectUri(URI.create(\"https://app.example/\"))."));
      return;
    }

    // Publish a non-secret snapshot for OidcDiagnosticContributor.
    eu.jsentinel.jcustos.dx.diagnostics.OidcDiagnosticState.publish(
        new eu.jsentinel.jcustos.dx.diagnostics.OidcDiagnosticState.Snapshot(
            oidc.requireNonce(), oidc.userInfoEnabled(), oidc.logoutEnabled(),
            !oidc.acrValues().isEmpty()));

    // JS-SEC-056 (CWE-1188): disabling the OIDC nonce removes the code-flow replay / login-CSRF
    // defence. Like the PKCE gate above, STRICT/PRODUCTION must hard-fail this deliberate opt-out of
    // a secure default rather than only surfacing it via JCustosDiagnostics.inspect().
    if (!oidc.requireNonce()) {
      Severity sev = switch (state.mode()) {
        case STRICT, PRODUCTION -> Severity.ERROR;
        default -> Severity.INFO;
      };
      warnings.add(new JCustosBootstrapWarning(sev, "oidc/nonce-disabled",
          "OIDC nonce is disabled (.requireNonce(false)).",
          "Keep the nonce enabled — it binds the id_token to this login and defends the code flow "
              + "against id_token replay / login-CSRF."));
    }

    services.add(new RegisteredJCustosService(
        OidcState.class, OidcState.class, "bootstrap-oidc", false));
  }

  /**
   * Consumes the {@link AuditState} accumulated by {@code .audit(...)}
   * calls, applies the validation rules from Konzept §6.4, builds the
   * resulting {@link JCustosAuditService} (Konzept §6.2), registers
   * it via {@link JCustosServiceResolver#setJCustosAuditService(JCustosAuditService)}
   * and adds a {@link RegisteredJCustosService} entry plus any
   * required warnings.
   *
   * <p>Called by each adapter's {@code install()} immediately after
   * authn/authz wiring so the audit service is in place before any
   * other dependent setup.
   */
  /**
   * JS-SEC-085 (CWE-1188): publishes {@code .denyByDefault(...)} to the resolver and
   * reports allow-by-omission. No builder offered the switch before, yet the resolver's
   * Javadoc asked production applications to turn it on at bootstrap; with the flag off
   * the adapters' cross-checks returned without a finding - a {@code .mode(STRICT)}
   * application booted green although every unannotated handler was public.
   */
  protected final void applyDenyByDefaultConfiguration(List<RegisteredJCustosService> services,
                                                       List<JCustosBootstrapWarning> warnings) {
    Boolean configured = state.denyByDefault();
    if (configured != null) {
      JCustosServiceResolver.setDenyByDefault(configured);
      services.add(new RegisteredJCustosService(
          JCustosServiceResolver.class, Boolean.class,
          "bootstrap-deny-by-default=" + configured, false));
    }
    if (JCustosServiceResolver.isDenyByDefault()) {
      return;
    }
    Severity severity = switch (state.mode()) {
      case STRICT -> Severity.ERROR;
      case PRODUCTION -> Severity.WARNING;
      default -> null;
    };
    if (severity != null) {
      warnings.add(new JCustosBootstrapWarning(
          severity,
          "authorization/allow-by-omission",
          "Deny-by-default is off: an element without a security annotation is served to everyone.",
          "Call .denyByDefault(true) and mark public entry points with @PublicRoute."));
    }
  }

  protected final void applyAuditConfiguration(List<RegisteredJCustosService> services,
                                               List<JCustosBootstrapWarning> warnings) {
    if (!state.auditConfigured()) {
      // JS-SEC-080 (CWE-778): no .audit(...) and nothing registered elsewhere means the
      // application runs without an audit trail. Say so - as an error in STRICT.
      if (JCustosServiceResolver.findJCustosAuditService().isEmpty()) {
        Severity severity = state.mode() == JCustosBootstrapMode.STRICT ? Severity.ERROR : Severity.WARNING;
        warnings.add(new JCustosBootstrapWarning(
            severity,
            "audit/noop-fallback",
            "No JCustosAuditService is configured; security events are discarded.",
            "Call .audit(a -> a.logging()) (or .ringBuffer(n), .storeBacked(...)) or register a "
                + "JCustosAuditService via META-INF/services."));
      }
      return;
    }
    AuditState audit = state.auditState();

    // empty .audit(a -> {})
    if (!audit.hasAnySelection()) {
      warnings.add(new JCustosBootstrapWarning(
          Severity.ERROR,
          "audit/missing-service",
          ".audit(...) was called without a selection method.",
          "Choose one of .securityAuditService(...), .storeBacked(...), .logging(), .ringBuffer(n)."));
      return;
    }

    boolean directWithComposition = audit.directService() != null
        && audit.hasCompositionInputs();
    if (directWithComposition) {
      warnings.add(new JCustosBootstrapWarning(
          Severity.ERROR,
          "audit/conflicting-direct-service",
          ".securityAuditService(...) was combined with another audit selection method.",
          "Either pass a pre-built service via .securityAuditService(...), or compose via .storeBacked(...) / .logging() / .ringBuffer(...). Not both."));
      // do not register anything when configuration is ambiguous
      return;
    }

    if (audit.storeBackedRequested() && audit.storeBackedStore() == null) {
      warnings.add(new JCustosBootstrapWarning(
          Severity.ERROR,
          "audit/store-backed-without-store",
          ".storeBacked(null) is not a valid audit configuration.",
          "Pass a non-null AuditEventStore to .storeBacked(...)."));
      return;
    }

    if (audit.ringBufferEnabled() && audit.ringBufferCapacityProvided()
        && audit.ringBufferCapacity() <= 0) {
      warnings.add(new JCustosBootstrapWarning(
          Severity.ERROR,
          "audit/invalid-ring-buffer-capacity",
          ".ringBuffer(" + audit.ringBufferCapacity() + ") — capacity must be > 0.",
          "Pass a positive int (RingBufferAuditSink.DEFAULT_CAPACITY = 256)."));
      return;
    }

    JCustosAuditService finalService;
    String source;
    if (audit.directService() != null) {
      finalService = audit.directService();
      source = "bootstrap-explicit";
    } else {
      finalService = buildComposedAuditService(audit);
      source = "bootstrap-composed";
    }

    JCustosServiceResolver.setJCustosAuditService(finalService);
    services.add(new RegisteredJCustosService(
        JCustosAuditService.class, finalService.getClass(), source, false));

    if (audit.credentialEventsConfigured()) {
      services.add(new RegisteredJCustosService(
          CredentialEventsFlag.class,
          audit.credentialEventsEnabled()
              ? CredentialEventsFlag.Enabled.class
              : CredentialEventsFlag.Disabled.class,
          "bootstrap-recorded", false));
    }
  }

  private static JCustosAuditService buildComposedAuditService(AuditState audit) {
    boolean store = audit.storeBackedRequested();
    boolean ring = audit.ringBufferEnabled();
    boolean logging = audit.loggingEnabled();

    JCustosAuditService storeService = store
        ? new StoreBackedJCustosAuditService(audit.storeBackedStore())
        : null;
    RingBufferAuditSink ringSink = ring
        ? new RingBufferAuditSink(audit.ringBufferCapacity())
        : null;
    LoggingAuditSink loggingSink = logging ? new LoggingAuditSink() : null;

    // store-only
    if (store && !ring && !logging) {
      return storeService;
    }

    // sinks-only — core CompositeAuditService requires a ring buffer
    // in slot 1; if no ring buffer was requested but logging was,
    // create a default ring buffer so the core composite is satisfied.
    if (!store) {
      if (ringSink == null) {
        ringSink = new RingBufferAuditSink();
      }
      AuditSink[] extras = loggingSink == null ? new AuditSink[0] : new AuditSink[]{loggingSink};
      return new eu.jsentinel.jcustos.audit.CompositeAuditService(ringSink, extras);
    }

    // mixed: store-backed + at least one sink → tee them
    List<AuditSink> sinks = new ArrayList<>();
    if (ringSink != null) sinks.add(ringSink);
    if (loggingSink != null) sinks.add(loggingSink);
    JCustosAuditService sinksComposite;
    if (sinks.isEmpty()) {
      // unreachable here (store-only path returned above) but defensive
      return storeService;
    } else if (sinks.size() == 1 && sinks.get(0) instanceof RingBufferAuditSink rbs) {
      sinksComposite = new eu.jsentinel.jcustos.audit.CompositeAuditService(rbs);
    } else if (ringSink != null) {
      AuditSink[] extras = loggingSink != null ? new AuditSink[]{loggingSink} : new AuditSink[0];
      sinksComposite = new eu.jsentinel.jcustos.audit.CompositeAuditService(ringSink, extras);
    } else {
      // logging-only sinks with store-backed → need a synthetic ring buffer
      sinksComposite = new eu.jsentinel.jcustos.audit.CompositeAuditService(
          new RingBufferAuditSink(), loggingSink);
    }
    return new TeeingJCustosAuditService(storeService, sinksComposite);
  }

  /**
   * Identifies the kind of adapter calling
   * {@link #applySessionConfiguration} so adapter-specific INFO codes
   * (Konzept §4.1, §13.2) can be emitted from the shared helper.
   */
  protected enum AdapterKind {
    VAADIN, REST, STANDALONE
  }

  /**
   * Consumes the {@link SessionState} accumulated by
   * {@code .sessions(...)} calls and applies it per Konzept §7. The
   * {@code adapter} parameter selects the adapter-specific
   * informational codes:
   * <ul>
   *   <li>{@link AdapterKind#STANDALONE} — any selection produces
   *       {@code standalone/sessions-not-applicable} (INFO) and the
   *       resolver is not touched.</li>
   *   <li>{@link AdapterKind#REST} — every selection except
   *       {@code storeBacked} is consumed; {@code storeBacked}
   *       produces {@code rest/session-store-unused} (INFO).</li>
   *   <li>{@link AdapterKind#VAADIN} — full consumption.</li>
   * </ul>
   */
  protected final void applySessionConfiguration(AdapterKind adapter,
                                                 List<RegisteredJCustosService> services,
                                                 List<JCustosBootstrapWarning> warnings) {
    if (!state.sessionsConfigured()) {
      return;
    }
    SessionState session = state.sessionState();
    if (!session.hasAnySelection()) {
      // empty .sessions(s -> {}) — silent on purpose; no diagnostic noise
      return;
    }

    if (adapter == AdapterKind.STANDALONE) {
      warnings.add(new JCustosBootstrapWarning(
          Severity.INFO,
          "standalone/sessions-not-applicable",
          ".sessions(...) was configured on StandaloneSecurity.bootstrap(); the CLI adapter has no session model.",
          "Drop the .sessions(...) call or use Vaadin / REST adapters."));
      return;
    }

    // Validate timeout/lifetime up front
    if (session.timeoutConfigured() && !isValidDuration(session.idleTimeout())) {
      warnings.add(new JCustosBootstrapWarning(
          Severity.ERROR,
          "sessions/invalid-timeout",
          ".timeout(" + session.idleTimeout() + ") — must be a positive, finite Duration.",
          "Pass Duration.ofMinutes(n) with n > 0."));
      return;
    }
    if (session.absoluteLifetimeConfigured() && !isValidDuration(session.absoluteLifetime())) {
      warnings.add(new JCustosBootstrapWarning(
          Severity.ERROR,
          "sessions/invalid-timeout",
          ".absoluteLifetime(" + session.absoluteLifetime() + ") — must be a positive, finite Duration.",
          "Pass Duration.ofHours(n) with n > 0."));
      return;
    }

    // .timeout(...) without .storeBacked(...) AND without .policy(...) is invalid
    boolean timeoutWithoutHome = (session.timeoutConfigured() || session.absoluteLifetimeConfigured())
        && session.sessionStore() == null
        && session.policy() == null;
    if (timeoutWithoutHome) {
      warnings.add(new JCustosBootstrapWarning(
          Severity.ERROR,
          "sessions/missing-store",
          ".timeout(...) / .absoluteLifetime(...) were configured without a SessionStore or SessionPolicy.",
          "Pair the timeout with .storeBacked(...) or .policy(...)."));
      return;
    }

    // BL06 (V00.81, CWE-613 / JS-SEC-035): store-backed sessions WITHOUT any
    // lifetime enforcement are a silent no-op — sessions never expire, even in
    // PRODUCTION/STRICT. 00.79.40 only shipped a log WARN; gate it the
    // JS-SEC-056 mode-dependent way so STRICT fails the boot and PRODUCTION
    // surfaces an ERROR finding, while local dev stays at INFO.
    boolean storeWithoutLifetime = session.sessionStore() != null
        && session.policy() == null
        && !session.timeoutConfigured()
        && !session.absoluteLifetimeConfigured();
    if (storeWithoutLifetime) {
      // JS-SEC-065 (CWE-1188): since 00.84.00 the resolver default is an enforcing
      // TimeoutSessionPolicy (30 min idle / 12 h absolute), so an unconfigured lifetime is no
      // longer a silent no-op and no longer gates STRICT or PRODUCTION; the finding stays as
      // INFO so the implicit choice is visible in the bootstrap report.
      warnings.add(new JCustosBootstrapWarning(Severity.INFO, "sessions/no-timeout-policy",
          ".storeBacked(...) sessions are configured without .timeout(...) / "
              + ".absoluteLifetime(...) / .policy(...) — the secure default applies "
              + "(30 min idle, 12 h absolute, rotation after login).",
          "Configure .timeout(Duration) and .absoluteLifetime(Duration) to choose your own "
              + "limits, or supply a custom .policy(...)."));
    }

    // Policy: custom .policy(...) wins; otherwise construct TimeoutSessionPolicy
    SessionPolicy<?> effectivePolicy = session.policy();
    if (effectivePolicy == null
        && (session.timeoutConfigured() || session.absoluteLifetimeConfigured())) {
      effectivePolicy = buildTimeoutSessionPolicy(session);
    }
    if (effectivePolicy != null) {
      registerSessionPolicy(effectivePolicy);
      services.add(new RegisteredJCustosService(
          SessionPolicy.class, effectivePolicy.getClass(),
          session.policy() != null ? "bootstrap-explicit" : "bootstrap-composed",
          false));
    }

    // JCustosVersion + SubjectIdResolver
    if (session.securityVersionStore() != null) {
      JCustosServiceResolver.setJCustosVersionStore(session.securityVersionStore());
      services.add(new RegisteredJCustosService(
          JCustosVersionStore.class, session.securityVersionStore().getClass(),
          "bootstrap-explicit", false));
      if (session.subjectIdResolver() == null
          && JCustosServiceResolver.findSubjectIdResolver().isEmpty()) {
        warnings.add(new JCustosBootstrapWarning(
            Severity.ERROR,
            "security-version-without-subject-id-resolver",
            ".securityVersion(...) was configured without a SubjectIdResolver; drift detection cannot resolve subjects.",
            "Call .subjectIdResolver(...) or register one via @JCustosAutoService."));
      }
    }
    if (session.subjectIdResolver() != null) {
      registerSubjectIdResolver(session.subjectIdResolver());
      services.add(new RegisteredJCustosService(
          SubjectIdResolver.class, session.subjectIdResolver().getClass(),
          "bootstrap-explicit", false));
    }

    // SessionStore — adapter-specific consumption
    if (session.sessionStore() != null) {
      if (adapter == AdapterKind.REST) {
        warnings.add(new JCustosBootstrapWarning(
            Severity.INFO,
            "rest/session-store-unused",
            ".storeBacked(...) was configured on RestSecurity.bootstrap(); REST consumes Policy/Version/Resolver but not SessionStore.",
            "Drop the .storeBacked(...) call or move it to the Vaadin adapter."));
      } else {
        services.add(new RegisteredJCustosService(
            SessionStore.class, session.sessionStore().getClass(),
            "bootstrap-explicit", false));
      }
    }
  }

  private static boolean isValidDuration(Duration d) {
    return d != null && !d.isNegative() && !d.isZero();
  }

  private static SessionPolicy<?> buildTimeoutSessionPolicy(SessionState session) {
    TimeoutSessionPolicy.Config defaults = TimeoutSessionPolicy.Config.defaults();
    Duration idle = session.idleTimeout() != null ? session.idleTimeout() : defaults.idleTimeout();
    Duration absolute = session.absoluteLifetime() != null
        ? session.absoluteLifetime() : defaults.absoluteLifetime();
    // JS-SEC-065: the login route follows the resolver, not the hardcoded default.
    TimeoutSessionPolicy.Config config = new TimeoutSessionPolicy.Config(
        idle, absolute, defaults.rotateSessionAfterLogin(),
        "/" + JCustosServiceResolver.loginRouteName());
    JCustosAuditService audit = JCustosServiceResolver.findJCustosAuditService()
        .orElseGet(NoopJCustosAuditService::new);
    return new TimeoutSessionPolicy<>(config, Clock.systemUTC(), audit);
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private static void registerSessionPolicy(SessionPolicy<?> policy) {
    JCustosServiceResolver.setSessionPolicy((SessionPolicy) policy);
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private static void registerSubjectIdResolver(SubjectIdResolver<?> resolver) {
    JCustosServiceResolver.setSubjectIdResolver((SubjectIdResolver) resolver);
  }

  /**
   * Synthetic marker types used as the {@code impl} class of the
   * {@link RegisteredJCustosService} entry that surfaces the
   * {@code .credentialEvents(boolean)} flag in {@link JCustosRuntime}.
   * V00.73 reserves them; future releases may move them to a typed
   * runtime surface.
   */
  static final class CredentialEventsFlag {
    static final class Enabled { }
    static final class Disabled { }
    private CredentialEventsFlag() { }
  }

  /**
   * Helper: {@code true} iff the warning list contains any
   * {@link Severity#ERROR} entry. Provided here so adapter
   * subclasses don't each re-implement the same predicate.
   */
  protected static boolean warningsContainError(List<JCustosBootstrapWarning> warnings) {
    return warnings.stream().anyMatch(w -> w.severity() == Severity.ERROR);
  }

  // ---- sub-builder recorders ---------------------------------------------

  /**
   * Consumes the {@link RoleState} accumulated by
   * {@code .roles(...)} calls and applies it per Konzept §9.
   * Currently a single concern: {@code RoleHierarchy} wiring via
   * {@link JCustosServiceResolver#setRoleHierarchy(RoleHierarchy)}.
   * Missing hierarchy is INFO ({@code roles/missing-hierarchy}).
   * {@code RoleHierarchy.Builder.build()} surfaces cycle errors as
   * {@code IllegalStateException}; the helper translates that into
   * {@code roles/hierarchy-cycle} (STRICT throws).
   */
  protected final void applyRoleConfiguration(List<RegisteredJCustosService> services,
                                              List<JCustosBootstrapWarning> warnings) {
    if (!state.rolesConfigured()) {
      return;
    }
    RoleState roles = state.roleState();
    if (roles.hierarchy() == null) {
      warnings.add(new JCustosBootstrapWarning(
          Severity.INFO,
          "roles/missing-hierarchy",
          ".roles(...) was called without .hierarchy(...).",
          "Configure a RoleHierarchy or drop the .roles(...) call."));
      return;
    }
    try {
      JCustosServiceResolver.setRoleHierarchy(roles.hierarchy());
      services.add(new RegisteredJCustosService(
          RoleHierarchy.class, roles.hierarchy().getClass(),
          "bootstrap-explicit", false));
    } catch (IllegalStateException cycle) {
      warnings.add(new JCustosBootstrapWarning(
          Severity.ERROR,
          "roles/hierarchy-cycle",
          "Role hierarchy is invalid: " + cycle.getMessage(),
          "Inspect the RoleHierarchy.Builder includes() chain and remove the cycle."));
    }
  }

  /**
   * Consumes the {@link CredentialState} accumulated by
   * {@code .credentials(...)} calls and applies it per Konzept §10.
   * The legacy {@code PasswordHasher} path is wired through
   * {@link JCustosServiceResolver#setPasswordHashingService(PasswordHasher)};
   * the V00.71 {@link PasswordHashingService} — from {@code .hashing(...)},
   * {@code .modern()} or {@code .pbkdf2Defaults()} — is wired through
   * {@link JCustosServiceResolver#setCredentialHashingService(PasswordHashingService)}
   * since 00.84.00 (JS-SEC-073, CWE-684) and is never stuffed into the
   * legacy setter. {@code .pepper(...)}, {@code .credentialStore(...)},
   * {@code .passwordChange(...)} and {@code .passwordReset(...)} have no
   * resolver and no consumer inside the bootstrap: they are recorded for the
   * application's own wiring and reported as
   * {@code dx/credential-<entry>-recorded-not-wired} (WARNING; STRICT → ERROR),
   * exactly like {@code .rateLimit(...)} since JS-SEC-055 — never as an
   * active service.
   */
  protected final void applyCredentialConfiguration(List<RegisteredJCustosService> services,
                                                    List<JCustosBootstrapWarning> warnings) {
    if (!state.credentialsConfigured()) {
      return;
    }
    CredentialState cred = state.credentialState();

    // .modern() probe: load BouncyCastleHashingServices.modern() reflectively
    if (cred.modernRequested()) {
      Object loaded = loadModernHashingService();
      if (loaded == null) {
        warnings.add(new JCustosBootstrapWarning(
            Severity.ERROR,
            "credentials/modern-without-bc",
            ".modern() requires the jCustos-crypto-bc module on the classpath.",
            "Add the dependency:\n"
                + "  <dependency>\n"
                + "    <groupId>eu.jsentinel.jcustos</groupId>\n"
                + "    <artifactId>jCustos-crypto-bc</artifactId>\n"
                + "    <version>${jcustos.version}</version>\n"
                + "  </dependency>"));
        // do not register anything further when the explicit modern
        // request can't be honored
        return;
      }
      if (cred.hashingService() == null) {
        cred.hashingService((PasswordHashingService) loaded);
      }
    }

    // .pbkdf2Defaults(): set BOTH worlds; never overwrite an explicit choice
    if (cred.pbkdf2DefaultsRequested()) {
      if (cred.passwordHasher() == null) {
        cred.passwordHasher(new Pbkdf2PasswordHasher());
      }
      if (cred.hashingService() == null) {
        cred.hashingService(PasswordHashingServices.defaults());
      }
    }

    // legacy hasher path
    if (cred.passwordHasher() != null) {
      JCustosServiceResolver.setPasswordHashingService(cred.passwordHasher());
      services.add(new RegisteredJCustosService(
          PasswordHasher.class, cred.passwordHasher().getClass(),
          "bootstrap-explicit", false));
    }

    // V00.71 pipeline. JS-SEC-073 (CWE-684): the hashing service IS wired —
    // through its own resolver slot, never the legacy PasswordHasher setter —
    // so .modern() really activates Argon2id for everything that resolves
    // JCustosServiceResolver.credentialHashingService().
    if (cred.hashingService() != null) {
      JCustosServiceResolver.setCredentialHashingService(cred.hashingService());
      services.add(new RegisteredJCustosService(
          PasswordHashingService.class, cred.hashingService().getClass(),
          "bootstrap-explicit", false));
    }
    // The remaining pipeline entries have no resolver and no consumer inside
    // the bootstrap. Before 00.84.00 they appeared in services() as
    // "bootstrap-explicit", indistinguishable from the wired entries above and
    // falsely reading as "configured and active" — the JS-SEC-055 pattern.
    // Report them as recorded-not-wired instead: WARNING, and in STRICT a hard
    // boot failure, so nobody ships an inert pepper or credential store.
    Severity credentialRecordedNotWired = switch (state.mode()) {
      case STRICT -> Severity.ERROR;
      default -> Severity.WARNING;
    };
    if (cred.pepperService() != null) {
      warnings.add(recordedNotWired(credentialRecordedNotWired, "pepper", ".pepper(...)",
          cred.pepperService().getClass(),
          "Compose it into the pipeline instead: .hashing(PasswordHashingServices.defaults(policy, limiter, pepper))."));
    }
    if (cred.credentialStore() != null) {
      warnings.add(recordedNotWired(credentialRecordedNotWired, "store", ".credentialStore(...)",
          cred.credentialStore().getClass(),
          "Hand the store to your application's credential wiring; drop the call if nothing reads it."));
    }
    if (cred.passwordChangeService() != null) {
      warnings.add(recordedNotWired(credentialRecordedNotWired, "change", ".passwordChange(...)",
          cred.passwordChangeService().getClass(),
          "Expose the service through your application's wiring; drop the call if nothing reads it."));
    }
    if (cred.passwordResetService() != null) {
      warnings.add(recordedNotWired(credentialRecordedNotWired, "reset", ".passwordReset(...)",
          cred.passwordResetService().getClass(),
          "Expose the service through your application's wiring; drop the call if nothing reads it."));
    }

    // STRICT-ERROR validation: change/reset need a hashing service
    boolean needsHashing = cred.passwordChangeService() != null
        || cred.passwordResetService() != null;
    if (needsHashing && cred.hashingService() == null) {
      warnings.add(new JCustosBootstrapWarning(
          Severity.ERROR,
          "credentials/missing-hashing",
          "PasswordChangeService / PasswordResetService configured without .hashing(...).",
          "Call .hashing(...) or .pbkdf2Defaults() before .passwordChange(...) / .passwordReset(...)."));
    }
  }

  /**
   * Reflective probe for {@code BouncyCastleHashingServices.modern()}.
   * Returns the loaded {@link PasswordHashingService} or {@code null}
   * when {@code security-crypto-bc} is not on the classpath.
   */
  private static JCustosBootstrapWarning recordedNotWired(Severity severity, String entry,
                                                        String call, Class<?> impl, String remedy) {
    return new JCustosBootstrapWarning(
        severity,
        "dx/credential-" + entry + "-recorded-not-wired",
        call + " recorded " + impl.getName() + " but NO shipped jCustos module consumes it from the "
            + "bootstrap; the entry is inert unless your application wires it itself (JS-SEC-073).",
        remedy);
  }

  private static Object loadModernHashingService() {
    try {
      Class<?> bc = Class.forName(
          "eu.jsentinel.jcustos.credential.password.bouncycastle.BouncyCastleHashingServices");
      return bc.getMethod("modern").invoke(null);
    } catch (ClassNotFoundException | NoSuchMethodException
             | IllegalAccessException | java.lang.reflect.InvocationTargetException e) {
      return null;
    }
  }

  /**
   * Consumes the {@link PolicyState} accumulated by
   * {@code .policies(...)} calls and applies it per Konzept §8.
   *
   * <p>Wiring rules:
   * <ul>
   *   <li>{@code .registry(external)} → {@link JCustosServiceResolver#setPolicyRegistry(PolicyRegistry)}.</li>
   *   <li>{@code .resourceRegistry(external)} → {@link JCustosServiceResolver#setResourceResolverRegistry(ResourceResolverRegistry)}.</li>
   *   <li>{@code .register(policy)} → active registry's
   *       {@link PolicyRegistry#register(Policy)}.</li>
   *   <li>{@code .resourceResolver(r)} → active registry's
   *       {@link ResourceResolverRegistry#register(ResourceResolver)}.</li>
   * </ul>
   *
   * <p>Empty {@code .policies(p -> {})} is silently allowed (Konzept §13
   * marks the diagnostic as optional INFO; V00.73 drops it to avoid
   * noise).
   */
  protected final void applyPolicyConfiguration(List<RegisteredJCustosService> services,
                                                List<JCustosBootstrapWarning> warnings) {
    if (!state.policiesConfigured()) {
      return;
    }
    PolicyState policies = state.policyState();

    if (policies.registry() != null) {
      JCustosServiceResolver.setPolicyRegistry(policies.registry());
      services.add(new RegisteredJCustosService(
          PolicyRegistry.class, policies.registry().getClass(),
          "bootstrap-explicit", false));
    }
    if (policies.resourceRegistry() != null) {
      JCustosServiceResolver.setResourceResolverRegistry(policies.resourceRegistry());
      services.add(new RegisteredJCustosService(
          ResourceResolverRegistry.class, policies.resourceRegistry().getClass(),
          "bootstrap-explicit", false));
    }

    PolicyRegistry activePolicyRegistry = policies.registry() != null
        ? policies.registry()
        : JCustosServiceResolver.policyRegistry();
    ResourceResolverRegistry activeResourceRegistry = policies.resourceRegistry() != null
        ? policies.resourceRegistry()
        : JCustosServiceResolver.resourceResolverRegistry();

    for (Policy policy : policies.policies()) {
      activePolicyRegistry.register(policy);
    }
    for (ResourceResolver<?> resolver : policies.resolvers()) {
      activeResourceRegistry.register(resolver);
    }
  }

  /**
   * V00.74: applies the direct-set services configured via the new
   * top-level methods on {@link CommonJCustosBootstrap}.
   *
   * <p>Two categories:
   * <ul>
   *   <li><strong>Resolver-wired</strong> — {@link LogoutService} via
   *       {@link JCustosServiceResolver#setLogoutService},
   *       {@link LoginAttemptPolicy} via
   *       {@link JCustosServiceResolver#setLoginAttemptPolicy}.</li>
   *   <li><strong>DX-state only</strong> — {@link RateLimitPolicy},
   *       {@link ApiKeyAuthenticationService}, {@link TokenService}.
   *       These types have no global resolver setter; the bootstrap does
   *       not touch any global singleton for them. They are recorded in
   *       {@link BootstrapState} for adapter-DX modules to consume, and
   *       (R029) surfaced as an {@code INFO} warning
   *       ({@code dx/<feature>-recorded-not-wired}) rather than a
   *       {@link JCustosRuntime#services()} entry — a recorded-but-unwired
   *       feature must not read as an actively-wired service.</li>
   * </ul>
   */
  @SuppressWarnings({"unchecked", "rawtypes"})
  protected final void applyDirectServiceConfiguration(
      List<RegisteredJCustosService> services,
      List<JCustosBootstrapWarning> warnings) {
    if (state.logoutService() != null) {
      LogoutService raw = state.logoutService();
      JCustosServiceResolver.setLogoutService(raw);
      services.add(new RegisteredJCustosService(
          LogoutService.class, raw.getClass(), "bootstrap-explicit", false));
    }
    if (state.loginAttemptPolicy() != null) {
      JCustosServiceResolver.setLoginAttemptPolicy(state.loginAttemptPolicy());
      services.add(new RegisteredJCustosService(
          LoginAttemptPolicy.class, state.loginAttemptPolicy().getClass(),
          "bootstrap-explicit", false));
    }
    if (state.clientAddressResolver() != null) {
      // JS-SEC-061 (CWE-348): the resolver decides which address keys throttles and audit lines.
      JCustosServiceResolver.setClientAddressResolver(state.clientAddressResolver());
      services.add(new RegisteredJCustosService(
          ClientAddressResolver.class, state.clientAddressResolver().getClass(),
          "bootstrap-explicit", false));
    }
    // R029: rateLimit / apiKeys / refreshTokens have no global resolver setter,
    // so the bootstrap cannot wire them. Previously they were added to
    // services() with source "bootstrap-explicit" — indistinguishable from the
    // genuinely resolver-wired entries above, falsely reading as "configured
    // and active". They are recorded in BootstrapState for adapter-DX modules
    // to consume; surface that honestly as an INFO instead of a fake
    // registration.
    // JS-SEC-055 (CWE-684): .rateLimit(...) / .apiKeys(...) / .refreshTokens(...) are recorded but
    // NOT consumed by any shipped jCustos module — the earlier INFO falsely claimed "adapter-DX
    // modules read it from the bootstrap state", so a developer who opted into rate-limiting could
    // ship an inert control believing it active. State the truth, and raise the severity so it is
    // loud (WARNING) and, in STRICT, a hard boot failure — a developer cannot silently ship an inert
    // hardening control.
    Severity recordedNotWired = switch (state.mode()) {
      case STRICT -> Severity.ERROR;
      default -> Severity.WARNING;
    };
    if (state.rateLimitPolicy() != null) {
      warnings.add(new JCustosBootstrapWarning(
          recordedNotWired,
          "dx/rate-limit-recorded-not-wired",
          "RateLimitPolicy (" + state.rateLimitPolicy().getClass().getName()
              + ") was recorded via .rateLimit(...) but is NOT consumed by any shipped jCustos "
              + "module — no enforcement is wired.",
          "Read BootstrapState / JCustosRuntime and wire enforcement yourself, or drop the "
              + ".rateLimit(...) call so the control is not falsely assumed active."));
    }
    if (state.apiKeyAuthenticationService() != null) {
      warnings.add(new JCustosBootstrapWarning(
          recordedNotWired,
          "dx/api-keys-recorded-not-wired",
          "ApiKeyAuthenticationService ("
              + state.apiKeyAuthenticationService().getClass().getName()
              + ") was recorded via .apiKeys(...) but is NOT consumed by any shipped jCustos "
              + "module — no enforcement is wired.",
          "Read BootstrapState / JCustosRuntime and wire enforcement yourself, or drop the "
              + ".apiKeys(...) call."));
    }
    if (state.tokenService() != null) {
      warnings.add(new JCustosBootstrapWarning(
          recordedNotWired,
          "dx/refresh-tokens-recorded-not-wired",
          "TokenService (" + state.tokenService().getClass().getName()
              + ") was recorded via .refreshTokens(...) but is NOT consumed by any shipped "
              + "jCustos module — no enforcement is wired.",
          "Read BootstrapState / JCustosRuntime and wire enforcement yourself, or drop the "
              + ".refreshTokens(...) call."));
    }
  }

}