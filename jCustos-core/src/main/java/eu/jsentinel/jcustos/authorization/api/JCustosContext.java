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
package eu.jsentinel.jcustos.authorization.api;

import eu.jsentinel.jcustos.action.ActionAuthorizationService;
import eu.jsentinel.jcustos.audit.NoopJCustosAuditService;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.logout.LogoutService;
import eu.jsentinel.jcustos.logout.NoopLogoutService;
import eu.jsentinel.jcustos.logout.SubjectClearingLogoutService;
import eu.jsentinel.jcustos.authentication.PasswordHasher;
import eu.jsentinel.jcustos.authentication.Pbkdf2PasswordHasher;
import eu.jsentinel.jcustos.authorization.api.roles.NoopRoleHierarchy;
import eu.jsentinel.jcustos.authorization.api.roles.RoleHierarchy;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.NoopLoginAttemptPolicy;
import eu.jsentinel.jcustos.credential.propagation.OutboundTokenStrategy;
import eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore;
import eu.jsentinel.jcustos.policy.impl.InMemoryPolicyRegistry;
import eu.jsentinel.jcustos.policy.impl.InMemoryResourceResolverRegistry;
import eu.jsentinel.jcustos.policy.spi.PolicyRegistry;
import eu.jsentinel.jcustos.policy.spi.ResourceResolverRegistry;
import eu.jsentinel.jcustos.session.NoopSessionPolicy;
import eu.jsentinel.jcustos.session.JCustosVersionStore;
import eu.jsentinel.jcustos.session.SessionPolicy;
import eu.jsentinel.jcustos.session.TimeoutSessionPolicy;

import java.util.Optional;
import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Per-instance holder for security-related SPI services.
 * <p>
 * This is the instance-state counterpart to the static
 * {@link JCustosServiceResolver} facade. The facade delegates all of its
 * static accessors to a single process-wide default context
 * ({@link JCustosServiceResolver#current()}); applications and tests that
 * need an isolated, non-global service registry obtain a fresh context via
 * {@link #createIsolated()}.
 * <p>
 * Each service has two access patterns:
 * <ul>
 *   <li><b>Strict</b> ({@code authenticationService()}, etc.) — throws
 *       {@link IllegalStateException} with an actionable message if no
 *       SPI implementation is registered. The result is cached.</li>
 *   <li><b>Optional</b> ({@code findAuthenticationService()}, etc.) —
 *       returns {@link Optional#empty()} if no SPI implementation is
 *       registered. Delegates to the strict method internally, so a
 *       successful lookup is also cached.</li>
 * </ul>
 * <p>
 * Thread-safe: resolved services are cached via {@link AtomicReference} so
 * repeated lookups do not trigger SPI discovery again. Unlike the static
 * {@link JCustosServiceResolver#resetAll()}, the instance
 * {@link #resetAll()} clears only this context's fields and does
 * <strong>not</strong> touch the global {@link SubjectStores} state.
 *
 * @since 00.75.10
 */
@ExperimentalJCustosApi
public final class JCustosContext {

  private final AtomicReference<AuthenticationService<?, ?>> authenticationServiceRef =
      new AtomicReference<>();
  private final AtomicReference<AuthorizationService<?>> authorizationServiceRef =
      new AtomicReference<>();
  private final AtomicReference<JCustosAuditService> auditServiceRef =
      new AtomicReference<>();
  private final AtomicReference<ActionAuthorizationService<?>> actionAuthServiceRef =
      new AtomicReference<>();
  private final AtomicReference<LoginAttemptPolicy> loginAttemptPolicyRef =
      new AtomicReference<>();
  /** JS-SEC-065: the policy {@link #sessionPolicy()} created as its secure default, if any. */
  private volatile SessionPolicy<?> defaultedSessionPolicy;
  private final AtomicReference<SessionPolicy<?>> sessionPolicyRef =
      new AtomicReference<>();
  private final AtomicReference<PasswordHasher> passwordHasherRef =
      new AtomicReference<>();
  private final AtomicReference<LogoutService> logoutServiceRef =
      new AtomicReference<>();
  private final AtomicReference<PolicyRegistry> policyRegistryRef =
      new AtomicReference<>();
  private final AtomicReference<ResourceResolverRegistry> resourceResolverRegistryRef =
      new AtomicReference<>();
  private final AtomicReference<RoleHierarchy> roleHierarchyRef =
      new AtomicReference<>();
  private final AtomicReference<JCustosVersionStore> securityVersionStoreRef =
      new AtomicReference<>();
  private final AtomicReference<SubjectIdResolver<?>> subjectIdResolverRef =
      new AtomicReference<>();
  private final AtomicReference<String> stepUpRouteNameRef =
      new AtomicReference<>();
  private final AtomicReference<String> loginRouteNameRef =
      new AtomicReference<>();
  // JS-SEC-024 (CWE-862): opt-in deny-by-default for un-annotated targets.
  private final AtomicBoolean denyByDefaultRef = new AtomicBoolean(false);
  // V00.74: token-propagation surface. Store cached via SPI; strategies
  // registered explicitly through the .propagation(...) sub-builder.
  private final AtomicReference<TokenCredentialStore> tokenCredentialStoreRef =
      new AtomicReference<>();
  private final java.util.concurrent.ConcurrentMap<String, OutboundTokenStrategy>
      outboundStrategies = new java.util.concurrent.ConcurrentHashMap<>();
  // V00.76: JWT validator surface. Not SPI-discovered — assembled by the
  // JwtValidatorFactory and installed explicitly through the .jwt(...) sub-builder.
  private final AtomicReference<eu.jsentinel.jcustos.jwt.api.JwtValidator>
      jwtValidatorRef = new AtomicReference<>();

  /**
   * Creates a fresh, empty context. Use {@link #createIsolated()} for a
   * named, intention-revealing factory.
   */
  public JCustosContext() {
  }

  /**
   * Creates a fresh, isolated context whose service registry is completely
   * independent of the process-wide default context and of any other
   * isolated context.
   *
   * @return a new empty {@link JCustosContext}
   */
  public static JCustosContext createIsolated() {
    return new JCustosContext();
  }

  // ── AuthenticationService ──────────────────────────────────────

  /**
   * Returns the registered {@link AuthenticationService}.
   *
   * @param <T> the credentials type
   * @param <U> the subject type
   * @return the resolved service (cached after first lookup)
   * @throws IllegalStateException if no implementation is registered
   */
  @SuppressWarnings("unchecked")
  public <T, U> AuthenticationService<T, U> authenticationService() {
    AuthenticationService<?, ?> cached = authenticationServiceRef.get();
    if (cached != null) {
      return (AuthenticationService<T, U>) cached;
    }

    AuthenticationService<T, U> loaded = (AuthenticationService<T, U>) requireSingleService(
        AuthenticationService.class,
        ServiceLoader.load(AuthenticationService.class));

    authenticationServiceRef.compareAndSet(null, loaded);
    return (AuthenticationService<T, U>) authenticationServiceRef.get();
  }

  /**
   * Returns the registered {@link AuthenticationService}, or empty
   * if none is registered.
   *
   * @param <T> the credentials type
   * @param <U> the subject type
   * @return the service, or empty
   */
  @SuppressWarnings("unchecked")
  public <T, U> Optional<AuthenticationService<T, U>> findAuthenticationService() {
    AuthenticationService<?, ?> cached = authenticationServiceRef.get();
    if (cached != null) {
      return Optional.of((AuthenticationService<T, U>) cached);
    }

    Optional<AuthenticationService> loaded = findSingleService(
        AuthenticationService.class,
        ServiceLoader.load(AuthenticationService.class));
    loaded.ifPresent(service -> authenticationServiceRef.compareAndSet(null, service));
    return Optional.ofNullable((AuthenticationService<T, U>) authenticationServiceRef.get());
  }

  /**
   * Overrides the cached {@link AuthenticationService}. Primarily used by
   * tests and by deployments that compose the authentication service from
   * application code rather than via {@link ServiceLoader}. Pass {@code null}
   * to clear the cache and force the next call to consult the SPI again.
   *
   * @param service the service to cache, or {@code null} to clear
   * @param <T>     credentials type
   * @param <U>     subject type
   */
  public <T, U> void setAuthenticationService(AuthenticationService<T, U> service) {
    authenticationServiceRef.set(service);
  }

  // ── AuthorizationService ───────────────────────────────────────

  /**
   * Returns the registered {@link AuthorizationService}.
   *
   * @param <U> the subject type
   * @return the resolved service (cached after first lookup)
   * @throws IllegalStateException if no implementation is registered
   */
  @SuppressWarnings("unchecked")
  public <U> AuthorizationService<U> authorizationService() {
    AuthorizationService<?> cached = authorizationServiceRef.get();
    if (cached != null) {
      return (AuthorizationService<U>) cached;
    }

    AuthorizationService<U> loaded = (AuthorizationService<U>) requireSingleService(
        AuthorizationService.class,
        ServiceLoader.load(AuthorizationService.class));

    authorizationServiceRef.compareAndSet(null, loaded);
    return (AuthorizationService<U>) authorizationServiceRef.get();
  }

  /**
   * Overrides the cached {@link AuthorizationService}. Primarily used by
   * tests and by deployments that compose the authorization service from
   * application code rather than via {@link ServiceLoader}. Pass {@code null}
   * to clear the cache and force the next call to consult the SPI again.
   *
   * @param service the service to cache, or {@code null} to clear
   * @param <U>     subject type
   */
  public <U> void setAuthorizationService(AuthorizationService<U> service) {
    authorizationServiceRef.set(service);
  }

  /**
   * Returns the registered {@link AuthorizationService}, or empty
   * if none is registered.
   *
   * @param <U> the subject type
   * @return the service, or empty
   */
  @SuppressWarnings("unchecked")
  public <U> Optional<AuthorizationService<U>> findAuthorizationService() {
    AuthorizationService<?> cached = authorizationServiceRef.get();
    if (cached != null) {
      return Optional.of((AuthorizationService<U>) cached);
    }

    Optional<AuthorizationService> loaded = findSingleService(
        AuthorizationService.class,
        ServiceLoader.load(AuthorizationService.class));
    loaded.ifPresent(service -> authorizationServiceRef.compareAndSet(null, service));
    return Optional.ofNullable((AuthorizationService<U>) authorizationServiceRef.get());
  }

  // ── JCustosAuditService ───────────────────────────────────────

  /**
   * Returns the registered {@link JCustosAuditService}, or
   * {@link NoopJCustosAuditService#INSTANCE} if no SPI implementation is
   * registered. Unlike {@link #authenticationService()} and
   * {@link #authorizationService()}, this method <strong>never</strong>
   * throws — auditing is optional infrastructure and the framework must
   * not refuse to operate when no sink is configured.
   *
   * @return the resolved audit service, never {@code null}
   */
  public JCustosAuditService securityAuditService() {
    JCustosAuditService cached = auditServiceRef.get();
    if (cached != null) {
      return cached;
    }

    JCustosAuditService loaded = findSingleService(
        JCustosAuditService.class,
        ServiceLoader.load(JCustosAuditService.class))
        .orElse(NoopJCustosAuditService.INSTANCE);

    auditServiceRef.compareAndSet(null, loaded);
    return auditServiceRef.get();
  }

  /**
   * Returns the registered {@link JCustosAuditService}, or empty if
   * the SPI is unconfigured. Use {@link #securityAuditService()} to
   * obtain the noop fallback instead.
   *
   * @return the SPI-registered service, or empty
   */
  public Optional<JCustosAuditService> findJCustosAuditService() {
    JCustosAuditService cached = auditServiceRef.get();
    if (cached != null && cached != NoopJCustosAuditService.INSTANCE) {
      return Optional.of(cached);
    }
    if (cached == NoopJCustosAuditService.INSTANCE) {
      return Optional.empty();
    }

    Optional<JCustosAuditService> loaded = findSingleService(
        JCustosAuditService.class,
        ServiceLoader.load(JCustosAuditService.class));
    loaded.ifPresent(service -> auditServiceRef.compareAndSet(null, service));
    return loaded;
  }

  /**
   * Replaces the cached {@link JCustosAuditService}. Intended for tests
   * and for applications that prefer programmatic wiring over SPI.
   *
   * @param service the audit service, or {@code null} to clear
   */
  public void setJCustosAuditService(JCustosAuditService service) {
    auditServiceRef.set(service);
  }

  // ── ActionAuthorizationService ─────────────────────────────────

  /**
   * Returns the registered {@link ActionAuthorizationService}.
   *
   * @param <U> the subject type
   * @return the resolved service
   * @throws IllegalStateException if no implementation is registered
   *                               or programmatically configured
   */
  @SuppressWarnings("unchecked")
  public <U> ActionAuthorizationService<U> actionAuthorizationService() {
    ActionAuthorizationService<?> cached = actionAuthServiceRef.get();
    if (cached != null) {
      return (ActionAuthorizationService<U>) cached;
    }

    ActionAuthorizationService<U> loaded =
        (ActionAuthorizationService<U>) requireSingleService(
            ActionAuthorizationService.class,
            ServiceLoader.load(ActionAuthorizationService.class));

    actionAuthServiceRef.compareAndSet(null, loaded);
    return (ActionAuthorizationService<U>) actionAuthServiceRef.get();
  }

  /**
   * Returns the registered {@link ActionAuthorizationService}, or empty
   * if none is configured.
   *
   * @param <U> the subject type
   * @return the service, or empty
   */
  @SuppressWarnings("unchecked")
  public <U> Optional<ActionAuthorizationService<U>> findActionAuthorizationService() {
    ActionAuthorizationService<?> cached = actionAuthServiceRef.get();
    if (cached != null) {
      return Optional.of((ActionAuthorizationService<U>) cached);
    }

    Optional<ActionAuthorizationService> loaded = findSingleService(
        ActionAuthorizationService.class,
        ServiceLoader.load(ActionAuthorizationService.class));
    loaded.ifPresent(service -> actionAuthServiceRef.compareAndSet(null, service));
    return Optional.ofNullable((ActionAuthorizationService<U>) actionAuthServiceRef.get());
  }

  /**
   * Replaces the cached {@link ActionAuthorizationService}. Intended for
   * tests and for applications that prefer programmatic wiring over SPI.
   *
   * @param service the action authorization service, or {@code null} to clear
   * @param <U>     subject type
   */
  public <U> void setActionAuthorizationService(ActionAuthorizationService<U> service) {
    actionAuthServiceRef.set(service);
  }

  // ── LoginAttemptPolicy ─────────────────────────────────────────

  /**
   * Returns the registered {@link LoginAttemptPolicy}, or
   * {@link NoopLoginAttemptPolicy#INSTANCE} if no SPI implementation is
   * configured. Like {@link #securityAuditService()}, this method
   * <strong>never</strong> throws — brute-force throttling is optional
   * infrastructure.
   *
   * @return the resolved policy, never {@code null}
   */
  public LoginAttemptPolicy loginAttemptPolicy() {
    LoginAttemptPolicy cached = loginAttemptPolicyRef.get();
    if (cached != null) {
      return cached;
    }

    LoginAttemptPolicy loaded = findSingleService(
        LoginAttemptPolicy.class,
        ServiceLoader.load(LoginAttemptPolicy.class))
        .orElse(NoopLoginAttemptPolicy.INSTANCE);

    loginAttemptPolicyRef.compareAndSet(null, loaded);
    return loginAttemptPolicyRef.get();
  }

  /**
   * Returns the registered {@link LoginAttemptPolicy}, or empty if none
   * is configured. Use {@link #loginAttemptPolicy()} for the noop
   * fallback.
   *
   * @return the SPI-registered policy, or empty
   */
  public Optional<LoginAttemptPolicy> findLoginAttemptPolicy() {
    LoginAttemptPolicy cached = loginAttemptPolicyRef.get();
    if (cached != null && cached != NoopLoginAttemptPolicy.INSTANCE) {
      return Optional.of(cached);
    }
    if (cached == NoopLoginAttemptPolicy.INSTANCE) {
      return Optional.empty();
    }

    Optional<LoginAttemptPolicy> loaded = findSingleService(
        LoginAttemptPolicy.class,
        ServiceLoader.load(LoginAttemptPolicy.class));
    loaded.ifPresent(policy -> loginAttemptPolicyRef.compareAndSet(null, policy));
    return loaded;
  }

  /**
   * Replaces the cached {@link LoginAttemptPolicy}. Intended for tests
   * and for applications that prefer programmatic wiring over SPI.
   *
   * @param policy the policy, or {@code null} to clear
   */
  public void setLoginAttemptPolicy(LoginAttemptPolicy policy) {
    loginAttemptPolicyRef.set(policy);
  }

  // ── SessionPolicy ──────────────────────────────────────────────

  /**
   * Returns the registered {@link SessionPolicy}, or the secure default
   * ({@link TimeoutSessionPolicy#secureDefault(String)}, JS-SEC-065) if no SPI
   * implementation is configured. Like the audit and login-attempt accessors, this method
   * <strong>never</strong> throws — session policies are optional
   * infrastructure.
   *
   * @param <U> subject type
   * @return the resolved policy, never {@code null}
   */
  @SuppressWarnings("unchecked")
  public <U> SessionPolicy<U> sessionPolicy() {
    SessionPolicy<?> cached = sessionPolicyRef.get();
    if (cached != null) {
      return (SessionPolicy<U>) cached;
    }

    SessionPolicy<?> loaded = findSingleService(
        SessionPolicy.class,
        ServiceLoader.load(SessionPolicy.class))
        .map(p -> (SessionPolicy<?>) p)
        .orElse(null);
    if (loaded == null) {
      loaded = secureDefaultSessionPolicy();
    }

    sessionPolicyRef.compareAndSet(null, loaded);
    return (SessionPolicy<U>) sessionPolicyRef.get();
  }

  /**
   * JS-SEC-065 (CWE-1188): the resolver default is an enforcing
   * {@link TimeoutSessionPolicy} — 30 min idle, 12 h absolute lifetime, rotation
   * after login, login route from {@link #loginRouteName()} — not the inert
   * {@link NoopSessionPolicy} it was until 00.83.00. {@link #findSessionPolicy()}
   * still reports the default as "not configured", so bootstrap diagnostics can
   * tell a default from a registration; registering {@link NoopSessionPolicy}
   * explicitly remains the opt-out.
   */
  private SessionPolicy<?> secureDefaultSessionPolicy() {
    SessionPolicy<?> policy = TimeoutSessionPolicy.secureDefault("/" + loginRouteName());
    defaultedSessionPolicy = policy;
    return policy;
  }

  /**
   * Returns the registered {@link SessionPolicy}, or empty if none is
   * configured. Use {@link #sessionPolicy()} for the noop fallback.
   *
   * @param <U> subject type
   * @return the SPI-registered policy, or empty
   */
  @SuppressWarnings("unchecked")
  public <U> Optional<SessionPolicy<U>> findSessionPolicy() {
    SessionPolicy<?> cached = sessionPolicyRef.get();
    if (cached != null) {
      boolean configured = !(cached instanceof NoopSessionPolicy<?>) && cached != defaultedSessionPolicy;
      return configured ? Optional.of((SessionPolicy<U>) cached) : Optional.empty();
    }

    Optional<SessionPolicy> loaded = findSingleService(
        SessionPolicy.class,
        ServiceLoader.load(SessionPolicy.class));
    loaded.ifPresent(policy -> sessionPolicyRef.compareAndSet(null, policy));
    return loaded.map(p -> (SessionPolicy<U>) p);
  }

  /**
   * Replaces the cached {@link SessionPolicy}. Intended for tests and for
   * applications that prefer programmatic wiring over SPI.
   *
   * @param policy the policy, or {@code null} to clear
   * @param <U>    subject type
   */
  public <U> void setSessionPolicy(SessionPolicy<U> policy) {
    sessionPolicyRef.set(policy);
  }

  // ── PasswordHasher ─────────────────────────────────────────────

  /**
   * Returns the registered {@link PasswordHasher}, or a fresh
   * {@link Pbkdf2PasswordHasher} when none is configured. Like the
   * audit / login-attempt / session accessors, this method
   * <strong>never</strong> throws — every application needs *some*
   * hasher; falling back to PBKDF2 with default iterations is the
   * least-surprising default.
   *
   * @return the resolved hasher, never {@code null}
   */
  public PasswordHasher passwordHashingService() {
    PasswordHasher cached = passwordHasherRef.get();
    if (cached != null) {
      return cached;
    }

    PasswordHasher loaded = findSingleService(
        PasswordHasher.class,
        ServiceLoader.load(PasswordHasher.class))
        .orElseGet(Pbkdf2PasswordHasher::new);

    passwordHasherRef.compareAndSet(null, loaded);
    return passwordHasherRef.get();
  }

  /**
   * Returns the SPI-registered {@link PasswordHasher}, or empty when
   * the hasher is the default PBKDF2 fallback.
   *
   * @return the SPI-registered hasher, or empty
   */
  public Optional<PasswordHasher> findPasswordHashingService() {
    PasswordHasher cached = passwordHasherRef.get();
    if (cached != null && !(cached instanceof Pbkdf2PasswordHasher)) {
      return Optional.of(cached);
    }
    if (cached instanceof Pbkdf2PasswordHasher) {
      // The cached instance is the default fallback. Allow SPI to
      // override on the next lookup by reporting "no SPI" here.
      return Optional.empty();
    }

    Optional<PasswordHasher> loaded = findSingleService(
        PasswordHasher.class,
        ServiceLoader.load(PasswordHasher.class));
    loaded.ifPresent(hasher -> passwordHasherRef.compareAndSet(null, hasher));
    return loaded;
  }

  /**
   * Replaces the cached {@link PasswordHasher}. Intended for tests and
   * for applications that prefer programmatic wiring over SPI.
   *
   * @param hasher the hasher, or {@code null} to clear
   */
  public void setPasswordHashingService(PasswordHasher hasher) {
    passwordHasherRef.set(hasher);
  }

  // ── LogoutService ──────────────────────────────────────────────

  /**
   * Returns the registered {@link LogoutService}, or
   * {@link NoopLogoutService#INSTANCE} when none is configured.
   * <p>
   * Like the audit / login-attempt / session accessors, this method
   * <strong>never</strong> throws — logout is optional infrastructure.
   * Production applications register a real {@link LogoutService}
   * (e.g. {@link SubjectClearingLogoutService} or the Vaadin adapter's
   * {@code VaadinLogoutService}) during startup via
   * {@link #setLogoutService(LogoutService)} or through
   * {@code META-INF/services}.
   *
   * @return the resolved service, never {@code null}
   */
  public LogoutService logoutService() {
    LogoutService cached = logoutServiceRef.get();
    if (cached != null) {
      return cached;
    }

    LogoutService loaded = findSingleService(
        LogoutService.class,
        ServiceLoader.load(LogoutService.class))
        .orElse(NoopLogoutService.INSTANCE);

    logoutServiceRef.compareAndSet(null, loaded);
    return logoutServiceRef.get();
  }

  /**
   * Returns the SPI-registered {@link LogoutService}, or empty when
   * only the noop fallback is cached.
   *
   * @return the SPI-registered service, or empty
   */
  public Optional<LogoutService> findLogoutService() {
    LogoutService cached = logoutServiceRef.get();
    if (cached != null && cached != NoopLogoutService.INSTANCE) {
      return Optional.of(cached);
    }
    if (cached == NoopLogoutService.INSTANCE) {
      return Optional.empty();
    }

    Optional<LogoutService> loaded = findSingleService(
        LogoutService.class,
        ServiceLoader.load(LogoutService.class));
    loaded.ifPresent(service -> logoutServiceRef.compareAndSet(null, service));
    return loaded;
  }

  /**
   * Replaces the cached {@link LogoutService}. Intended for tests and
   * for applications that prefer programmatic wiring over SPI.
   *
   * @param service the logout service, or {@code null} to clear
   */
  public void setLogoutService(LogoutService service) {
    logoutServiceRef.set(service);
  }

  // ── PolicyRegistry ─────────────────────────────────────────────

  /**
   * Returns the registered {@link PolicyRegistry}, or a fresh
   * {@link InMemoryPolicyRegistry} when none is configured. Like the
   * audit / login-attempt / session accessors, this method
   * <strong>never</strong> throws — the policy registry is optional
   * infrastructure for applications that use the {@code @RequiresPolicy}
   * annotation. The fallback registry is cached, so applications can
   * register policies into it at startup and they are visible on
   * subsequent lookups.
   *
   * @return the resolved registry, never {@code null}
   */
  public PolicyRegistry policyRegistry() {
    PolicyRegistry cached = policyRegistryRef.get();
    if (cached != null) {
      return cached;
    }

    PolicyRegistry loaded = findSingleService(
        PolicyRegistry.class,
        ServiceLoader.load(PolicyRegistry.class))
        .orElseGet(InMemoryPolicyRegistry::new);

    policyRegistryRef.compareAndSet(null, loaded);
    return policyRegistryRef.get();
  }

  /**
   * Returns the SPI-registered {@link PolicyRegistry}, or empty when
   * only the default {@link InMemoryPolicyRegistry} fallback is in use.
   *
   * @return the SPI-registered registry, or empty
   */
  public Optional<PolicyRegistry> findPolicyRegistry() {
    PolicyRegistry cached = policyRegistryRef.get();
    if (cached != null && !(cached instanceof InMemoryPolicyRegistry)) {
      return Optional.of(cached);
    }
    if (cached instanceof InMemoryPolicyRegistry) {
      // The cached instance is the default fallback. Report "no SPI"
      // so callers can decide whether to override.
      return Optional.empty();
    }

    Optional<PolicyRegistry> loaded = findSingleService(
        PolicyRegistry.class,
        ServiceLoader.load(PolicyRegistry.class));
    loaded.ifPresent(registry -> policyRegistryRef.compareAndSet(null, registry));
    return loaded;
  }

  /**
   * Replaces the cached {@link PolicyRegistry}. Intended for tests and
   * for applications that prefer programmatic wiring over SPI.
   *
   * @param registry the registry, or {@code null} to clear
   */
  public void setPolicyRegistry(PolicyRegistry registry) {
    policyRegistryRef.set(registry);
  }

  // ── ResourceResolverRegistry ──────────────────────────────────

  /**
   * Returns the registered {@link ResourceResolverRegistry}, or a
   * fresh {@link InMemoryResourceResolverRegistry} when none is
   * configured. Like the audit / policy accessors, this method
   * <strong>never</strong> throws — resource resolution is optional
   * infrastructure for applications that use
   * {@code ResourcePredicates}. The fallback registry is cached so
   * resolvers registered at startup remain visible.
   *
   * @return the resolved registry, never {@code null}
   */
  public ResourceResolverRegistry resourceResolverRegistry() {
    ResourceResolverRegistry cached = resourceResolverRegistryRef.get();
    if (cached != null) {
      return cached;
    }

    ResourceResolverRegistry loaded = findSingleService(
        ResourceResolverRegistry.class,
        ServiceLoader.load(ResourceResolverRegistry.class))
        .orElseGet(InMemoryResourceResolverRegistry::new);

    resourceResolverRegistryRef.compareAndSet(null, loaded);
    return resourceResolverRegistryRef.get();
  }

  /**
   * Returns the SPI-registered {@link ResourceResolverRegistry}, or
   * empty when only the default {@link InMemoryResourceResolverRegistry}
   * fallback is in use.
   *
   * @return the SPI-registered registry, or empty
   */
  public Optional<ResourceResolverRegistry> findResourceResolverRegistry() {
    ResourceResolverRegistry cached = resourceResolverRegistryRef.get();
    if (cached != null && !(cached instanceof InMemoryResourceResolverRegistry)) {
      return Optional.of(cached);
    }
    if (cached instanceof InMemoryResourceResolverRegistry) {
      return Optional.empty();
    }

    Optional<ResourceResolverRegistry> loaded = findSingleService(
        ResourceResolverRegistry.class,
        ServiceLoader.load(ResourceResolverRegistry.class));
    loaded.ifPresent(registry -> resourceResolverRegistryRef.compareAndSet(null, registry));
    return loaded;
  }

  /**
   * Replaces the cached {@link ResourceResolverRegistry}. Intended
   * for tests and for applications that prefer programmatic wiring
   * over SPI.
   *
   * @param registry the registry, or {@code null} to clear
   */
  public void setResourceResolverRegistry(ResourceResolverRegistry registry) {
    resourceResolverRegistryRef.set(registry);
  }

  // ── RoleHierarchy ─────────────────────────────────────────────

  /**
   * Returns the registered {@link RoleHierarchy}, or
   * {@link NoopRoleHierarchy#INSTANCE} when none is configured. Like
   * the audit / policy accessors, this method <strong>never</strong>
   * throws — role inheritance is optional infrastructure.
   *
   * @return the resolved hierarchy, never {@code null}
   */
  public RoleHierarchy roleHierarchy() {
    RoleHierarchy cached = roleHierarchyRef.get();
    if (cached != null) {
      return cached;
    }

    RoleHierarchy loaded = findSingleService(
        RoleHierarchy.class,
        ServiceLoader.load(RoleHierarchy.class))
        .orElse(NoopRoleHierarchy.INSTANCE);

    roleHierarchyRef.compareAndSet(null, loaded);
    return roleHierarchyRef.get();
  }

  /**
   * Returns the SPI-registered {@link RoleHierarchy}, or empty when
   * only the {@link NoopRoleHierarchy} fallback is in use.
   *
   * @return the SPI-registered hierarchy, or empty
   */
  public Optional<RoleHierarchy> findRoleHierarchy() {
    RoleHierarchy cached = roleHierarchyRef.get();
    if (cached != null && cached != NoopRoleHierarchy.INSTANCE) {
      return Optional.of(cached);
    }
    if (cached == NoopRoleHierarchy.INSTANCE) {
      return Optional.empty();
    }

    Optional<RoleHierarchy> loaded = findSingleService(
        RoleHierarchy.class,
        ServiceLoader.load(RoleHierarchy.class));
    loaded.ifPresent(hierarchy -> roleHierarchyRef.compareAndSet(null, hierarchy));
    return loaded;
  }

  /**
   * Replaces the cached {@link RoleHierarchy}. Intended for tests and
   * for applications that prefer programmatic wiring over SPI.
   *
   * @param hierarchy the hierarchy, or {@code null} to clear
   */
  public void setRoleHierarchy(RoleHierarchy hierarchy) {
    roleHierarchyRef.set(hierarchy);
  }

  // ── JCustosVersionStore ──────────────────────────────────────

  /**
   * Returns the SPI-registered {@link JCustosVersionStore}, or
   * empty when no implementation is configured. Phase 4c
   * snapshot-capture in the Vaadin login flow only fires when this
   * resolver returns a value <em>and</em> a {@link SubjectIdResolver}
   * is configured.
   *
   * @return the registered store, or empty
   */
  public Optional<JCustosVersionStore> findJCustosVersionStore() {
    JCustosVersionStore cached = securityVersionStoreRef.get();
    if (cached != null) {
      return Optional.of(cached);
    }
    Optional<JCustosVersionStore> loaded = findSingleService(
        JCustosVersionStore.class,
        ServiceLoader.load(JCustosVersionStore.class));
    loaded.ifPresent(store -> securityVersionStoreRef.compareAndSet(null, store));
    return loaded;
  }

  /**
   * Replaces the cached {@link JCustosVersionStore}. Intended for
   * tests and for applications that prefer programmatic wiring
   * over SPI.
   *
   * @param store the store, or {@code null} to clear
   */
  public void setJCustosVersionStore(JCustosVersionStore store) {
    securityVersionStoreRef.set(store);
  }

  // ── SubjectIdResolver ─────────────────────────────────────────

  /**
   * Returns the SPI-registered {@link SubjectIdResolver}, or
   * empty when no implementation is configured.
   *
   * @param <U> application user type
   * @return the registered resolver, or empty
   */
  @SuppressWarnings("unchecked")
  public <U> Optional<SubjectIdResolver<U>> findSubjectIdResolver() {
    SubjectIdResolver<?> cached = subjectIdResolverRef.get();
    if (cached != null) {
      return Optional.of((SubjectIdResolver<U>) cached);
    }
    Optional<SubjectIdResolver> loaded = findSingleService(
        SubjectIdResolver.class,
        ServiceLoader.load(SubjectIdResolver.class));
    loaded.ifPresent(resolver -> subjectIdResolverRef.compareAndSet(null, resolver));
    return Optional.ofNullable((SubjectIdResolver<U>) subjectIdResolverRef.get());
  }

  /**
   * Replaces the cached {@link SubjectIdResolver}. Intended for
   * tests and for applications that prefer programmatic wiring
   * over SPI.
   *
   * @param resolver the resolver, or {@code null} to clear
   * @param <U>      application user type
   */
  public <U> void setSubjectIdResolver(SubjectIdResolver<U> resolver) {
    subjectIdResolverRef.set(resolver);
  }

  // ── Step-up route ─────────────────────────────────────────────

  /**
   * Returns the route name a Vaadin adapter reroutes to when a
   * {@link AuthorizationDecision.StepUpRequired} is mapped. Defaults
   * to {@link JCustosServiceResolver#DEFAULT_STEP_UP_ROUTE_NAME};
   * can be overridden via {@link #setStepUpRouteName(String)} at
   * application bootstrap.
   *
   * @return non-blank route name, never {@code null}
   */
  public String stepUpRouteName() {
    String configured = stepUpRouteNameRef.get();
    return configured == null
        ? JCustosServiceResolver.DEFAULT_STEP_UP_ROUTE_NAME : configured;
  }

  /**
   * Returns the explicitly configured step-up route name, or empty
   * when only the {@link JCustosServiceResolver#DEFAULT_STEP_UP_ROUTE_NAME}
   * fallback is in use. Symmetric to the other {@code findXxx()} accessors
   * so tests and bootstrap code can distinguish "default" from "configured".
   *
   * @return configured route name, or empty
   */
  public Optional<String> findStepUpRouteName() {
    return Optional.ofNullable(stepUpRouteNameRef.get());
  }

  /**
   * Overrides the step-up route name. Pass {@code null} to fall back
   * to {@link JCustosServiceResolver#DEFAULT_STEP_UP_ROUTE_NAME}.
   * Adapter-side routing reads the value on every navigation, so
   * reconfiguration takes effect immediately.
   *
   * @param routeName non-blank route name, or {@code null} to reset
   * @throws IllegalArgumentException if {@code routeName} is blank
   */
  public void setStepUpRouteName(String routeName) {
    if (routeName != null && routeName.isBlank()) {
      throw new IllegalArgumentException("stepUpRouteName must not be blank");
    }
    stepUpRouteNameRef.set(routeName);
  }

  // ── Login route ───────────────────────────────────────────────

  /**
   * Returns the route name a Vaadin adapter reroutes to when an
   * {@link AuthorizationDecision.Unauthenticated} is mapped. Defaults to
   * {@link JCustosServiceResolver#DEFAULT_LOGIN_ROUTE_NAME}; can be overridden
   * via {@link #setLoginRouteName(String)} at application bootstrap so apps that
   * name their login route differently are not silently broken (R025).
   *
   * @return non-blank route name, never {@code null}
   */
  public String loginRouteName() {
    String configured = loginRouteNameRef.get();
    return configured == null
        ? JCustosServiceResolver.DEFAULT_LOGIN_ROUTE_NAME : configured;
  }

  /**
   * Returns the explicitly configured login route name, or empty when only the
   * {@link JCustosServiceResolver#DEFAULT_LOGIN_ROUTE_NAME} fallback is in use.
   *
   * @return configured route name, or empty
   */
  public Optional<String> findLoginRouteName() {
    return Optional.ofNullable(loginRouteNameRef.get());
  }

  /**
   * Overrides the login route name. Pass {@code null} to fall back to
   * {@link JCustosServiceResolver#DEFAULT_LOGIN_ROUTE_NAME}.
   *
   * @param routeName non-blank route name, or {@code null} to reset
   * @throws IllegalArgumentException if {@code routeName} is blank
   */
  public void setLoginRouteName(String routeName) {
    if (routeName != null && routeName.isBlank()) {
      throw new IllegalArgumentException("loginRouteName must not be blank");
    }
    loginRouteNameRef.set(routeName);
  }

  // ── Deny-by-default (JS-SEC-024 / CWE-862) ─────────────────────

  /** @return {@code true} when un-annotated non-{@code @PublicRoute} targets fail closed. */
  public boolean isDenyByDefault() {
    return denyByDefaultRef.get();
  }

  /**
   * Enables/disables deny-by-default. Adapters read this on every navigation /
   * request, so reconfiguration is immediate.
   *
   * @param denyByDefault {@code true} to fail closed
   */
  public void setDenyByDefault(boolean denyByDefault) {
    denyByDefaultRef.set(denyByDefault);
  }

  // ── TokenCredentialStore / OutboundTokenStrategy ───────────────

  /**
   * V00.74 — resolve the {@link TokenCredentialStore}.
   *
   * <p>SPI-discovered + cached. Override via
   * {@link #setTokenCredentialStore(TokenCredentialStore)} or via the
   * {@code .propagation(p -> p.credentialStore(...))} bootstrap
   * sub-builder.
   *
   * @return the active store
   * @throws IllegalStateException if no SPI implementation is registered
   */
  @ExperimentalJCustosApi
  public TokenCredentialStore tokenCredentialStore() {
    TokenCredentialStore cached = tokenCredentialStoreRef.get();
    if (cached != null) return cached;
    TokenCredentialStore resolved = findSingleService(
        TokenCredentialStore.class, ServiceLoader.load(TokenCredentialStore.class))
        .orElseThrow(() -> missingService(TokenCredentialStore.class));
    tokenCredentialStoreRef.compareAndSet(null, resolved);
    return tokenCredentialStoreRef.get();
  }

  /**
   * V00.74 — optional lookup of the {@link TokenCredentialStore}.
   *
   * @return the resolved store, or empty if none registered
   */
  @ExperimentalJCustosApi
  public Optional<TokenCredentialStore> findTokenCredentialStore() {
    TokenCredentialStore cached = tokenCredentialStoreRef.get();
    if (cached != null) return Optional.of(cached);
    Optional<TokenCredentialStore> resolved = findSingleService(
        TokenCredentialStore.class, ServiceLoader.load(TokenCredentialStore.class));
    resolved.ifPresent(s -> tokenCredentialStoreRef.compareAndSet(null, s));
    return resolved;
  }

  /**
   * V00.74 — explicitly install a {@link TokenCredentialStore}.
   * Overrides any SPI-discovered or previously-cached value. Used by
   * the {@code .propagation(...)} bootstrap sub-builder.
   *
   * @param store the store, or {@code null} to reset
   */
  @ExperimentalJCustosApi
  public void setTokenCredentialStore(TokenCredentialStore store) {
    tokenCredentialStoreRef.set(store);
  }

  /**
   * V00.76 — optional lookup of the installed {@link
   * eu.jsentinel.jcustos.jwt.api.JwtValidator}. Not SPI-discovered; present
   * only after the {@code .jwt(...)} sub-builder installs one.
   *
   * @return the active validator, or empty
   */
  @ExperimentalJCustosApi
  public Optional<eu.jsentinel.jcustos.jwt.api.JwtValidator> findJwtValidator() {
    return Optional.ofNullable(jwtValidatorRef.get());
  }

  /**
   * V00.76 — install the {@link eu.jsentinel.jcustos.jwt.api.JwtValidator}.
   * Used by the {@code .jwt(...)} bootstrap sub-builder.
   *
   * @param validator the validator, or {@code null} to reset
   */
  @ExperimentalJCustosApi
  public void setJwtValidator(eu.jsentinel.jcustos.jwt.api.JwtValidator validator) {
    jwtValidatorRef.set(validator);
  }

  /**
   * V00.74 — register an {@link OutboundTokenStrategy} under a name.
   * Used by the {@code .propagation(p -> p.strategy(name, ...))} bootstrap
   * sub-builder.
   *
   * @param name     the lookup key
   * @param strategy the strategy
   */
  @ExperimentalJCustosApi
  public void registerOutboundTokenStrategy(String name, OutboundTokenStrategy strategy) {
    java.util.Objects.requireNonNull(name, "name");
    java.util.Objects.requireNonNull(strategy, "strategy");
    outboundStrategies.put(name, strategy);
  }

  /**
   * V00.74 — look up an {@link OutboundTokenStrategy} by name.
   * Returns {@link Optional#empty()} when the name is not registered;
   * STRICT-mode diagnostics raise on missing strategies elsewhere, not
   * here, so the advisor stays side-effect-free.
   *
   * @param name the lookup key
   * @return the strategy, or empty
   */
  @ExperimentalJCustosApi
  public Optional<OutboundTokenStrategy> findOutboundTokenStrategy(String name) {
    return Optional.ofNullable(outboundStrategies.get(name));
  }

  // ── Reset (for testing) ────────────────────────────────────────

  /**
   * Clears all cached service references held by this context.
   * <p>
   * Unlike {@link JCustosServiceResolver#resetAll()}, this method does
   * <strong>not</strong> reset the global {@link SubjectStores} — that
   * coupling lives only on the static facade.
   */
  public void resetAll() {
    authenticationServiceRef.set(null);
    authorizationServiceRef.set(null);
    auditServiceRef.set(null);
    actionAuthServiceRef.set(null);
    loginAttemptPolicyRef.set(null);
    sessionPolicyRef.set(null);
    defaultedSessionPolicy = null;
    passwordHasherRef.set(null);
    logoutServiceRef.set(null);
    policyRegistryRef.set(null);
    resourceResolverRegistryRef.set(null);
    roleHierarchyRef.set(null);
    securityVersionStoreRef.set(null);
    subjectIdResolverRef.set(null);
    stepUpRouteNameRef.set(null);
    loginRouteNameRef.set(null);
    denyByDefaultRef.set(false);
    tokenCredentialStoreRef.set(null);
    outboundStrategies.clear();
  }

  static <S> S requireSingleService(Class<S> serviceType, Iterable<? extends S> services) {
    return findSingleService(serviceType, services)
        .orElseThrow(() -> missingService(serviceType));
  }

  static <S> Optional<S> findSingleService(Class<S> serviceType, Iterable<? extends S> services) {
    var found = StreamSupport.stream(services.spliterator(), false)
        .toList();
    if (found.isEmpty()) {
      return Optional.empty();
    }
    if (found.size() > 1) {
      throw multipleServices(serviceType, found);
    }
    return Optional.of(found.getFirst());
  }

  private static IllegalStateException missingService(Class<?> serviceType) {
    return new IllegalStateException(
        "Unable to resolve " + serviceType.getSimpleName() + " — "
            + "no implementation found in META-INF/services/"
            + serviceType.getName()
            + ". Provide an implementation and register it "
            + "via the ServiceLoader mechanism.");
  }

  private static IllegalStateException multipleServices(Class<?> serviceType, Iterable<?> services) {
    String implementations = StreamSupport.stream(services.spliterator(), false)
        .map(service -> service.getClass().getName())
        .collect(Collectors.joining(", "));
    return new IllegalStateException(
        "Unable to resolve " + serviceType.getSimpleName() + " — "
            + "multiple implementations found in META-INF/services/"
            + serviceType.getName()
            + ": " + implementations
            + ". Register exactly one implementation to avoid classpath-order dependent security behavior.");
  }
}
