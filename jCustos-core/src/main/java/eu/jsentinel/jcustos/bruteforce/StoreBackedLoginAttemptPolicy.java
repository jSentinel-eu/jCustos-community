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
package eu.jsentinel.jcustos.bruteforce;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore.AttemptLimits;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore.AttemptStatus;
import eu.jsentinel.jcustos.util.SubjectKeyCanonicalizer;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;

import static java.util.Objects.requireNonNull;

/**
 * {@link LoginAttemptPolicy} that stores its failure counters in a
 * {@link LoginAttemptStore}.
 * <p>
 * Counter and last-failure timestamp survive a process restart — a
 * lockout earned on Monday is still in effect on Tuesday. Unlike the
 * {@link InMemoryLoginAttemptPolicy} default, this implementation
 * runs a <em>flat</em> lockout: once
 * {@link LoginAttemptConfiguration#failureThreshold()} failures have
 * accumulated, the key locks for
 * {@link LoginAttemptConfiguration#initialLockout()} starting at the
 * last failure. The progressive backoff that the in-memory policy
 * offers requires per-key history (lockout level, "just locked"
 * flag) that the narrower {@link LoginAttemptStore} contract does
 * not carry — applications that need progressive backoff stay on
 * the in-memory policy or wrap this one with a richer key store.
 *
 * <p><strong>Atomic attempts (JS-SEC-122, JS-SEC-123).</strong> The policy
 * talks to the store only through its atomic attempt operations:
 * {@link #beforeAttempt} is {@link LoginAttemptStore#tryBeginAttempt} — the
 * lockout check and the reservation in one step —, the reports are
 * {@link LoginAttemptStore#completeFailure},
 * {@link LoginAttemptStore#completeSuccess} and
 * {@link LoginAttemptStore#abandonAttempt}. With a store that implements
 * them atomically (the in-memory store, the Eclipse-Store adapter)
 * parallel requests cannot exceed the threshold, a late success does not
 * lift a lockout, a full store refuses new keys instead of evicting a
 * lockout, and a counter is forgotten once no failure has been recorded
 * for a full {@link LoginAttemptConfiguration#window()}. With a store that
 * only inherits the SPI defaults the policy behaves as it did before
 * 00.84.00, apart from the late success.
 *
 * <p><strong>Scope (JS-SEC-012):</strong> the lockout key is the
 * {@code (tenant, username, ip)} tuple, so this policy only locks a
 * <em>single</em> username from a <em>single</em> source address. It does
 * <strong>not</strong> stop password spraying (many usernames, one host) or
 * distributed credential stuffing (one account, many IPs) — those keep every
 * per-tuple counter under the threshold. Anti-automation across those
 * dimensions is the job of the {@code AbuseDetectionService} (CLIENT_ADDRESS /
 * TENANT / GLOBAL volume, per the ASVS L2 map); wire it alongside this policy
 * rather than relying on the lockout alone.
 *
 * <p>Bound to one {@link TenantId} at construction. Multi-tenant
 * deployments instantiate one policy per tenant or wrap with a
 * resolver.
 */
@ExperimentalJCustosApi
public final class StoreBackedLoginAttemptPolicy implements LoginAttemptPolicy {

  private final LoginAttemptStore store;
  private final LoginAttemptConfiguration config;
  private final AttemptLimits limits;
  private final TenantId tenant;
  private final Clock clock;
  private final SubjectKeyCanonicalizer canonicalizer;

  /**
   * Builds a policy with {@link LoginAttemptConfiguration#defaults()}
   * and {@link TenantId#DEFAULT}.
   *
   * @param store backing store; non-null
   */
  public StoreBackedLoginAttemptPolicy(LoginAttemptStore store) {
    this(store, LoginAttemptConfiguration.defaults(), TenantId.DEFAULT, Clock.systemUTC());
  }

  /**
   * Full constructor with the default {@link SubjectKeyCanonicalizer}.
   *
   * @param store  backing store; non-null
   * @param config thresholds; non-null
   * @param tenant tenant scope; {@code null} becomes
   *               {@link TenantId#DEFAULT}
   * @param clock  time source; non-null. Pass a fixed clock to make
   *               tests deterministic.
   */
  public StoreBackedLoginAttemptPolicy(LoginAttemptStore store,
                                       LoginAttemptConfiguration config,
                                       TenantId tenant,
                                       Clock clock) {
    this(store, config, tenant, clock, SubjectKeyCanonicalizer.defaults());
  }

  /**
   * JS-SEC-123 (CWE-178): the canonicaliser decides which spellings of a
   * user name are the same account. Hand the same instance to the
   * credential store.
   *
   * @param store         backing store; non-null
   * @param config        thresholds; non-null
   * @param tenant        tenant scope; {@code null} becomes
   *                      {@link TenantId#DEFAULT}
   * @param clock         time source; non-null
   * @param canonicalizer maps a user name onto its throttle key; non-null
   * @since 00.84.00
   */
  public StoreBackedLoginAttemptPolicy(LoginAttemptStore store,
                                       LoginAttemptConfiguration config,
                                       TenantId tenant,
                                       Clock clock,
                                       SubjectKeyCanonicalizer canonicalizer) {
    this.store = requireNonNull(store, "store must not be null");
    this.config = requireNonNull(config, "config must not be null");
    this.tenant = tenant == null ? TenantId.DEFAULT : tenant;
    this.clock = requireNonNull(clock, "clock must not be null");
    this.canonicalizer = requireNonNull(canonicalizer, "canonicalizer must not be null");
    this.limits = new AttemptLimits(config.failureThreshold(), config.window(),
        config.initialLockout(), InMemoryLoginAttemptPolicy.ATTEMPT_RESERVATION_TTL);
  }

  @Override
  public LoginAttemptDecision beforeAttempt(LoginAttemptContext context) {
    requireNonNull(context, "context must not be null");
    Instant now = clock.instant();
    // JS-SEC-123 (CWE-367): one store operation checks the lockout and reserves the attempt.
    return decision(store.tryBeginAttempt(key(context), now, limits), now);
  }

  @Override
  public LoginAttemptDecision peek(LoginAttemptContext context) {
    requireNonNull(context, "context must not be null");
    LoginAttemptKey key = key(context);
    int failures = store.failureCount(key);
    if (failures < config.failureThreshold()) {
      return LoginAttemptDecision.allowed();
    }
    Instant now = clock.instant();
    return store.lastFailureAt(key)
        .map(last -> last.plus(config.initialLockout()))
        .filter(now::isBefore)
        .<LoginAttemptDecision>map(until ->
            LoginAttemptDecision.lockedOut(Duration.between(now, until), failures))
        .orElseGet(LoginAttemptDecision::allowed);
  }

  @Override
  public void recordSuccess(LoginAttemptContext context) {
    confirmSuccess(context);
  }

  @Override
  public LoginAttemptDecision confirmSuccess(LoginAttemptContext context) {
    requireNonNull(context, "context must not be null");
    Instant now = clock.instant();
    // JS-SEC-123 (CWE-307): the store keeps a live lockout and reports it; the login is denied.
    return decision(store.completeSuccess(key(context), now, limits), now);
  }

  @Override
  public void recordFailure(LoginAttemptContext context) {
    requireNonNull(context, "context must not be null");
    store.completeFailure(key(context), clock.instant(), limits);
  }

  @Override
  public void abandonAttempt(LoginAttemptContext context) {
    requireNonNull(context, "context must not be null");
    // JS-SEC-126 (CWE-703): no verdict - release the reservation, count nothing.
    store.abandonAttempt(key(context), clock.instant());
  }

  private static LoginAttemptDecision decision(AttemptStatus status, Instant now) {
    if (!status.blocked()) {
      return LoginAttemptDecision.allowed();
    }
    Instant until = status.blockedUntil().get();
    Duration remaining = until.isAfter(now) ? Duration.between(now, until) : Duration.ZERO;
    return LoginAttemptDecision.lockedOut(remaining, status.failures());
  }

  private LoginAttemptKey key(LoginAttemptContext context) {
    return new LoginAttemptKey(tenant, username(context.username()),
        address(context.clientAddress()));
  }

  private String username(String value) {
    if (value == null || value.isBlank()) {
      return "-";
    }
    String canonical = canonicalizer.canonicalize(value);
    return canonical.isBlank() ? "-" : canonical;
  }

  private static String address(String value) {
    return value == null || value.isBlank() ? "-" : value.trim().toLowerCase(Locale.ROOT);
  }
}
