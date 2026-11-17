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

import eu.jsentinel.jcustos.audit.JCustosAuditService;
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
 * <em>single</em> username from a <em>single</em> source address. Without
 * further configuration it does <strong>not</strong> stop password spraying
 * (many usernames, one host) or distributed credential stuffing (one account,
 * many IPs) — those keep every per-tuple counter under the threshold.
 *
 * <p><strong>Password spraying (JS-SEC-062, CWE-307).</strong> With
 * {@link LoginAttemptLimits#perAddress()} set, every attempt that carries a
 * client address is also counted on the address key
 * {@link LoginAttemptKey#forAddress(TenantId, String)}: a second store
 * operation per attempt, with the address thresholds and the flat lockout of
 * this policy ({@code initialLockout}; {@code maxLockout} is not used here). The
 * account is asked first; when the address then refuses, the account's
 * reservation is given back. A successful login releases the address's
 * reservation but does not reset its counter. The account key and the address
 * key are separate store operations, not one atomic step: a lockout of the
 * address that sets in between them is caught by the next attempt. User names
 * pass through {@link LoginAttemptKey#accountUserId(String)}, so no account
 * can share the address's counter. Distributed stuffing against one account
 * remains the job of the {@code AbuseDetectionService} (TENANT / GLOBAL
 * volume, per the ASVS L2 map).
 *
 * <p><strong>Concurrent credential checks (JS-SEC-063, CWE-770).</strong>
 * {@link #credentialCheckGate()} returns the gate of the policy's
 * {@link LoginAttemptLimits}: unbounded by default.
 *
 * <p>Bound to one {@link TenantId} at construction. Multi-tenant
 * deployments instantiate one policy per tenant or wrap with a
 * resolver.
 */
@ExperimentalJCustosApi
public final class StoreBackedLoginAttemptPolicy implements LoginAttemptPolicy {

  private final LoginAttemptStore store;
  private final LoginAttemptLimits loginLimits;
  private final AttemptLimits limits;
  /** Limits of the address key; {@code null} while the address counter is off (JS-SEC-062). */
  private final AttemptLimits addressLimits;
  private final CredentialCheckGate gate;
  private final TenantId tenant;
  private final Clock clock;
  private final SubjectKeyCanonicalizer canonicalizer;
  private final JCustosAuditService auditService;

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
    this(store, config, tenant, clock, canonicalizer, null);
  }

  /**
   * Full constructor with an explicit audit service for the {@code LoginFailed} event of
   * {@link #recordFailure(LoginAttemptContext)}.
   *
   * @param store         backing store; non-null
   * @param config        thresholds; non-null
   * @param tenant        tenant scope; {@code null} becomes
   *                      {@link TenantId#DEFAULT}
   * @param clock         time source; non-null
   * @param canonicalizer maps a user name onto its throttle key; non-null
   * @param auditService  audit sink, or {@code null} to resolve from
   *                      {@link eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver}
   *                      on each event
   * @since 00.84.00
   */
  public StoreBackedLoginAttemptPolicy(LoginAttemptStore store,
                                       LoginAttemptConfiguration config,
                                       TenantId tenant,
                                       Clock clock,
                                       SubjectKeyCanonicalizer canonicalizer,
                                       JCustosAuditService auditService) {
    this(store, LoginAttemptLimits.of(requireNonNull(config, "config must not be null")), tenant,
        clock, canonicalizer, auditService);
  }

  /**
   * Full constructor with the address counter and the bound on concurrent credential checks of
   * {@code limits} (JS-SEC-062, JS-SEC-063).
   *
   * @param store         backing store; non-null
   * @param limits        thresholds; non-null
   * @param tenant        tenant scope; {@code null} becomes
   *                      {@link TenantId#DEFAULT}
   * @param clock         time source; non-null
   * @param canonicalizer maps a user name onto its throttle key; non-null
   * @param auditService  audit sink, or {@code null} to resolve from
   *                      {@link eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver}
   *                      on each event
   * @since 00.84.00
   */
  public StoreBackedLoginAttemptPolicy(LoginAttemptStore store,
                                       LoginAttemptLimits limits,
                                       TenantId tenant,
                                       Clock clock,
                                       SubjectKeyCanonicalizer canonicalizer,
                                       JCustosAuditService auditService) {
    this.auditService = auditService;
    this.store = requireNonNull(store, "store must not be null");
    this.loginLimits = requireNonNull(limits, "limits must not be null");
    LoginAttemptConfiguration config = limits.perAccount();
    this.tenant = tenant == null ? TenantId.DEFAULT : tenant;
    this.clock = requireNonNull(clock, "clock must not be null");
    this.canonicalizer = requireNonNull(canonicalizer, "canonicalizer must not be null");
    this.limits = new AttemptLimits(config.failureThreshold(), config.window(),
        config.initialLockout(), InMemoryLoginAttemptPolicy.ATTEMPT_RESERVATION_TTL);
    this.addressLimits = limits.perAddress()
        .map(address -> new AttemptLimits(address.failureThreshold(), address.window(),
            address.initialLockout(), InMemoryLoginAttemptPolicy.ATTEMPT_RESERVATION_TTL))
        .orElse(null);
    this.gate = CredentialCheckGate.of(limits, clock, auditService);
  }

  /**
   * @return the limits this policy counts with
   * @since 00.84.00
   */
  public LoginAttemptLimits limits() {
    return loginLimits;
  }

  /**
   * The gate of this policy's {@link LoginAttemptLimits}; the same instance on every call.
   *
   * @return the gate
   * @since 00.84.00
   */
  @Override
  public CredentialCheckGate credentialCheckGate() {
    return gate;
  }

  @Override
  public LoginAttemptDecision beforeAttempt(LoginAttemptContext context) {
    requireNonNull(context, "context must not be null");
    Instant now = clock.instant();
    LoginAttemptKey account = key(context);
    // JS-SEC-123 (CWE-367): one store operation checks the lockout and reserves the attempt.
    AttemptStatus accountStatus = store.tryBeginAttempt(account, now, limits);
    LoginAttemptKey address = addressKey(context);
    if (accountStatus.blocked() || address == null) {
      return decision(accountStatus, now);
    }
    // JS-SEC-062 (CWE-307): the address is asked second; a refusal gives the account back.
    AttemptStatus addressStatus;
    try {
      addressStatus = store.tryBeginAttempt(address, now, addressLimits);
    } catch (RuntimeException storeFailure) {
      store.abandonAttempt(account, now);
      throw storeFailure;
    }
    if (addressStatus.blocked()) {
      store.abandonAttempt(account, now);
    }
    return decision(addressStatus, now);
  }

  @Override
  public LoginAttemptDecision peek(LoginAttemptContext context) {
    requireNonNull(context, "context must not be null");
    Instant now = clock.instant();
    LoginAttemptDecision account = derivedLockout(key(context), limits, now);
    if (account instanceof LoginAttemptDecision.LockedOut) {
      return account;
    }
    LoginAttemptKey address = addressKey(context);
    return address == null ? account : derivedLockout(address, addressLimits, now);
  }

  /**
   * The lockout {@code key} is under, derived from counter and last failure the way the store
   * derives it - without reserving anything.
   */
  private LoginAttemptDecision derivedLockout(LoginAttemptKey key, AttemptLimits keyLimits,
                                              Instant now) {
    int failures = store.failureCount(key);
    if (failures < keyLimits.failureThreshold()) {
      return LoginAttemptDecision.allowed();
    }
    return store.lastFailureAt(key)
        .map(last -> plusLockout(last, keyLimits))
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
    LoginAttemptKey account = key(context);
    LoginAttemptKey address = addressKey(context);
    if (address != null) {
      // JS-SEC-062: the address keeps its failures - a success only gives its slot back. A
      // lockout of the address that set in while this attempt was checked denies the login,
      // as a lockout of the account does (JS-SEC-123), and leaves the account counter alone.
      store.abandonAttempt(address, now);
      LoginAttemptDecision addressLock = derivedLockout(address, addressLimits, now);
      if (addressLock instanceof LoginAttemptDecision.LockedOut) {
        store.abandonAttempt(account, now);
        return addressLock;
      }
    }
    // JS-SEC-123 (CWE-307): the store keeps a live lockout and reports it; the login is denied.
    return decision(store.completeSuccess(account, now, limits), now);
  }

  @Override
  public void recordFailure(LoginAttemptContext context) {
    recordFailure(context, REASON_CREDENTIALS_REJECTED);
  }

  /**
   * Counts the failure and publishes the one {@code LoginFailed} event of the rejected login
   * (see {@link LoginAttemptPolicy#recordFailure(LoginAttemptContext)}). Until 00.84.00 this
   * policy published nothing, and an adapter that left the event to the policy - the Vaadin
   * {@code LoginView}, the REST handlers - audited no failed login behind it.
   *
   * <p>When the failure locks the key, {@code BruteForceLimitReached} follows, as with
   * {@link InMemoryLoginAttemptPolicy}. Until 00.84.00 this policy ignored the status the store
   * reported, and a lockout earned against the persistent store never reached the audit trail
   * (JS-SEC-123, CWE-778).</p>
   */
  @Override
  public void recordFailure(LoginAttemptContext context, String reason) {
    requireNonNull(context, "context must not be null");
    Instant now = clock.instant();
    AttemptStatus status = store.completeFailure(key(context), now, limits);
    LoginAttemptKey address = addressKey(context);
    AttemptStatus addressStatus = address == null
        ? null
        : store.completeFailure(address, now, addressLimits);
    LoginFailureAudit.publish(auditService, now, context, reason);
    if (lockedByThisFailure(status, now, limits)) {
      publishLimitReached(context, status, now);
    }
    if (addressStatus != null && lockedByThisFailure(addressStatus, now, addressLimits)) {
      // JS-SEC-062: the lockout belongs to the address, not to the account that was tried last
      publishLimitReached(new LoginAttemptContext("", context.clientAddress(),
          context.sessionId(), context.timestamp()), addressStatus, now);
    }
  }

  private void publishLimitReached(LoginAttemptContext context, AttemptStatus status,
                                   Instant now) {
    Instant until = status.blockedUntil().get();
    LoginFailureAudit.publishLimitReached(auditService, now, context, status.failures(),
        until.isAfter(now) ? Duration.between(now, until) : Duration.ZERO);
  }

  /**
   * The store derives a lockout from counter and last failure: a key is locked from the failure
   * that reaches the threshold, and every further failure - the single attempt admitted after a
   * lockout ran out - locks it again from that failure on. Either way the lockout starts with
   * the failure just recorded.
   */
  private static boolean lockedByThisFailure(AttemptStatus status, Instant now,
                                             AttemptLimits keyLimits) {
    return status.blocked()
        && status.failures() >= keyLimits.failureThreshold()
        && status.blockedUntil().get().equals(plusLockout(now, keyLimits));
  }

  private static Instant plusLockout(Instant from, AttemptLimits keyLimits) {
    try {
      return from.plus(keyLimits.lockout());
    } catch (java.time.DateTimeException | ArithmeticException overflow) {
      return Instant.MAX;
    }
  }

  @Override
  public void abandonAttempt(LoginAttemptContext context) {
    requireNonNull(context, "context must not be null");
    Instant now = clock.instant();
    // JS-SEC-126 (CWE-703): no verdict - release the reservation, count nothing.
    store.abandonAttempt(key(context), now);
    LoginAttemptKey address = addressKey(context);
    if (address != null) {
      store.abandonAttempt(address, now);
    }
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

  /**
   * JS-SEC-062: the address key, or {@code null} when the address counter is off or the attempt
   * carries no client address - an address that is not known is not counted.
   */
  private LoginAttemptKey addressKey(LoginAttemptContext context) {
    if (addressLimits == null || context.clientAddress() == null
        || context.clientAddress().isBlank()) {
      return null;
    }
    return LoginAttemptKey.forAddress(tenant, address(context.clientAddress()));
  }

  private String username(String value) {
    if (value == null || value.isBlank()) {
      return "-";
    }
    String canonical = canonicalizer.canonicalize(value);
    // JS-SEC-062: a name that looks like a reserved user id is escaped - no account shares the
    // counter of an address key
    return canonical.isBlank() ? "-" : LoginAttemptKey.accountUserId(canonical);
  }

  private static String address(String value) {
    return value == null || value.isBlank() ? "-" : value.trim().toLowerCase(Locale.ROOT);
  }
}
