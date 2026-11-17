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
import java.util.ArrayList;
import java.util.List;
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
 * <p><strong>Scope (JS-SEC-012, JS-SEC-166, CWE-307).</strong> Every attempt is
 * counted on two keys with the thresholds of
 * {@link LoginAttemptLimits#perAccount()}, as {@link InMemoryLoginAttemptPolicy}
 * counts it on its combined and its user-name counter:
 *
 * <ul>
 *   <li>the {@code (tenant, username, ip)} tuple - one user name from one source
 *       address;</li>
 *   <li>the account key {@link LoginAttemptKey#forAccount(TenantId, String)} -
 *       the account from every address, so distributed credential stuffing (one
 *       account, many addresses) locks the account once the threshold is reached
 *       in total.</li>
 * </ul>
 *
 * <p>Until 00.84.00 the policy counted the tuple only, and an attacker who
 * changed address after every few guesses was never locked out (JS-SEC-012);
 * whoever moved from the in-memory policy to this one to run several nodes lost
 * that protection. The account key is always on, as the user-name counter of the
 * in-memory policy is. <strong>Consequence:</strong> anybody who knows a user
 * name can lock that account for {@code initialLockout} by failing
 * {@code failureThreshold} times from any addresses - the same targeted lockout
 * the in-memory policy has always allowed. A success never lifts a lockout in
 * force; the next one is possible after it ends. The tuple, the account and the
 * address key are separate store operations, not one atomic step: a lockout of
 * one of them that sets in between them is caught by the next attempt.
 *
 * <p><strong>Password spraying (JS-SEC-062, CWE-307).</strong> With
 * {@link LoginAttemptLimits#perAddress()} set, every attempt that carries a
 * client address is also counted on the address key
 * {@link LoginAttemptKey#forAddress(TenantId, String)}: a third store
 * operation per attempt, with the address thresholds and the flat lockout of
 * this policy ({@code initialLockout}; {@code maxLockout} is not used here). The
 * account keys are asked first; when the address then refuses, their
 * reservations are given back. A successful login releases the address's
 * reservation but does not reset its counter. User names pass through
 * {@link LoginAttemptKey#accountUserId(String)}, so no account can share the
 * counter of an address or of an account key.
 *
 * <p><strong>Several nodes (JS-SEC-166).</strong> Policies on several nodes that
 * share one store act as one throttle: a lockout earned through one node refuses
 * the attempt on every other node, and the reservations of all nodes together
 * stay within the threshold - provided the store performs each attempt operation
 * atomically for every caller, not only within one process. Every node passes its
 * own clock's instant to the store, so a skew between the node clocks lengthens or
 * shortens a lockout by up to that skew. The in-memory store and the Eclipse-Store
 * adapter live in one process and cannot be shared between nodes; the deployment
 * guide {@code docs/security/deployment/cluster.md} names what a shared store has
 * to provide. A shared store often keeps instants in milliseconds or whole seconds;
 * the policy still recognises the lockout a failure caused and audits it, within
 * {@link #STORE_INSTANT_TOLERANCE}.
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

  /** Stands for a missing or blank user name or client address in a key. */
  private static final String NO_VALUE = "-";

  /**
   * How much earlier than {@code now + lockout} the lockout a store reports for a failure may
   * end and still count as started by that failure: {@code 1 s}. It covers a store that keeps
   * instants in milliseconds or whole seconds - a JDBC {@code TIMESTAMP(3)} or {@code DATETIME}
   * column - instead of the nanoseconds of {@link Instant}; a coarser store does not get its
   * lockouts audited as {@code BruteForceLimitReached}.
   *
   * @since 00.84.00
   */
  public static final Duration STORE_INSTANT_TOLERANCE = Duration.ofSeconds(1);

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
    Keys keys = keys(context);
    // JS-SEC-123 (CWE-367): one store operation per key checks the lockout and reserves the
    // attempt. JS-SEC-166 / JS-SEC-062 (CWE-307): the tuple first, then the account, then the
    // address; a refusal gives back what the keys before it reserved.
    List<LoginAttemptKey> reserved = new ArrayList<>(3);
    for (Counter counter : keys.counters(limits, addressLimits)) {
      AttemptStatus status;
      try {
        status = store.tryBeginAttempt(counter.key(), now, counter.limits());
      } catch (RuntimeException storeFailure) {
        giveBack(reserved, now, storeFailure);
        throw storeFailure;
      }
      if (status.blocked()) {
        giveBack(reserved, now, null);
        return decision(status, now);
      }
      reserved.add(counter.key());
    }
    return LoginAttemptDecision.allowed();
  }

  /**
   * Releases the reservations of {@code reserved}. A store failure while doing so is attached to
   * {@code cause} when there is one, so it does not hide the failure that is being reported.
   */
  private void giveBack(List<LoginAttemptKey> reserved, Instant now, RuntimeException cause) {
    for (LoginAttemptKey key : reserved) {
      try {
        store.abandonAttempt(key, now);
      } catch (RuntimeException releaseFailure) {
        if (cause == null) {
          throw releaseFailure;
        }
        cause.addSuppressed(releaseFailure);
      }
    }
  }

  @Override
  public LoginAttemptDecision peek(LoginAttemptContext context) {
    requireNonNull(context, "context must not be null");
    Instant now = clock.instant();
    for (Counter counter : keys(context).counters(limits, addressLimits)) {
      LoginAttemptDecision lockout = derivedLockout(counter.key(), counter.limits(), now);
      if (lockout instanceof LoginAttemptDecision.LockedOut) {
        return lockout;
      }
    }
    return LoginAttemptDecision.allowed();
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
    Keys keys = keys(context);
    if (keys.address() != null) {
      // JS-SEC-062: the address keeps its failures - a success only gives its slot back. A
      // lockout of the address that set in while this attempt was checked denies the login,
      // as a lockout of the account does (JS-SEC-123), and leaves the account counters alone.
      store.abandonAttempt(keys.address(), now);
      LoginAttemptDecision addressLock = derivedLockout(keys.address(), addressLimits, now);
      if (addressLock instanceof LoginAttemptDecision.LockedOut) {
        store.abandonAttempt(keys.account(), now);
        store.abandonAttempt(keys.tuple(), now);
        return addressLock;
      }
    }
    // JS-SEC-166 (CWE-307): the account before the tuple. A lockout earned from other addresses
    // while this attempt was checked denies the login and leaves the tuple's counter alone.
    AttemptStatus account = store.completeSuccess(keys.account(), now, limits);
    if (account.blocked()) {
      store.abandonAttempt(keys.tuple(), now);
      return decision(account, now);
    }
    // JS-SEC-123 (CWE-307): the store keeps a live lockout and reports it; the login is denied.
    return decision(store.completeSuccess(keys.tuple(), now, limits), now);
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
   * (JS-SEC-123, CWE-778). The tuple and the account key lock at the same threshold; when one
   * failure locks both, one event is published (JS-SEC-166).</p>
   */
  @Override
  public void recordFailure(LoginAttemptContext context, String reason) {
    requireNonNull(context, "context must not be null");
    Instant now = clock.instant();
    Keys keys = keys(context);
    AttemptStatus status = store.completeFailure(keys.tuple(), now, limits);
    AttemptStatus accountStatus = store.completeFailure(keys.account(), now, limits);
    AttemptStatus addressStatus = keys.address() == null
        ? null
        : store.completeFailure(keys.address(), now, addressLimits);
    LoginFailureAudit.publish(auditService, now, context, reason);
    if (lockedByThisFailure(status, now, limits)) {
      publishLimitReached(context, status, now);
    } else if (lockedByThisFailure(accountStatus, now, limits)) {
      // JS-SEC-166: the account reached the threshold across several addresses
      publishLimitReached(context, accountStatus, now);
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
   *
   * <p>The store may keep instants coarser than the clock - a JDBC {@code TIMESTAMP(3)} keeps
   * milliseconds, a {@code DATETIME} whole seconds -, so the lockout it reports can start up to
   * {@link #STORE_INSTANT_TOLERANCE} before {@code now}, or a little after it when the store
   * rounds. Until 00.84.00 the test was exact equality, and a store with millisecond instants
   * never published {@code BruteForceLimitReached} (CWE-778). A lockout that an earlier failure
   * started and this one did not move ends at least that tolerance earlier; a store that moves the
   * lockout with every failure, as the SPI derivation does, reports it with every failure anyway.
   */
  private static boolean lockedByThisFailure(AttemptStatus status, Instant now,
                                             AttemptLimits keyLimits) {
    return status.blocked()
        && status.failures() >= keyLimits.failureThreshold()
        && !status.blockedUntil().get().isBefore(
            minusTolerance(plusLockout(now, keyLimits)));
  }

  private static Instant minusTolerance(Instant lockoutEnd) {
    try {
      return lockoutEnd.minus(STORE_INSTANT_TOLERANCE);
    } catch (java.time.DateTimeException | ArithmeticException overflow) {
      return Instant.MIN;
    }
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
    // JS-SEC-126 (CWE-703): no verdict - release the reservations, count nothing.
    for (Counter counter : keys(context).counters(limits, addressLimits)) {
      store.abandonAttempt(counter.key(), now);
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

  /**
   * The keys of one attempt. The user name is canonicalised once: the tuple key carries it
   * escaped ({@link LoginAttemptKey#accountUserId(String)}), the account key unchanged behind
   * its reserved prefix (JS-SEC-166).
   */
  private Keys keys(LoginAttemptContext context) {
    String canonical = canonicalUsername(context.username());
    String address = address(context.clientAddress());
    return new Keys(
        new LoginAttemptKey(tenant, LoginAttemptKey.accountUserId(canonical), address),
        LoginAttemptKey.forAccount(tenant, canonical),
        addressKey(context, address));
  }

  /**
   * JS-SEC-062: the address key, or {@code null} when the address counter is off or the attempt
   * carries no client address - an address that is not known is not counted.
   */
  private LoginAttemptKey addressKey(LoginAttemptContext context, String normalisedAddress) {
    if (addressLimits == null || context.clientAddress() == null
        || context.clientAddress().isBlank()) {
      return null;
    }
    return LoginAttemptKey.forAddress(tenant, normalisedAddress);
  }

  /** The canonical user name, or {@code "-"} for a missing or blank one. */
  private String canonicalUsername(String value) {
    if (value == null || value.isBlank()) {
      return NO_VALUE;
    }
    String canonical = canonicalizer.canonicalize(value);
    return canonical.isBlank() ? NO_VALUE : canonical;
  }

  private static String address(String value) {
    return value == null || value.isBlank() ? NO_VALUE : value.trim().toLowerCase(Locale.ROOT);
  }

  /**
   * The keys one attempt is counted on (JS-SEC-166).
   *
   * @param tuple   the {@code (tenant, username, ip)} key
   * @param account the account key across all addresses
   * @param address the address key; {@code null} when the address counter does not apply
   */
  private record Keys(LoginAttemptKey tuple, LoginAttemptKey account, LoginAttemptKey address) {

    /** The keys with their limits, in the order they are asked. */
    List<Counter> counters(AttemptLimits accountLimits, AttemptLimits addressLimits) {
      return address == null
          ? List.of(new Counter(tuple, accountLimits), new Counter(account, accountLimits))
          : List.of(new Counter(tuple, accountLimits), new Counter(account, accountLimits),
              new Counter(address, addressLimits));
    }
  }

  /** A key and the limits it is counted with. */
  private record Counter(LoginAttemptKey key, AttemptLimits limits) {
  }
}
