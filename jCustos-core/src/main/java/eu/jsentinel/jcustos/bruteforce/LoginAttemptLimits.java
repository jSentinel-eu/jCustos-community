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
import eu.jsentinel.jcustos.net.AddressBucket;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

/**
 * Everything the shipped {@link LoginAttemptPolicy} implementations limit: the per-account
 * thresholds of {@link LoginAttemptConfiguration}, plus two dimensions that configuration cannot
 * carry without breaking its stable record shape.
 *
 * <ul>
 *   <li><strong>{@link #perAddress()}</strong> (JS-SEC-062, CWE-307) - a counter on the client
 *       address alone. The account counters cannot see password spraying: one address that tries
 *       one or two passwords against each of many accounts stays below every per-account
 *       threshold. IPv6 addresses are counted per prefix, {@link #DEFAULT_IPV6_PREFIX_LENGTH}
 *       bits by default. Off by default.</li>
 *   <li><strong>{@link #maxConcurrentCredentialChecks()}</strong> (JS-SEC-063, CWE-770) - how many
 *       credential checks may run at the same time behind the policy's
 *       {@link LoginAttemptPolicy#credentialCheckGate() gate}. A credential check is the most
 *       expensive step of a login (a memory-hard KDF, a directory lookup); without a bound, a
 *       flood of logins for distinct accounts exhausts CPU and memory long before any throttle
 *       counts a failure. {@link #UNBOUNDED_CREDENTIAL_CHECKS} (the default) means no bound.</li>
 * </ul>
 *
 * <p>{@link #of(LoginAttemptConfiguration)} and {@link #defaults()} keep the behaviour of a
 * policy built from a plain {@link LoginAttemptConfiguration}: no address counter, no bound on
 * concurrent checks. Nothing changes until one of them is configured, in code through the
 * {@code with...} methods or through {@link LoginAttemptConfigurationLoader#loadLimits()}.
 *
 * @param perAccount                    thresholds of the account counters; non-null
 * @param perAddress                    thresholds of the address counter; empty switches it off
 * @param maxConcurrentCredentialChecks credential checks that may run at once;
 *                                      {@link #UNBOUNDED_CREDENTIAL_CHECKS} for no bound
 * @param gateWait                      how long an attempt waits for a free slot before it is
 *                                      deferred; zero or positive, at most {@link #MAX_GATE_WAIT}
 * @param gateRetryAfter                the retry-after a deferred attempt is answered with;
 *                                      positive
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public record LoginAttemptLimits(
    LoginAttemptConfiguration perAccount,
    Optional<AddressLimit> perAddress,
    int maxConcurrentCredentialChecks,
    Duration gateWait,
    Duration gateRetryAfter
) {

  /** {@link #maxConcurrentCredentialChecks()} value that switches the bound off: {@value}. */
  public static final int UNBOUNDED_CREDENTIAL_CHECKS = 0;

  /**
   * Default {@link #gateWait()}: 250 ms. Long enough to ride out a short burst, short enough
   * that a request thread does not queue for long behind a saturated gate.
   */
  public static final Duration DEFAULT_GATE_WAIT = Duration.ofMillis(250);

  /** Default {@link #gateRetryAfter()}: one second. */
  public static final Duration DEFAULT_GATE_RETRY_AFTER = Duration.ofSeconds(1);

  /**
   * Longest accepted {@link #gateWait()}: ten seconds. An attempt waits for the gate after the
   * policy has reserved it, and the reservation lapses after
   * {@link InMemoryLoginAttemptPolicy#ATTEMPT_RESERVATION_TTL}; a wait close to that would let the
   * reservation run out while the attempt is still queued, and the credential check needs its
   * share of the time as well.
   */
  public static final Duration MAX_GATE_WAIT = Duration.ofSeconds(10);

  /**
   * Default {@link AddressLimit#ipv6PrefixLength()}: {@value} bits. A /64 is the standard IPv6
   * subnet (RFC 4291 interface identifiers, SLAAC): what one host, one mobile device or one
   * customer LAN is usually given, and within which it can pick a new source address for every
   * request. Counting such a client per exact address would never see two of its attempts.
   *
   * @since 00.84.00
   */
  public static final int DEFAULT_IPV6_PREFIX_LENGTH = 64;

  /**
   * Shortest accepted {@link AddressLimit#ipv6PrefixLength()}: {@value} bits, the typical size
   * of the block a regional internet registry allocates to a provider. A shorter prefix would
   * put the customers of several providers into one bucket, and one sprayer among them would
   * lock out all of them.
   *
   * @since 00.84.00
   */
  public static final int MIN_IPV6_PREFIX_LENGTH = 32;

  /**
   * Longest accepted {@link AddressLimit#ipv6PrefixLength()}: {@value} bits - every IPv6 address
   * is counted exactly, as IPv4 addresses always are.
   *
   * @since 00.84.00
   */
  public static final int MAX_IPV6_PREFIX_LENGTH = 128;

  /** Validates the components. */
  public LoginAttemptLimits {
    Objects.requireNonNull(perAccount, "perAccount");
    Objects.requireNonNull(perAddress, "perAddress");
    if (maxConcurrentCredentialChecks < 0) {
      throw new IllegalArgumentException("maxConcurrentCredentialChecks must be >= 0 (0 = unbounded)");
    }
    Objects.requireNonNull(gateWait, "gateWait");
    if (gateWait.isNegative()) {
      throw new IllegalArgumentException("gateWait must not be negative");
    }
    if (gateWait.compareTo(MAX_GATE_WAIT) > 0) {
      throw new IllegalArgumentException("gateWait must not exceed " + MAX_GATE_WAIT);
    }
    Objects.requireNonNull(gateRetryAfter, "gateRetryAfter");
    if (gateRetryAfter.isNegative() || gateRetryAfter.isZero()) {
      throw new IllegalArgumentException("gateRetryAfter must be positive");
    }
  }

  /**
   * Thresholds of the address counter (JS-SEC-062). Same vocabulary as
   * {@link LoginAttemptConfiguration}: {@code failureThreshold} failures from one address within
   * {@code window} lock the address for {@code initialLockout}; the in-memory policy doubles the
   * lockout on every further breach up to {@code maxLockout}, the store-backed policy locks for
   * {@code initialLockout} each time.
   *
   * <p>Choose the threshold with the clients in mind that share one address - an office behind
   * NAT, a reverse proxy without a configured {@code ClientAddressResolver}. Every failed login
   * of all of them counts against the address, and a successful login does <strong>not</strong>
   * reset the address counter: an attacker with one account of their own could otherwise reset
   * the counter of the address they spray from.
   *
   * <p><strong>Failures only, no reservation (exit review RF03).</strong> Unlike the account
   * counters, the address counter does not count attempts in flight against its threshold: it
   * refuses an attempt only while the address is locked. Otherwise {@code failureThreshold}
   * users behind one company or mobile NAT who log in at the same moment would lock out every
   * further user of that address - without a single failure. The price is a bounded overshoot:
   * the attempts from one address that were admitted before the failure that reaches the
   * threshold are still checked, so the address can collect more failures than the threshold
   * by up to the number of its attempts in flight at that moment. The credential-check gate
   * bounds that number (JS-SEC-063): with {@link LoginAttemptLimits#maxConcurrentCredentialChecks()}
   * set, at most that many checks run at once for all addresses together, and an attempt that
   * waits for a permit longer than {@link LoginAttemptLimits#gateWait()} is deferred unchecked.
   * The account counters keep their reservations, so no single account sees more than its own
   * threshold in flight.
   *
   * <p><strong>IPv6 prefixes (JS-SEC-062).</strong> An IPv6 host can usually pick a new source
   * address within its /64 for every request. The counter therefore keys an IPv6 address on its
   * first {@code ipv6PrefixLength} bits - every address of one prefix shares one counter - and an
   * IPv4 address, also when written as IPv4-mapped IPv6, on the exact address. See
   * {@link #bucketOf(String)}. The {@code (tenant, user, address)} tuple counter of the
   * store-backed policy and the {@code (user, address)} counter of the in-memory policy keep the
   * exact address.
   *
   * @param failureThreshold failures from one address within {@code window} that lock it
   * @param window           rolling window for the count
   * @param initialLockout   duration of the first lockout
   * @param maxLockout       cap for the progressive backoff
   * @param ipv6PrefixLength bits of an IPv6 address that identify the client it is counted for,
   *                         from {@link #MIN_IPV6_PREFIX_LENGTH} to
   *                         {@link #MAX_IPV6_PREFIX_LENGTH}; {@link #DEFAULT_IPV6_PREFIX_LENGTH}
   *                         with the four-argument constructor (since 00.84.00)
   */
  @ExperimentalJCustosApi
  public record AddressLimit(int failureThreshold, Duration window, Duration initialLockout,
                             Duration maxLockout, int ipv6PrefixLength) {

    /**
     * Validates the components: the thresholds with the rules of
     * {@link LoginAttemptConfiguration}, the prefix length against its range - fail closed.
     */
    public AddressLimit {
      new LoginAttemptConfiguration(failureThreshold, window, initialLockout, maxLockout);
      if (ipv6PrefixLength < MIN_IPV6_PREFIX_LENGTH || ipv6PrefixLength > MAX_IPV6_PREFIX_LENGTH) {
        throw new IllegalArgumentException("ipv6PrefixLength must be between "
            + MIN_IPV6_PREFIX_LENGTH + " and " + MAX_IPV6_PREFIX_LENGTH + ": " + ipv6PrefixLength);
      }
    }

    /**
     * Thresholds with the default IPv6 prefix of {@link #DEFAULT_IPV6_PREFIX_LENGTH} bits.
     *
     * @param failureThreshold failures from one address within {@code window} that lock it
     * @param window           rolling window for the count
     * @param initialLockout   duration of the first lockout
     * @param maxLockout       cap for the progressive backoff
     */
    public AddressLimit(int failureThreshold, Duration window, Duration initialLockout,
                        Duration maxLockout) {
      this(failureThreshold, window, initialLockout, maxLockout, DEFAULT_IPV6_PREFIX_LENGTH);
    }

    /**
     * @param prefixLength bits of an IPv6 address that identify its bucket, from
     *                     {@link #MIN_IPV6_PREFIX_LENGTH} to {@link #MAX_IPV6_PREFIX_LENGTH}
     * @return a copy with the new prefix length
     * @since 00.84.00
     */
    public AddressLimit withIpv6PrefixLength(int prefixLength) {
      return new AddressLimit(failureThreshold, window, initialLockout, maxLockout, prefixLength);
    }

    /**
     * The bucket the address counter counts {@code clientAddress} in: for an IPv6 literal its
     * network prefix of {@link #ipv6PrefixLength()} bits in canonical form, such as
     * {@code 2001:db8:1:2::/64}; for an IPv4 literal, also an IPv4-mapped one, the exact address;
     * for any other text the trimmed, lower-cased text. Both shipped policies key their address
     * counter on this value, so every node derives the same key. See
     * {@link eu.jsentinel.jcustos.net.AddressBucket}.
     *
     * @param clientAddress the client address of an attempt; non-null
     * @return the bucket
     * @since 00.84.00
     */
    public String bucketOf(String clientAddress) {
      return AddressBucket.of(clientAddress, ipv6PrefixLength);
    }

    /**
     * @return the same thresholds in the vocabulary the policies count with
     */
    public LoginAttemptConfiguration asConfiguration() {
      return new LoginAttemptConfiguration(failureThreshold, window, initialLockout, maxLockout);
    }
  }

  /**
   * The limits of a policy built from {@code perAccount} alone: no address counter, no bound on
   * concurrent credential checks - the behaviour before 00.84.00.
   *
   * @param perAccount thresholds of the account counters; non-null
   * @return limits with only the account thresholds set
   */
  public static LoginAttemptLimits of(LoginAttemptConfiguration perAccount) {
    return new LoginAttemptLimits(perAccount, Optional.empty(), UNBOUNDED_CREDENTIAL_CHECKS,
        DEFAULT_GATE_WAIT, DEFAULT_GATE_RETRY_AFTER);
  }

  /**
   * @return {@code of(LoginAttemptConfiguration.defaults())}
   */
  public static LoginAttemptLimits defaults() {
    return of(LoginAttemptConfiguration.defaults());
  }

  /**
   * @param addressLimit thresholds of the address counter; non-null
   * @return a copy with the address counter switched on
   */
  public LoginAttemptLimits withAddressLimit(AddressLimit addressLimit) {
    return new LoginAttemptLimits(perAccount, Optional.of(addressLimit),
        maxConcurrentCredentialChecks, gateWait, gateRetryAfter);
  }

  /**
   * @param maxConcurrent credential checks that may run at once;
   *                      {@link #UNBOUNDED_CREDENTIAL_CHECKS} switches the bound off
   * @return a copy with the new bound
   */
  public LoginAttemptLimits withMaxConcurrentCredentialChecks(int maxConcurrent) {
    return new LoginAttemptLimits(perAccount, perAddress, maxConcurrent, gateWait, gateRetryAfter);
  }

  /**
   * @param wait how long an attempt waits for a free slot; zero or positive, at most
   *             {@link #MAX_GATE_WAIT}
   * @return a copy with the new wait
   */
  public LoginAttemptLimits withGateWait(Duration wait) {
    return new LoginAttemptLimits(perAccount, perAddress, maxConcurrentCredentialChecks, wait,
        gateRetryAfter);
  }

  /**
   * @param retryAfter the retry-after of a deferred attempt; positive
   * @return a copy with the new retry-after
   */
  public LoginAttemptLimits withGateRetryAfter(Duration retryAfter) {
    return new LoginAttemptLimits(perAccount, perAddress, maxConcurrentCredentialChecks, gateWait,
        retryAfter);
  }

  /**
   * @return {@code true} when concurrent credential checks are bounded
   */
  public boolean credentialChecksBounded() {
    return maxConcurrentCredentialChecks != UNBOUNDED_CREDENTIAL_CHECKS;
  }
}
