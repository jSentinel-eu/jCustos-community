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

import eu.jsentinel.jcustos.audit.BruteForceLimitReached;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicyTest.RecordingAudit;
import eu.jsentinel.jcustos.util.SubjectKeyCanonicalizer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-062 (CWE-307): the address counter of both policies counts an IPv6 address per prefix -
 * a /64 by default - and an IPv4 address exactly. Whoever controls a /64 can no longer pick a new
 * address for every guess. Real policies, real stores, documentation addresses only.
 */
@DisplayName("JS-SEC-062 - the address counter counts IPv6 per prefix, IPv4 exactly")
class LoginAttemptAddressPrefixTest {

  private static final Instant T0 = Instant.parse("2026-11-19T10:00:00Z");
  /** Three failures from one bucket within an hour lock it for 30 min; the default /64. */
  private static final LoginAttemptLimits.AddressLimit ADDRESS = new LoginAttemptLimits.AddressLimit(
      3, Duration.ofHours(1), Duration.ofMinutes(30), Duration.ofHours(2));

  private static LoginAttemptContext ctx(String user, String address) {
    return new LoginAttemptContext(user, address, null, T0);
  }

  private static List<Function<RecordingAudit, LoginAttemptPolicy>> bothPolicies(
      LoginAttemptLimits.AddressLimit address) {
    LoginAttemptLimits limits = LoginAttemptLimits.defaults().withAddressLimit(address);
    Clock clock = Clock.fixed(T0, ZoneOffset.UTC);
    return List.of(
        audit -> new InMemoryLoginAttemptPolicy(limits, clock, audit),
        audit -> new StoreBackedLoginAttemptPolicy(new InMemoryLoginAttemptStore(), limits,
            TenantId.DEFAULT, clock, SubjectKeyCanonicalizer.defaults(), audit));
  }

  /** One failed login from each address, each on an account of its own. */
  private static void sprayFrom(LoginAttemptPolicy policy, String... addresses) {
    for (int i = 0; i < addresses.length; i++) {
      LoginAttemptContext attempt = ctx("user-" + i + "-" + addresses[i], addresses[i]);
      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(attempt),
          policy.getClass().getSimpleName() + ": " + addresses[i]);
      policy.recordFailure(attempt);
    }
  }

  @Test
  @DisplayName("three addresses of one /64 share the counter: the /64 locks, a neighbouring /64 does not")
  void oneSlash64SharesTheCounter() {
    for (Function<RecordingAudit, LoginAttemptPolicy> factory : bothPolicies(ADDRESS)) {
      RecordingAudit audit = new RecordingAudit();
      LoginAttemptPolicy policy = factory.apply(audit);
      String name = policy.getClass().getSimpleName();

      sprayFrom(policy, "2001:db8:1:2::1", "2001:db8:1:2:aaaa::2", "2001:db8:1:2:ffff:ffff:ffff:ffff");

      LoginAttemptDecision.LockedOut locked = assertInstanceOf(LoginAttemptDecision.LockedOut.class,
          policy.beforeAttempt(ctx("fresh", "2001:db8:1:2:1234::99")),
          name + ": a fourth address of the same /64 is refused");
      assertEquals(ADDRESS.initialLockout(), locked.remaining(), name);
      assertEquals(LoginAttemptDecision.allowed(), policy.peek(ctx("fresh", "2001:db8:1:3::1")),
          name + ": the neighbouring /64 is a client of its own");

      List<BruteForceLimitReached> limitReached = audit.events.stream()
          .filter(BruteForceLimitReached.class::isInstance)
          .map(BruteForceLimitReached.class::cast)
          .toList();
      assertEquals(1, limitReached.size(), name);
      assertEquals("", limitReached.getFirst().username(), name);
      assertEquals("2001:db8:1:2::/64", limitReached.getFirst().clientAddress(),
          name + ": the audit names the locked prefix");
    }
  }

  @Test
  @DisplayName("a configured /48 groups wider: three /64 of one /48 lock it; the default /64 counts them apart")
  void slash48GroupsWider() {
    String[] spread = {"2001:db8:1:2::1", "2001:db8:1:3::1", "2001:db8:1:ffff::1"};
    for (Function<RecordingAudit, LoginAttemptPolicy> factory
        : bothPolicies(ADDRESS.withIpv6PrefixLength(48))) {
      LoginAttemptPolicy policy = factory.apply(new RecordingAudit());
      sprayFrom(policy, spread);
      assertInstanceOf(LoginAttemptDecision.LockedOut.class,
          policy.peek(ctx("fresh", "2001:db8:1:abcd::7")), policy.getClass().getSimpleName());
      assertEquals(LoginAttemptDecision.allowed(), policy.peek(ctx("fresh", "2001:db8:2::1")),
          policy.getClass().getSimpleName() + ": another /48");
    }
    for (Function<RecordingAudit, LoginAttemptPolicy> factory : bothPolicies(ADDRESS)) {
      LoginAttemptPolicy policy = factory.apply(new RecordingAudit());
      sprayFrom(policy, spread);
      for (String address : spread) {
        assertEquals(LoginAttemptDecision.allowed(), policy.peek(ctx("fresh", address)),
            policy.getClass().getSimpleName() + ": " + address + " with the default /64");
      }
    }
  }

  @Test
  @DisplayName("128 counts every IPv6 address exactly - the behaviour before the prefix")
  void slash128IsExact() {
    for (Function<RecordingAudit, LoginAttemptPolicy> factory
        : bothPolicies(ADDRESS.withIpv6PrefixLength(128))) {
      LoginAttemptPolicy policy = factory.apply(new RecordingAudit());
      sprayFrom(policy, "2001:db8:1:2::1", "2001:db8:1:2::2", "2001:db8:1:2::3");
      assertEquals(LoginAttemptDecision.allowed(), policy.peek(ctx("fresh", "2001:db8:1:2::4")),
          policy.getClass().getSimpleName());
    }
  }

  @Test
  @DisplayName("IPv4 stays exact; an IPv4-mapped IPv6 address counts as that IPv4 address")
  void ipv4IsExactAndMappedIsIpv4() {
    for (Function<RecordingAudit, LoginAttemptPolicy> factory : bothPolicies(ADDRESS)) {
      LoginAttemptPolicy policy = factory.apply(new RecordingAudit());
      String name = policy.getClass().getSimpleName();
      sprayFrom(policy, "203.0.113.1", "203.0.113.2", "203.0.113.3");
      for (String address : List.of("203.0.113.1", "203.0.113.2", "203.0.113.4")) {
        assertEquals(LoginAttemptDecision.allowed(), policy.peek(ctx("fresh", address)),
            name + ": " + address + " - no grouping of IPv4 addresses");
      }

      sprayFrom(policy, "::ffff:203.0.113.7", "203.0.113.7", "::FFFF:CB00:7107");
      assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.peek(ctx("x", "203.0.113.7")),
          name + ": three spellings, one IPv4 address");
      assertInstanceOf(LoginAttemptDecision.LockedOut.class,
          policy.peek(ctx("x", "::ffff:203.0.113.7")), name);
    }
  }

  @Test
  @DisplayName("store-backed: the address key carries the bucket, the tuple key the exact address")
  void storeKeysCarryBucketAndExactAddress() {
    InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore();
    StoreBackedLoginAttemptPolicy policy = new StoreBackedLoginAttemptPolicy(store,
        LoginAttemptLimits.defaults().withAddressLimit(ADDRESS), TenantId.DEFAULT,
        Clock.fixed(T0, ZoneOffset.UTC), SubjectKeyCanonicalizer.defaults(), new RecordingAudit());

    sprayFrom(policy, "2001:DB8:1:2::1", "[2001:db8:1:2::2]:4711");

    assertEquals(2, store.failureCount(LoginAttemptKey.forAddress(TenantId.DEFAULT,
        "2001:db8:1:2::/64")), "one address key for the /64, in canonical form");
    assertEquals(0, store.failureCount(LoginAttemptKey.forAddress(TenantId.DEFAULT,
        "2001:db8:1:2::1")));
    assertEquals(1, store.failureCount(new LoginAttemptKey(TenantId.DEFAULT,
        "user-0-2001:db8:1:2::1", "2001:db8:1:2::1")),
        "the tuple key keeps the exact address, normalised as before");
    assertEquals(1, store.failureCount(LoginAttemptKey.forAccount(TenantId.DEFAULT,
        "user-0-2001:db8:1:2::1")));
  }

  @Test
  @DisplayName("in memory: the (user, address) counter keeps the exact address - one /64 is not one client for an account")
  void inMemoryCombinedKeyStaysExact() {
    LoginAttemptLimits limits = LoginAttemptLimits.defaults().withAddressLimit(
        new LoginAttemptLimits.AddressLimit(50, Duration.ofHours(1), Duration.ofMinutes(30),
            Duration.ofHours(2)));
    InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy(limits,
        Clock.fixed(T0, ZoneOffset.UTC), new RecordingAudit());
    int accountThreshold = limits.perAccount().failureThreshold();
    for (int i = 0; i < accountThreshold - 1; i++) {
      LoginAttemptContext attempt = ctx("alice", "2001:db8:1:2::" + (i + 1));
      assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(attempt));
      policy.recordFailure(attempt);
    }
    assertEquals(accountThreshold - 1, policy.trackedCombinedKeyCount(),
        "one (user, address) entry per exact address");
    assertEquals(1, policy.trackedAddressCount(), "one address entry for the /64");
    assertTrue(policy.peek(ctx("bob", "2001:db8:1:2::77")) instanceof LoginAttemptDecision.Allowed);
  }
}
