/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.abuse;

import eu.jsentinel.jcustos.audit.RateLimitExceeded;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.util.SubjectKeyCanonicalizer;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory reference implementation of
 * {@link AbuseDetectionService}.
 *
 * <p>Each {@code (AbuseAttemptType, AbuseDimension, dimensionKey)}
 * tuple has its own sliding-window deque of event timestamps. What
 * counts as an event depends on the pair
 * {@code (AbuseAttemptType, AbuseDimension)}:</p>
 * <ul>
 *   <li><em>Volume counters</em> record every attempt regardless of
 *       its outcome and are never reset by a success:
 *       {@link AbuseDimension#CLIENT_ADDRESS},
 *       {@link AbuseDimension#TENANT} and {@link AbuseDimension#GLOBAL}
 *       for every attempt type, and — since 00.84.00 —
 *       {@link AbuseDimension#USERNAME} for
 *       {@link AbuseAttemptType#RESET_REQUEST} (JS-SEC-121, CWE-799: an
 *       accepted reset request is a {@code SUCCESS}, so a failure
 *       counter never saw it and a mailbox could be flooded
 *       unthrottled).</li>
 *   <li><em>Failure counters</em> record failures only and are cleared
 *       by a success: {@link AbuseDimension#USERNAME} for every other
 *       attempt type ({@code LOGIN}, {@code PASSWORD_CHANGE},
 *       {@code RESET_CONSUME}).</li>
 * </ul>
 *
 * <p>One key per account (JS-SEC-123, CWE-178): the key of the
 * {@link AbuseDimension#USERNAME} dimension is the username after the
 * {@link SubjectKeyCanonicalizer} - by default NFKC, lower-case, trimmed -
 * so {@code alice} and {@code ALICE} draw on one budget, as they share one
 * counter in the login throttle and are one record in
 * {@code InMemoryCredentialStore}. Until 00.84.00 the raw spelling was the
 * key: every spelling of a name had a reset-request budget of its own, and
 * the per-username limit was whatever the number of spellings made of it. A
 * deployment whose user names are case-sensitive passes
 * {@link SubjectKeyCanonicalizer#exact()} here, to its credential store and
 * to its login policy alike.</p>
 *
 * <p>Auditing is best-effort: every block / step-up / delay decision
 * publishes a {@link RateLimitExceeded} event with the dimension
 * encoded in the {@code scope} field. Sink failures are swallowed
 * (CWE-778).</p>
 */
public final class InMemoryAbuseDetectionService implements AbuseDetectionService {

  /** Dimensions that count every attempt, not just failures, for every attempt type. */
  private static final Set<AbuseDimension> VOLUME_DIMENSIONS = EnumSet.of(
      AbuseDimension.CLIENT_ADDRESS,
      AbuseDimension.TENANT,
      AbuseDimension.GLOBAL);

  /**
   * Counting semantics of one {@code (attemptType, dimension)} pair.
   *
   * <p>JS-SEC-121 (CWE-799, CWE-307): the per-username counter of
   * {@link AbuseAttemptType#RESET_REQUEST} is a volume counter. A reset request
   * that was accepted for an existing user is reported as
   * {@link AttemptOutcome#SUCCESS}; as a failure counter the dimension never
   * counted it and every such request cleared the window, so the documented
   * per-username limit only ever applied to unknown usernames.</p>
   *
   * @return {@code true} when every attempt is counted and a success does not
   *     reset the window; {@code false} for a failure counter that a success clears
   */
  static boolean countsEveryAttempt(AbuseAttemptType attemptType, AbuseDimension dimension) {
    return VOLUME_DIMENSIONS.contains(dimension)
        || attemptType == AbuseAttemptType.RESET_REQUEST;
  }

  /** JS-SEC-030 (CWE-770): default upper bound on tracked counter keys. */
  public static final int DEFAULT_MAX_ENTRIES = 100_000;

  private final AbuseLimitsPolicy policy;
  private final JCustosAuditService auditService;
  private final int maxEntries;
  private final SubjectKeyCanonicalizer canonicalizer;
  private final ConcurrentHashMap<String, Deque<Instant>> counters =
      new ConcurrentHashMap<>();

  public InMemoryAbuseDetectionService(
      AbuseLimitsPolicy policy, JCustosAuditService auditService) {
    this(policy, auditService, DEFAULT_MAX_ENTRIES);
  }

  public InMemoryAbuseDetectionService(
      AbuseLimitsPolicy policy, JCustosAuditService auditService, int maxEntries) {
    this(policy, auditService, maxEntries, SubjectKeyCanonicalizer.defaults());
  }

  /**
   * Full constructor.
   *
   * @param policy        limits per attempt type and dimension; non-null
   * @param auditService  audit sink; non-null
   * @param maxEntries    upper bound on tracked counter keys; at least 1
   * @param canonicalizer maps a user name onto the key of the
   *                      {@link AbuseDimension#USERNAME} dimension (JS-SEC-123);
   *                      use the instance the credential store and the login
   *                      policy use; non-null
   * @since 00.84.00
   */
  public InMemoryAbuseDetectionService(
      AbuseLimitsPolicy policy, JCustosAuditService auditService, int maxEntries,
      SubjectKeyCanonicalizer canonicalizer) {
    this.policy = Objects.requireNonNull(policy, "policy");
    this.auditService = Objects.requireNonNull(auditService, "auditService");
    if (maxEntries < 1) {
      throw new IllegalArgumentException("maxEntries must be >= 1");
    }
    this.maxEntries = maxEntries;
    this.canonicalizer = Objects.requireNonNull(canonicalizer, "canonicalizer");
  }

  /** Package-visible for tests: number of tracked counter keys (JS-SEC-030 bound). */
  int trackedCounterCount() {
    return counters.size();
  }

  @Override
  public AbuseDecision evaluate(AbuseAttemptContext context) {
    Objects.requireNonNull(context, "context");
    AbuseDecision strongest = AbuseDecision.Allow.INSTANCE;
    int strongestRank = 0;
    for (AbuseDimension dimension : AbuseDimension.values()) {
      Optional<AbuseLimitsPolicy.Limit> maybeLimit =
          policy.limit(context.attemptType(), dimension);
      if (maybeLimit.isEmpty()) {
        continue;
      }
      AbuseLimitsPolicy.Limit limit = maybeLimit.get();
      Optional<String> key = keyFor(context, dimension);
      if (key.isEmpty()) {
        continue;
      }
      int count = currentCount(
          composite(context.attemptType(), dimension, key.get()),
          limit.window(),
          context.at());
      AbuseDecision dimensionDecision = mapToDecision(limit, count, dimension);
      int rank = rank(dimensionDecision);
      if (rank > strongestRank) {
        strongest = dimensionDecision;
        strongestRank = rank;
      }
    }
    if (strongestRank > 0) {
      publish(context, strongest);
    }
    return strongest;
  }

  @Override
  public void recordOutcome(
      AbuseAttemptContext context, AttemptOutcome outcome) {
    Objects.requireNonNull(context, "context");
    Objects.requireNonNull(outcome, "outcome");
    for (AbuseDimension dimension : AbuseDimension.values()) {
      Optional<String> key = keyFor(context, dimension);
      if (key.isEmpty()) {
        continue;
      }
      String composite = composite(context.attemptType(), dimension, key.get());
      if (countsEveryAttempt(context.attemptType(), dimension)) {
        // Volume counters tick on every attempt and are not reset by a success.
        appendEvent(composite, context.at());
      } else {
        // Failure-only counters.
        if (outcome == AttemptOutcome.FAILURE) {
          appendEvent(composite, context.at());
        } else {
          // R014: a success resets the window by clearing the deque IN PLACE.
          // It must NOT remove the mapping: a concurrent appendEvent that already
          // holds this deque reference would otherwise add to an orphaned deque
          // and the failure would be lost — letting attempts slip past blockAt.
          counters.computeIfPresent(composite, (k, deque) -> {
            deque.clear();
            return deque;
          });
        }
      }
    }
  }

  private Optional<String> keyFor(
      AbuseAttemptContext context, AbuseDimension dimension) {
    return switch (dimension) {
      // JS-SEC-123 (CWE-178): one key per account, whatever the spelling.
      case USERNAME -> context.username().map(canonicalizer::canonicalize);
      case CLIENT_ADDRESS -> context.clientAddress();
      case TENANT -> Optional.of(tenantKey(context.tenant()));
      case GLOBAL -> Optional.of("*");
    };
  }

  private static String tenantKey(TenantId tenant) {
    return tenant == null ? TenantId.DEFAULT.value() : tenant.value();
  }

  private static String composite(
      AbuseAttemptType attemptType,
      AbuseDimension dimension,
      String key) {
    return attemptType.name() + "/" + dimension.name() + "/" + key;
  }

  private int currentCount(String composite, Duration window, Instant now) {
    Instant cutoff = now.minus(window);
    int[] size = {0};
    // R014: purge expired entries and read the size INSIDE compute, so the deque
    // is only ever touched while the ConcurrentHashMap holds the per-key bin lock
    // — the same discipline as appendEvent and the success-reset. No deque is ever
    // accessed through a reference that a concurrent remove could have orphaned.
    counters.computeIfPresent(composite, (k, deque) -> {
      // R039: the sliding window is the half-open interval (now-window, now] —
      // an event exactly `window` old has expired. Evict timestamps at or
      // before the cutoff (was isBefore, which kept the boundary event and made
      // the effective window one tick wider than "the last <window>").
      while (!deque.isEmpty() && !deque.peekFirst().isAfter(cutoff)) {
        deque.pollFirst();
      }
      size[0] = deque.size();
      // JS-SEC-030 (CWE-770): drop a fully-expired (now-empty) counter so the map is
      // self-reclaiming — the composite key embeds an attacker-controlled username /
      // client address. Safe: appendEvent's add is atomic inside compute, so a
      // concurrent record on this key just recreates the deque.
      return deque.isEmpty() ? null : deque;
    });
    return size[0];
  }

  private void appendEvent(String composite, Instant at) {
    enforceBound(composite);
    // R014: create-or-append in a single atomic compute. The previous
    // computeIfAbsent + synchronized(deque) left a window in which a concurrent
    // success-reset could remove the freshly created deque before the add landed,
    // losing the failure. Doing the add inside compute closes that window.
    counters.compute(composite, (k, deque) -> {
      Deque<Instant> d = (deque == null) ? new ArrayDeque<>() : deque;
      d.addLast(at);
      return d;
    });
  }

  /**
   * JS-SEC-030 (CWE-770): hard cap on the counter map. The composite key embeds an
   * attacker-controlled username / client address, and {@link #currentCount} only
   * reclaims keys that are re-evaluated — a spray of distinct keys each recorded once
   * and never re-evaluated would otherwise grow the map without limit. When a new key
   * would exceed {@code maxEntries}, evict existing counters back under the bound via a
   * safe {@code keySet().iterator().remove()}.
   *
   * <p>RF (exit-review, lockout-eviction bypass): eviction must never drop a counter
   * that is <em>currently at or over its block threshold</em>. Otherwise an attacker
   * spraying failures across ~{@code maxEntries} distinct throwaway usernames could push
   * the map to capacity and evict a victim's (or their own IP-dimension's) in-force block
   * before {@code blockAt} takes effect — turning the very map that JS-SEC-030 bounds into
   * a brute-force-lockout bypass. Actively-blocking counters are therefore skipped; if
   * <em>every</em> remaining counter is an active block (pathological), a transient soft
   * overshoot is accepted rather than resetting a live lockout — blocks are time-bounded
   * and self-reclaim via {@link #currentCount}'s expiry purge.
   */
  private void enforceBound(String incomingKey) {
    if (counters.size() < maxEntries || counters.containsKey(incomingKey)) {
      return;
    }
    var it = counters.keySet().iterator();
    while (counters.size() >= maxEntries && it.hasNext()) {
      String victim = it.next();
      if (victim.equals(incomingKey) || isActivelyBlocking(victim)) {
        continue; // never evict the incoming key or an in-force block
      }
      it.remove();
    }
    // Soft bound: if the loop protected every non-incoming counter (all active
    // blocks), the map may briefly exceed maxEntries. That is the safe trade —
    // preserving lockouts wins over the DoS-mitigation cap, and the overshoot is
    // transient because blocks expire and are reclaimed on the next evaluation.
  }

  /**
   * True when {@code composite} names a failure/volume counter that has reached its
   * configured {@code blockAt} threshold and is therefore an in-force block. The
   * composite key is {@code attemptType/dimension/key}; only the first two segments are
   * parsed (the trailing key may itself contain {@code '/'}). An unparseable segment,
   * an absent limit, or a non-positive {@code blockAt} means "not protected" — eviction
   * proceeds. A stale over-count (expired timestamps not yet purged) only makes this more
   * conservative, which is safe.
   */
  private boolean isActivelyBlocking(String composite) {
    int firstSlash = composite.indexOf('/');
    int secondSlash = firstSlash < 0 ? -1 : composite.indexOf('/', firstSlash + 1);
    if (firstSlash < 0 || secondSlash < 0) {
      return false;
    }
    AbuseAttemptType attemptType;
    AbuseDimension dimension;
    try {
      attemptType = AbuseAttemptType.valueOf(composite.substring(0, firstSlash));
      dimension = AbuseDimension.valueOf(composite.substring(firstSlash + 1, secondSlash));
    } catch (IllegalArgumentException notParseable) {
      return false;
    }
    Optional<AbuseLimitsPolicy.Limit> maybeLimit = policy.limit(attemptType, dimension);
    if (maybeLimit.isEmpty() || maybeLimit.get().blockAt() <= 0) {
      return false;
    }
    Deque<Instant> deque = counters.get(composite);
    return deque != null && deque.size() >= maybeLimit.get().blockAt();
  }

  private static AbuseDecision mapToDecision(
      AbuseLimitsPolicy.Limit limit, int count, AbuseDimension dimension) {
    if (limit.blockAt() > 0 && count >= limit.blockAt()) {
      return new AbuseDecision.Block(limit.blockLen(), dimension);
    }
    if (limit.stepUpAt() > 0 && count >= limit.stepUpAt()) {
      return new AbuseDecision.RequireAdditionalCheck(dimension);
    }
    if (limit.delayAt() > 0 && count >= limit.delayAt()) {
      return new AbuseDecision.Delay(limit.delayLen(), dimension);
    }
    return AbuseDecision.Allow.INSTANCE;
  }

  /**
   * Numeric rank so a decision evaluated across dimensions picks the
   * strongest reaction.
   */
  private static int rank(AbuseDecision decision) {
    if (decision instanceof AbuseDecision.Allow) {
      return 0;
    }
    if (decision instanceof AbuseDecision.Delay) {
      return 1;
    }
    if (decision instanceof AbuseDecision.RequireAdditionalCheck) {
      return 2;
    }
    return 3; // Block
  }

  private void publish(AbuseAttemptContext context, AbuseDecision decision) {
    AbuseDimension dim = dimensionOf(decision);
    if (dim == null) {
      return;
    }
    AbuseLimitsPolicy.Limit limit = policy.limit(context.attemptType(), dim)
        .orElse(null);
    if (limit == null) {
      return;
    }
    String subjectId = context.username().orElse(
        context.clientAddress().orElse("anonymous"));
    int events = currentCount(composite(
        context.attemptType(), dim,
        keyFor(context, dim).orElse("?")), limit.window(), context.at());
    try {
      int threshold = limit.blockAt() > 0 ? limit.blockAt() : limit.delayAt();
      if (threshold <= 0) {
        return;
      }
      auditService.publish(new RateLimitExceeded(
          context.at(),
          context.attemptType().name() + "/" + dim.name(),
          subjectId,
          threshold,
          limit.window(),
          events));
    } catch (RuntimeException ignored) {
      // Audit failure must not block the decision (CWE-778).
    }
  }

  private static AbuseDimension dimensionOf(AbuseDecision decision) {
    if (decision instanceof AbuseDecision.Delay d) {
      return d.dimension();
    }
    if (decision instanceof AbuseDecision.RequireAdditionalCheck r) {
      return r.dimension();
    }
    if (decision instanceof AbuseDecision.Block b) {
      return b.dimension();
    }
    return null;
  }
}
