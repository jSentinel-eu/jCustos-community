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

import java.time.Duration;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

/**
 * Per-dimension and per-attempt-type limits consumed by
 * {@link InMemoryAbuseDetectionService}.
 *
 * <p>The model is intentionally simple: each
 * {@code (AbuseAttemptType, AbuseDimension)} key carries a sliding
 * window of length {@code window} and three escalating thresholds —
 * {@code delayAt}, {@code stepUpAt}, {@code blockAt} — that map onto
 * {@link AbuseDecision.Delay}, {@link AbuseDecision.RequireAdditionalCheck}
 * and {@link AbuseDecision.Block} respectively.</p>
 *
 * <p>What a threshold counts depends on the key (JS-SEC-121, CWE-799):</p>
 * <ul>
 *   <li><em>Failure counters</em> — {@code USERNAME} for {@code LOGIN},
 *       {@code PASSWORD_CHANGE} and {@code RESET_CONSUME}: the thresholds
 *       count failed attempts in the window, and a successful attempt
 *       clears the counter.</li>
 *   <li><em>Volume counters</em> — {@code CLIENT_ADDRESS}, {@code TENANT}
 *       and {@code GLOBAL} for every attempt type, and {@code USERNAME} for
 *       {@code RESET_REQUEST}: the thresholds count every attempt in the
 *       window regardless of its outcome, and a success resets nothing. A
 *       reset request that was accepted is a success, so only a volume
 *       counter can limit how many links are sent to one account.</li>
 * </ul>
 */
public final class AbuseLimitsPolicy {

  /**
   * Single sliding-window limit definition.
   *
   * <p>The three thresholds are <em>event counts within the window</em>.
   * For a failure counter an event is a failed attempt; for a volume
   * counter it is any attempt, whatever its outcome — see the class
   * comment for which {@code (AbuseAttemptType, AbuseDimension)} key is
   * which. In particular the limit of {@code RESET_REQUEST / USERNAME}
   * bounds the number of reset requests for one account, accepted ones
   * included (JS-SEC-121, CWE-799).</p>
   *
   * @param window    sliding-window length
   * @param delayAt   event count at which {@link AbuseDecision.Delay}
   *                  kicks in, or 0 to disable the delay step
   * @param stepUpAt  event count at which
   *                  {@link AbuseDecision.RequireAdditionalCheck}
   *                  kicks in, or 0 to disable
   * @param blockAt   event count at which {@link AbuseDecision.Block}
   *                  kicks in, or 0 to disable
   * @param delayLen  duration returned with {@link AbuseDecision.Delay}
   * @param blockLen  duration returned with {@link AbuseDecision.Block}
   */
  public record Limit(
      Duration window,
      int delayAt,
      int stepUpAt,
      int blockAt,
      Duration delayLen,
      Duration blockLen
  ) {

    public Limit {
      Objects.requireNonNull(window, "window");
      if (window.isNegative() || window.isZero()) {
        throw new IllegalArgumentException("window must be positive");
      }
      if (delayAt < 0 || stepUpAt < 0 || blockAt < 0) {
        throw new IllegalArgumentException("thresholds must be >= 0");
      }
      Objects.requireNonNull(delayLen, "delayLen");
      Objects.requireNonNull(blockLen, "blockLen");
    }
  }

  private final Map<AbuseAttemptType, Map<AbuseDimension, Limit>> limits;

  private AbuseLimitsPolicy(
      Map<AbuseAttemptType, Map<AbuseDimension, Limit>> limits) {
    this.limits = limits;
  }

  public java.util.Optional<Limit> limit(
      AbuseAttemptType attemptType, AbuseDimension dimension) {
    Map<AbuseDimension, Limit> byDim = limits.get(attemptType);
    if (byDim == null) {
      return java.util.Optional.empty();
    }
    return java.util.Optional.ofNullable(byDim.get(dimension));
  }

  public static Builder builder() {
    return new Builder();
  }

  /**
   * Sensible default policy: 5/10/15 failures per username per
   * 15 minutes for LOGIN; 30 / 60 / 120 per client address per hour
   * (volume counter); for RESET_REQUEST a delay from the 3rd and a block
   * from the 6th request per username per hour and 10 / 30 per client
   * address per hour, both volume counters that count accepted requests
   * too (JS-SEC-121); no step-up for the reset and change flows.
   */
  public static AbuseLimitsPolicy defaults() {
    Duration loginWindow = Duration.ofMinutes(15);
    Duration clientWindow = Duration.ofHours(1);
    return builder()
        .with(AbuseAttemptType.LOGIN, AbuseDimension.USERNAME, new Limit(
            loginWindow, 5, 10, 15,
            Duration.ofSeconds(1), Duration.ofMinutes(15)))
        .with(AbuseAttemptType.LOGIN, AbuseDimension.CLIENT_ADDRESS, new Limit(
            clientWindow, 30, 60, 120,
            Duration.ofSeconds(1), Duration.ofMinutes(30)))
        .with(AbuseAttemptType.RESET_REQUEST, AbuseDimension.USERNAME, new Limit(
            Duration.ofHours(1), 3, 0, 6,
            Duration.ofSeconds(1), Duration.ofHours(1)))
        .with(AbuseAttemptType.RESET_REQUEST, AbuseDimension.CLIENT_ADDRESS, new Limit(
            Duration.ofHours(1), 10, 0, 30,
            Duration.ofSeconds(1), Duration.ofHours(1)))
        .with(AbuseAttemptType.RESET_CONSUME, AbuseDimension.CLIENT_ADDRESS, new Limit(
            Duration.ofMinutes(15), 10, 0, 30,
            Duration.ofSeconds(1), Duration.ofMinutes(30)))
        .with(AbuseAttemptType.PASSWORD_CHANGE, AbuseDimension.USERNAME, new Limit(
            Duration.ofMinutes(15), 3, 0, 6,
            Duration.ofSeconds(1), Duration.ofMinutes(15)))
        .build();
  }

  public static final class Builder {

    private final Map<AbuseAttemptType, Map<AbuseDimension, Limit>> map =
        new EnumMap<>(AbuseAttemptType.class);

    private Builder() { }

    public Builder with(
        AbuseAttemptType attemptType,
        AbuseDimension dimension,
        Limit limit) {
      Objects.requireNonNull(attemptType, "attemptType");
      Objects.requireNonNull(dimension, "dimension");
      Objects.requireNonNull(limit, "limit");
      map.computeIfAbsent(attemptType, k -> new EnumMap<>(AbuseDimension.class))
          .put(dimension, limit);
      return this;
    }

    public AbuseLimitsPolicy build() {
      Map<AbuseAttemptType, Map<AbuseDimension, Limit>> copy =
          new EnumMap<>(AbuseAttemptType.class);
      for (var entry : map.entrySet()) {
        copy.put(entry.getKey(), Collections.unmodifiableMap(
            new EnumMap<>(entry.getValue())));
      }
      return new AbuseLimitsPolicy(Collections.unmodifiableMap(copy));
    }
  }
}
