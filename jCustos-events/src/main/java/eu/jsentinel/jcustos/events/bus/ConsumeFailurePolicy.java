package eu.jsentinel.jcustos.events.bus;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

/**
 * Maps each consume-side verification failure kind to its
 * {@link ConsumeFailureAction} — the configuration object of the V00.80
 * strict-mode wiring (Konzept goal 10 subset: "Sequenzverletzung fuehrt zu
 * Reject oder Dead Letter").
 * <p>
 * Two canned profiles:
 * <ul>
 *   <li>{@link #strict()} — everything {@code REJECT}, fail-closed: zero
 *       attacker-controlled payloads are retained; dead-lettering is an
 *       explicit operator opt-in.</li>
 *   <li>{@link #operationalDefaults()} — sequence violations, expired
 *       envelopes and envelopes whose acceptance window exceeds the
 *       consumer's maximum are additionally dead-lettered (they are the
 *       kinds an operator typically must review: loss/reordering, and clock
 *       drift or a producer's time to live); cryptographic failures stay
 *       reject-only.</li>
 * </ul>
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class ConsumeFailurePolicy {

  /**
   * The consume-side failure kinds — one constant per non-{@code Valid}
   * variant of {@link JCustosEventVerificationResult}.
   */
  public enum FailureKind {
    INVALID_SIGNATURE,
    PAYLOAD_HASH_MISMATCH,
    UNKNOWN_KEY,
    KEY_REVOKED,
    KEY_EXPIRED,
    EXPIRED,
    REPLAY_DETECTED,
    SEQUENCE_VIOLATION,
    PRODUCER_NOT_ALLOWED,
    /** @since 00.84.00 */
    KEY_NOT_AUTHORIZED_FOR_PRODUCER,
    /** @since 00.84.00 */
    PAYLOAD_METADATA_MISMATCH,
    /** @since 00.84.00 */
    ACCEPTANCE_WINDOW_EXCEEDED;

    static FailureKind of(JCustosEventVerificationResult failure) {
      return switch (failure) {
        case JCustosEventVerificationResult.Valid ignored ->
            throw new IllegalArgumentException("Valid is not a failure");
        case JCustosEventVerificationResult.InvalidSignature ignored -> INVALID_SIGNATURE;
        case JCustosEventVerificationResult.PayloadHashMismatch ignored -> PAYLOAD_HASH_MISMATCH;
        case JCustosEventVerificationResult.UnknownKey ignored -> UNKNOWN_KEY;
        case JCustosEventVerificationResult.KeyRevoked ignored -> KEY_REVOKED;
        case JCustosEventVerificationResult.KeyExpired ignored -> KEY_EXPIRED;
        case JCustosEventVerificationResult.Expired ignored -> EXPIRED;
        case JCustosEventVerificationResult.ReplayDetected ignored -> REPLAY_DETECTED;
        case JCustosEventVerificationResult.SequenceViolation ignored -> SEQUENCE_VIOLATION;
        case JCustosEventVerificationResult.ProducerNotAllowed ignored -> PRODUCER_NOT_ALLOWED;
        case JCustosEventVerificationResult.KeyNotAuthorizedForProducer ignored ->
            KEY_NOT_AUTHORIZED_FOR_PRODUCER;
        case JCustosEventVerificationResult.PayloadMetadataMismatch ignored ->
            PAYLOAD_METADATA_MISMATCH;
        case JCustosEventVerificationResult.AcceptanceWindowExceeded ignored ->
            ACCEPTANCE_WINDOW_EXCEEDED;
      };
    }
  }

  private final Map<FailureKind, ConsumeFailureAction> actions;

  private ConsumeFailurePolicy(Map<FailureKind, ConsumeFailureAction> actions) {
    this.actions = actions;
  }

  /** @return the fail-closed profile: every kind {@code REJECT} */
  public static ConsumeFailurePolicy strict() {
    EnumMap<FailureKind, ConsumeFailureAction> actions = new EnumMap<>(FailureKind.class);
    for (FailureKind kind : FailureKind.values()) {
      actions.put(kind, ConsumeFailureAction.REJECT);
    }
    return new ConsumeFailurePolicy(actions);
  }

  /**
   * @return the operational profile: {@code SEQUENCE_VIOLATION},
   *     {@code EXPIRED} and {@code ACCEPTANCE_WINDOW_EXCEEDED} (since
   *     00.84.00) dead-letter for operator review, everything else rejects
   *     only
   */
  public static ConsumeFailurePolicy operationalDefaults() {
    EnumMap<FailureKind, ConsumeFailureAction> actions = new EnumMap<>(FailureKind.class);
    for (FailureKind kind : FailureKind.values()) {
      actions.put(kind, ConsumeFailureAction.REJECT);
    }
    actions.put(FailureKind.SEQUENCE_VIOLATION, ConsumeFailureAction.REJECT_AND_DEAD_LETTER);
    actions.put(FailureKind.EXPIRED, ConsumeFailureAction.REJECT_AND_DEAD_LETTER);
    // ER27: the other time-window rejection. Like EXPIRED it points at clock
    // drift or a producer's time to live — or at a signing key in hands that
    // chose the window themselves; the record is the trace.
    actions.put(FailureKind.ACCEPTANCE_WINDOW_EXCEEDED,
        ConsumeFailureAction.REJECT_AND_DEAD_LETTER);
    return new ConsumeFailurePolicy(actions);
  }

  /** @return a builder starting from {@link #strict()} */
  public static Builder custom() {
    return new Builder();
  }

  /**
   * @param failure a non-{@code Valid} verification result
   * @return the configured action for its kind
   * @throws IllegalArgumentException for {@code Valid}
   */
  public ConsumeFailureAction actionFor(JCustosEventVerificationResult failure) {
    Objects.requireNonNull(failure, "failure");
    return actions.get(FailureKind.of(failure));
  }

  /** @return {@code true} when any kind is configured to dead-letter */
  public boolean deadLettersAnything() {
    return actions.containsValue(ConsumeFailureAction.REJECT_AND_DEAD_LETTER);
  }

  /** Per-kind overrides on top of the fail-closed base. */
  public static final class Builder {

    private final EnumMap<FailureKind, ConsumeFailureAction> actions;

    private Builder() {
      this.actions = new EnumMap<>(FailureKind.class);
      for (FailureKind kind : FailureKind.values()) {
        actions.put(kind, ConsumeFailureAction.REJECT);
      }
    }

    public Builder with(FailureKind kind, ConsumeFailureAction action) {
      actions.put(Objects.requireNonNull(kind, "kind"),
          Objects.requireNonNull(action, "action"));
      return this;
    }

    public ConsumeFailurePolicy build() {
      return new ConsumeFailurePolicy(new EnumMap<>(actions));
    }
  }
}
