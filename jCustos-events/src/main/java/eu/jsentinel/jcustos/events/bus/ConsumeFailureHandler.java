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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.store.DeadLetterRecorder;
import eu.jsentinel.jcustos.events.store.JCustosEventDeadLetterStore;
import eu.jsentinel.jcustos.events.store.RejectionReason;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

/**
 * The ONE place a consume-side verification failure becomes observable
 * (Konzept goal 10 subset: Signature/Key/Replay/Sequence → Reject + Event
 * + Metrik): publishes the P004 self-observability event (the metric seam —
 * the monitoring bridge counts the event stream, so no
 * events→monitoring dependency ever exists), optionally dead-letters per
 * {@link ConsumeFailurePolicy}, and writes ONE operator-facing log line
 * with a stable {@code events/...} code and an actionable second sentence.
 * <p>
 * Total and never-throwing (audit-sink posture): a failing observability
 * publisher or dead-letter store is caught and logged, never propagated
 * into the transport. Misconfiguration fails at WIRING time: a policy that
 * dead-letters anything without a store is rejected in the constructor —
 * operators see it at startup, not at the first attack.
 * <p>
 * Failures of envelopes that were never authenticated are throttled
 * (JS-SEC-104, CWE-770): no key is needed to cause an unknown-key or
 * invalid-signature rejection, so without a limit every caller of the ingest
 * path could raise an alert and an audit entry per request. Within one
 * window at most {@link #DEFAULT_UNAUTHENTICATED_EVENT_LIMIT} such failures
 * produce their event and their log line; the rest are counted
 * ({@link #suppressedUnauthenticatedCount()}) and summarised in one
 * {@code events/unauthenticated-rejections-throttled} line. The limit is
 * global — this handler has no trustworthy notion of a source; a transport
 * that knows the authenticated caller should throttle per caller before the
 * envelope gets here. Failures of authenticated envelopes are never throttled.
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class ConsumeFailureHandler implements HasLogger {

  static final String CODE_MISCONFIGURED = "events/consume-policy-misconfigured";

  /**
   * Default number of failures of unauthenticated envelopes that are reported
   * (event and log line) per {@link #DEFAULT_UNAUTHENTICATED_EVENT_WINDOW}.
   *
   * @since 00.84.00
   */
  public static final int DEFAULT_UNAUTHENTICATED_EVENT_LIMIT = 20;

  /**
   * Default length of the throttling window for failures of unauthenticated
   * envelopes.
   *
   * @since 00.84.00
   */
  public static final Duration DEFAULT_UNAUTHENTICATED_EVENT_WINDOW = Duration.ofMinutes(1);

  /** Longest envelope, producer or tenant id written to an operator log line. */
  static final int MAX_LOGGED_ID_LENGTH = 128;

  private final ConsumeFailurePolicy policy;
  private final DeadLetterRecorder deadLetterRecorder;
  private final EventBusObservabilityPublisher observability;
  private final Supplier<Instant> clock;
  private final int unauthenticatedEventLimit;
  private final Duration unauthenticatedEventWindow;
  private final AtomicLong suppressedUnauthenticated = new AtomicLong();
  // Guarded by `this`: the current throttling window.
  private Instant windowStart;
  private int reportedInWindow;
  private long suppressedInWindow;

  /**
   * @param policy          reject-vs-dead-letter per failure kind
   * @param deadLetterStore the forensic store; may be {@code null} ONLY when
   *                        the policy never dead-letters
   * @param observability   the self-observability publisher (typically the
   *                        bus itself); {@code null} skips events
   * @param clock           the failure-event clock
   */
  public ConsumeFailureHandler(ConsumeFailurePolicy policy,
      JCustosEventDeadLetterStore deadLetterStore,
      EventBusObservabilityPublisher observability,
      Supplier<Instant> clock) {
    this(policy, deadLetterStore, observability, clock,
        DEFAULT_UNAUTHENTICATED_EVENT_LIMIT, DEFAULT_UNAUTHENTICATED_EVENT_WINDOW);
  }

  /**
   * @param policy          reject-vs-dead-letter per failure kind
   * @param deadLetterStore the forensic store; may be {@code null} ONLY when
   *                        the policy never dead-letters
   * @param observability   the self-observability publisher (typically the
   *                        bus itself); {@code null} skips events
   * @param clock           the failure-event clock
   * @param unauthenticatedEventLimit  how many failures of unauthenticated
   *                        envelopes are reported per window; {@code 0}
   *                        reports none of them
   * @param unauthenticatedEventWindow the length of the throttling window;
   *                        positive
   * @since 00.84.00
   */
  public ConsumeFailureHandler(ConsumeFailurePolicy policy,
      JCustosEventDeadLetterStore deadLetterStore,
      EventBusObservabilityPublisher observability,
      Supplier<Instant> clock,
      int unauthenticatedEventLimit,
      Duration unauthenticatedEventWindow) {
    this.policy = Objects.requireNonNull(policy, "policy");
    this.clock = Objects.requireNonNull(clock, "clock");
    if (unauthenticatedEventLimit < 0) {
      throw new IllegalArgumentException(
          "unauthenticatedEventLimit must be >= 0, was " + unauthenticatedEventLimit);
    }
    Objects.requireNonNull(unauthenticatedEventWindow, "unauthenticatedEventWindow");
    if (unauthenticatedEventWindow.isZero() || unauthenticatedEventWindow.isNegative()) {
      throw new IllegalArgumentException("unauthenticatedEventWindow must be positive");
    }
    this.unauthenticatedEventLimit = unauthenticatedEventLimit;
    this.unauthenticatedEventWindow = unauthenticatedEventWindow;
    this.observability = observability == null
        ? EventBusObservabilityPublisher.discard()
        : observability;
    if (deadLetterStore == null) {
      if (policy.deadLettersAnything()) {
        throw new IllegalArgumentException(CODE_MISCONFIGURED
            + ": the policy dead-letters at least one failure kind but no"
            + " dead-letter store is wired — add a store or use"
            + " ConsumeFailurePolicy.strict()");
      }
      this.deadLetterRecorder = null;
    } else {
      this.deadLetterRecorder = new DeadLetterRecorder(deadLetterStore,
          this.observability, clock);
    }
  }

  /**
   * Handles one verification failure — event, optional dead letter,
   * operator log. Never throws.
   *
   * @param envelope the rejected envelope
   * @param failure  the non-{@code Valid} verification result
   * @return the action taken
   */
  public ConsumeFailureAction handle(SignedJCustosEventEnvelope envelope,
      JCustosEventVerificationResult failure) {
    Objects.requireNonNull(envelope, "envelope");
    Objects.requireNonNull(failure, "failure");
    boolean authenticated = failure.envelopeAuthenticated();
    if (authenticated || admitUnauthenticated()) {
      try {
        SelfObservabilityEvents.fromVerification(failure, envelope, clock.get())
            .ifPresent(observability::publishObservability);
      } catch (RuntimeException eventFailure) {
        logger().warn("events/consume-observability-failed: {}",
            eventFailure.getClass().getSimpleName());
      }
      logFailure(envelope, failure);
    }
    ConsumeFailureAction action = policy.actionFor(failure);
    if (action == ConsumeFailureAction.REJECT_AND_DEAD_LETTER
        && deadLetterRecorder != null) {
      try {
        deadLetterRecorder.record(envelope, rejectionReason(failure), authenticated);
      } catch (RuntimeException storeFailure) {
        // The handler must stay total toward the transport; the loss is
        // itself security-relevant, so it is logged loudly.
        logger().warn("events/dead-letter-failed: {} while dead-lettering envelope {}",
            storeFailure.getClass().getSimpleName(), loggable(envelope.envelopeId().value()));
      }
    }
    return action;
  }

  /**
   * @return how many failures of unauthenticated envelopes were not reported
   *     (no event, no log line) because the limit of their window was used
   *     up, over this handler's lifetime
   * @since 00.84.00
   */
  public long suppressedUnauthenticatedCount() {
    return suppressedUnauthenticated.get();
  }

  // Fixed window on the handler's clock. Returns true while the window has
  // budget left; the first refusal of a window is announced, the size of the
  // suppressed remainder is logged when the next window opens.
  private synchronized boolean admitUnauthenticated() {
    Instant now;
    try {
      now = clock.get();
    } catch (RuntimeException clockFailure) {
      return false;
    }
    if (windowStart == null || now.isBefore(windowStart)
        || !now.isBefore(windowStart.plus(unauthenticatedEventWindow))) {
      if (suppressedInWindow > 0) {
        logger().warn("events/unauthenticated-rejections-throttled: {} further rejections of"
                + " unauthenticated envelopes were not reported in the window that started"
                + " at {}.", suppressedInWindow, windowStart);
      }
      windowStart = now;
      reportedInWindow = 0;
      suppressedInWindow = 0;
    }
    if (reportedInWindow < unauthenticatedEventLimit) {
      reportedInWindow++;
      return true;
    }
    suppressedUnauthenticated.incrementAndGet();
    if (suppressedInWindow++ == 0) {
      logger().warn("events/unauthenticated-rejections-throttled: more than {} envelopes"
              + " without a valid signature under a bound key were rejected within {} —"
              + " further such rejections are counted but neither logged nor published"
              + " as events until the window ends. Somebody is sending junk to the ingest"
              + " path; check who holds access to it.",
          unauthenticatedEventLimit, unauthenticatedEventWindow);
    }
    return false;
  }

  // CWE-117 / CWE-770: every id in an operator log line is scrubbed and
  // clipped — an envelope id is only bounded by the transport's body limit.
  private static String loggable(String id) {
    String scrubbed = LogFieldScrubber.scrub(id);
    if (scrubbed.length() <= MAX_LOGGED_ID_LENGTH) {
      return scrubbed;
    }
    // never cut a surrogate pair in half
    int end = Character.isHighSurrogate(scrubbed.charAt(MAX_LOGGED_ID_LENGTH - 1))
        ? MAX_LOGGED_ID_LENGTH - 1
        : MAX_LOGGED_ID_LENGTH;
    return scrubbed.substring(0, end) + "...";
  }

  private void logFailure(SignedJCustosEventEnvelope envelope,
      JCustosEventVerificationResult failure) {
    String envelopeId = loggable(envelope.envelopeId().value());
    String producer = loggable(envelope.producerId().value());
    String tenant = loggable(envelope.tenantId().value());
    switch (failure) {
      case JCustosEventVerificationResult.Valid ignored ->
          throw new IllegalArgumentException("Valid is not a failure");
      case JCustosEventVerificationResult.InvalidSignature ignored ->
          logger().warn("events/signature-invalid: envelope {} from producer {} (tenant {})"
                  + " rejected. Check that the producer signs with the registered key"
                  + " material and that both sides run the same signature-base version.",
              envelopeId, producer, tenant);
      case JCustosEventVerificationResult.PayloadHashMismatch ignored ->
          logger().warn("events/signature-invalid: envelope {} rejected — the payload does"
                  + " not match its signed hash. The payload was altered after signing;"
                  + " investigate the transport path of producer {}.",
              envelopeId, producer);
      case JCustosEventVerificationResult.UnknownKey unknown ->
          logger().warn("events/unknown-key: envelope {} rejected — key id '{}' is not"
                  + " resolvable. Register the producer's public key with the"
                  + " verification key resolver, or update the producer after a rotation.",
              envelopeId, loggable(unknown.keyId().value()));
      case JCustosEventVerificationResult.KeyRevoked revoked ->
          logger().warn("events/key-revoked: envelope {} rejected — key '{}' is revoked."
                  + " Rotate the producer to the current signing key; envelopes under a"
                  + " revoked key are permanently rejected.",
              envelopeId, loggable(revoked.keyId().value()));
      case JCustosEventVerificationResult.KeyExpired expired ->
          logger().warn("events/key-expired: envelope {} rejected — key '{}' is expired."
                  + " Rotate the producer to the current signing key.",
              envelopeId, loggable(expired.keyId().value()));
      case JCustosEventVerificationResult.Expired expired ->
          logger().warn("events/envelope-expired: envelope {} rejected — it expired at {}."
                  + " Check producer/consumer clock drift and the acceptance window.",
              envelopeId, expired.expiresAt());
      case JCustosEventVerificationResult.ReplayDetected ignored ->
          logger().warn("events/replay-detected: envelope {} was already consumed —"
                  + " possible replay attack or duplicate delivery. Investigate producer"
                  + " {} and the transport path; the envelope was rejected.",
              envelopeId, producer);
      case JCustosEventVerificationResult.SequenceViolation violation ->
          logger().warn("events/sequence-violation: producer {} (tenant {}) sent sequence"
                  + " {} but {} was expected — possible loss, reordering or injection."
                  + " The envelope was rejected{}.",
              producer, tenant, violation.actual().value(), violation.expected().value(),
              policy.deadLettersAnything() ? " (see the dead-letter store)" : "");
      case JCustosEventVerificationResult.ProducerNotAllowed ignored ->
          logger().warn("events/producer-not-allowed: envelope {} rejected — producer {}"
                  + " is not allow-listed for this event type on tenant {}. Extend the"
                  + " producer policy deliberately if this producer is legitimate.",
              envelopeId, producer, tenant);
      case JCustosEventVerificationResult.KeyNotAuthorizedForProducer unbound ->
          logger().warn("events/key-not-authorized: envelope {} rejected — key '{}' is"
                  + " trusted but not bound to producer {}, which the envelope claims."
                  + " A key holder may be impersonating another producer; if the producer"
                  + " legitimately signs with this key, bind the key to it in the"
                  + " verification key resolver.",
              envelopeId, loggable(unbound.keyId().value()), producer);
      case JCustosEventVerificationResult.PayloadMetadataMismatch mismatch ->
          logger().warn("events/payload-metadata-mismatch: envelope {} from producer {}"
                  + " (tenant {}) rejected — its payload does not match the signed"
                  + " envelope in '{}'. The producer signed a payload that describes a"
                  + " different event than the envelope announces; investigate the"
                  + " producer.",
              envelopeId, producer, tenant, loggable(mismatch.field()));
    }
  }

  private static RejectionReason rejectionReason(JCustosEventVerificationResult failure) {
    return switch (failure) {
      case JCustosEventVerificationResult.Valid ignored ->
          throw new IllegalArgumentException("Valid is not a failure");
      case JCustosEventVerificationResult.InvalidSignature ignored ->
          RejectionReason.INVALID_SIGNATURE;
      case JCustosEventVerificationResult.PayloadHashMismatch ignored ->
          RejectionReason.INVALID_SIGNATURE;
      case JCustosEventVerificationResult.UnknownKey ignored ->
          RejectionReason.UNKNOWN_KEY;
      case JCustosEventVerificationResult.KeyRevoked ignored ->
          RejectionReason.KEY_REVOKED;
      // The reason enum has no KEY_EXPIRED — an expired key is unusable like
      // a revoked one; the log line keeps the precise cause.
      case JCustosEventVerificationResult.KeyExpired ignored ->
          RejectionReason.KEY_REVOKED;
      case JCustosEventVerificationResult.Expired ignored ->
          RejectionReason.EXPIRED;
      case JCustosEventVerificationResult.ReplayDetected ignored ->
          RejectionReason.REPLAY_DETECTED;
      case JCustosEventVerificationResult.SequenceViolation ignored ->
          RejectionReason.SEQUENCE_VIOLATION;
      case JCustosEventVerificationResult.ProducerNotAllowed ignored ->
          RejectionReason.PRODUCER_NOT_ALLOWED;
      // The reason enum is part of persisted dead-letter records and is not
      // extended: a key that may not sign for the claimed producer is a
      // producer that is not allowed, a payload that contradicts its envelope
      // is a payload that does not deserialise into the announced event. The
      // log line keeps the precise cause.
      case JCustosEventVerificationResult.KeyNotAuthorizedForProducer ignored ->
          RejectionReason.PRODUCER_NOT_ALLOWED;
      case JCustosEventVerificationResult.PayloadMetadataMismatch ignored ->
          RejectionReason.DESERIALIZATION_ERROR;
    };
  }
}
