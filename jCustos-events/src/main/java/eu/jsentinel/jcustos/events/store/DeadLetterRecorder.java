package eu.jsentinel.jcustos.events.store;

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
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.bus.EventBusObservabilityPublisher;
import eu.jsentinel.jcustos.events.bus.SelfObservabilityEvents;
import eu.jsentinel.jcustos.events.types.DeadLetteredEvent;

import java.time.Instant;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * The canonical dead-letter emission point: stores a rejected envelope as a
 * {@link JCustosEventDeadLetter} and emits the matching
 * {@link DeadLetteredEvent} through the observability publisher.
 *
 * <p>Store and emission are strictly ordered: the store write comes first and
 * a store failure <em>propagates</em> — losing a dead letter must be visible
 * to the caller. The subsequent event emission is best-effort: an emission
 * failure is logged ({@code events/deadletter-event-failed}) and never masks
 * a successful store.
 *
 * <p>The store is asked to fold an identical open rejection
 * ({@link JCustosEventDeadLetterStore#storeOrMerge}); a repeat produces
 * neither a second record nor a second event (JS-SEC-109). An envelope that
 * was never authenticated is still stored as it arrived — that is the forensic
 * purpose — but the event about it does not adopt its tenant or its
 * full-length id (JS-SEC-104).
 *
 * <p>Routing policy — <em>which</em> rejections are dead-lettered at all — is
 * deliberately out of scope here; callers decide what to route into
 * {@link #record(SignedJCustosEventEnvelope, RejectionReason, boolean)}.
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class DeadLetterRecorder implements HasLogger {

  private final JCustosEventDeadLetterStore store;
  private final EventBusObservabilityPublisher observability;
  private final Supplier<Instant> clock;

  public DeadLetterRecorder(JCustosEventDeadLetterStore store,
      EventBusObservabilityPublisher observability, Supplier<Instant> clock) {
    this.store = Objects.requireNonNull(store, "store");
    this.observability = Objects.requireNonNull(observability, "observability");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Records a rejected envelope: builds the dead letter, stores it, then
   * emits a {@link DeadLetteredEvent} (reason string is
   * {@link RejectionReason#name()}). Whether the envelope counts as
   * authenticated has to be guessed from the reason, and the reason does not
   * tell: {@code PRODUCER_NOT_ALLOWED} stands both for an authenticated
   * producer outside the policy and for a key that is not bound to the
   * producer the envelope claims, whose tenant and id are unverified. The
   * guess therefore fails closed — {@code INVALID_SIGNATURE},
   * {@code UNKNOWN_KEY}, {@code KEY_REVOKED} and {@code PRODUCER_NOT_ALLOWED}
   * count as unauthenticated, so the event never adopts a tenant that may be
   * forged (since 00.84.00; before, {@code PRODUCER_NOT_ALLOWED} counted as
   * authenticated).
   *
   * @param envelope the rejected envelope
   * @param reason why it was rejected
   * @return the stored dead-letter record
   * @throws RuntimeException whatever the store throws — a failed store write
   *     is never swallowed
   * @deprecated the reason alone cannot tell whether the envelope was
   *     authenticated; use
   *     {@link #record(SignedJCustosEventEnvelope, RejectionReason, boolean)}
   *     with {@code JCustosEventVerificationResult.envelopeAuthenticated()}
   */
  @Deprecated(since = "00.84.00")
  public JCustosEventDeadLetter record(SignedJCustosEventEnvelope envelope,
      RejectionReason reason) {
    Objects.requireNonNull(reason, "reason");
    boolean authenticated = reason != RejectionReason.INVALID_SIGNATURE
        && reason != RejectionReason.UNKNOWN_KEY
        && reason != RejectionReason.KEY_REVOKED
        && reason != RejectionReason.PRODUCER_NOT_ALLOWED;
    return record(envelope, reason, authenticated);
  }

  /**
   * Records a rejected envelope: builds the dead letter, stores it — or folds
   * it into the open record of the same rejection — then emits a
   * {@link DeadLetteredEvent} for a newly stored record (reason string is
   * {@link RejectionReason#name()}).
   *
   * @param envelope the rejected envelope
   * @param reason why it was rejected
   * @param envelopeAuthenticated whether the envelope was authenticated when
   *     it was rejected
   *     ({@code JCustosEventVerificationResult.envelopeAuthenticated()}); if
   *     not, the {@link DeadLetteredEvent} is raised under
   *     {@link SelfObservabilityEvents#UNAUTHENTICATED_TENANT} with the id
   *     from {@link SelfObservabilityEvents#unverifiedId(String)}
   * @return the record that stands for the rejection — the newly stored one,
   *     or the open record this rejection repeats
   * @throws RuntimeException whatever the store throws — a failed store write
   *     is never swallowed
   * @since 00.84.00
   */
  public JCustosEventDeadLetter record(SignedJCustosEventEnvelope envelope,
      RejectionReason reason, boolean envelopeAuthenticated) {
    Objects.requireNonNull(envelope, "envelope");
    Objects.requireNonNull(reason, "reason");
    Instant now = clock.get();
    JCustosEventDeadLetter candidate = JCustosEventDeadLetter.of(envelope, reason, now);
    JCustosEventDeadLetter retained = store.storeOrMerge(candidate);
    if (!retained.id().equals(candidate.id())) {
      // A repeat of an open rejection: already stored, already announced.
      return retained;
    }
    String reportedId = envelopeAuthenticated
        ? envelope.envelopeId().value()
        : SelfObservabilityEvents.unverifiedId(envelope.envelopeId().value());
    try {
      EventMetadata metadata = EventMetadata.create(
          envelopeAuthenticated
              ? envelope.tenantId()
              : SelfObservabilityEvents.UNAUTHENTICATED_TENANT,
          JCustosEvent.SYSTEM_SUBJECT, now, JCustosEventSeverity.ERROR);
      observability.publishObservability(new DeadLetteredEvent(metadata,
          reportedId, reason.name()));
    } catch (RuntimeException failure) {
      logger().warn("events/deadletter-event-failed: DeadLettered emission failed for {} ({})",
          LogFieldScrubber.scrub(reportedId), failure.toString());
    }
    return retained;
  }
}
