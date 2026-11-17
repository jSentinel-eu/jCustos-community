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
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventSequence;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.api.PayloadContentType;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.codec.CanonicalJCustosEventPayload;
import eu.jsentinel.jcustos.events.codec.CanonicalJsonPayloadCodec;
import eu.jsentinel.jcustos.events.codec.PayloadCodec;
import eu.jsentinel.jcustos.events.keys.JCustosEventVerificationKeyResolver;
import eu.jsentinel.jcustos.events.keys.KeyStatus;
import eu.jsentinel.jcustos.events.producer.JCustosEventProducerPolicy;
import eu.jsentinel.jcustos.events.replay.JCustosEventReplayStore;
import eu.jsentinel.jcustos.events.sequence.JCustosEventSequenceStore;
import eu.jsentinel.jcustos.events.sequence.SequenceDecision;
import eu.jsentinel.jcustos.events.sequence.SequenceState;
import eu.jsentinel.jcustos.events.sequence.SequenceValidator;
import eu.jsentinel.jcustos.events.sequence.SequenceViolationStrategy;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithm;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithms;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The consume pipeline (Konzept §849-§871): verifies an incoming envelope and
 * returns a differentiated {@link JCustosEventVerificationResult}. Stages run
 * as read-only gates first — resolve key, check key status, check payload hash,
 * verify signature, check the key-to-producer binding, check time window,
 * replay {@code hasSeen}, sequence decision, producer policy, payload metadata
 * — and only when every gate passes are the two side effects committed
 * (sequence compare-and-advance first, then replay {@code markSeen}). An
 * envelope is {@link JCustosEventVerificationResult.Valid} only when every gate
 * passes.
 *
 * <p>Committing the side effects last (V00.75.10) means an envelope that fails a
 * later gate never poisons the replay store nor advances the per-producer
 * sequence. Within the commit, the sequence CAS runs first and {@code markSeen}
 * only after a successful CAS (V00.80.00, R04): a CAS-losing envelope is
 * rejected without a replay-store entry, so its later legitimate reprocessing
 * is not misclassified as {@code ReplayDetected}.
 *
 * <p>Two gates were added in 00.84.00. The <em>key-to-producer binding</em>
 * (JS-SEC-101) asks the key resolver whether the verifying key may vouch for
 * the producer the envelope claims; until it passes, nothing in the envelope
 * is attributable to anyone. The <em>payload metadata check</em> (JS-SEC-107)
 * decodes the canonical payload with the codec registered for its content
 * type, requires it to be canonical — re-encoding the decoded payload must
 * reproduce the signed bytes, so no reader can decode it differently — and
 * compares the fields it repeats — event type, event id, tenant, subject,
 * time — with the signed envelope, so the producer policy, which is decided
 * on the envelope, also holds for the payload a consumer acts on.
 *
 * <p>The <em>acceptance-window bound</em> (ER27, CWE-770) is part of the time
 * window check. The producer chooses {@code expiresAt}, and the replay store
 * remembers an accepted envelope id until then. An envelope whose declared
 * window ({@code expiresAt - issuedAt}) or remaining window
 * ({@code expiresAt - now}) is longer than {@link #maxAcceptanceWindow()} is
 * rejected as {@link JCustosEventVerificationResult.AcceptanceWindowExceeded}
 * before any side effect, so the pipeline never asks the replay store to keep
 * an id longer than that maximum. The default is
 * {@link #DEFAULT_MAX_ACCEPTANCE_WINDOW}; it must cover the time to live the
 * producers sign with.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class ConsumePipeline implements HasLogger {

  /**
   * {@link JCustosEventVerificationResult.PayloadMetadataMismatch#field()}:
   * no codec is registered for the envelope's payload content type.
   *
   * @since 00.84.00
   */
  public static final String FIELD_PAYLOAD_CONTENT_TYPE = "payloadContentType";

  /**
   * {@link JCustosEventVerificationResult.PayloadMetadataMismatch#field()}:
   * the payload could not be decoded, or it is not in the canonical form its
   * codec writes — re-encoding the decoded payload does not reproduce the
   * signed bytes (duplicate keys, other escapes, whitespace, key order).
   *
   * @since 00.84.00
   */
  public static final String FIELD_PAYLOAD = "canonicalPayload";

  /**
   * {@link JCustosEventVerificationResult.PayloadMetadataMismatch#field()}:
   * the payload's event type differs.
   *
   * @since 00.84.00
   */
  public static final String FIELD_EVENT_TYPE = "eventType";

  /**
   * {@link JCustosEventVerificationResult.PayloadMetadataMismatch#field()}:
   * the payload's event id differs.
   *
   * @since 00.84.00
   */
  public static final String FIELD_EVENT_ID = "eventId";

  /**
   * {@link JCustosEventVerificationResult.PayloadMetadataMismatch#field()}:
   * the payload's tenant differs.
   *
   * @since 00.84.00
   */
  public static final String FIELD_TENANT_ID = "tenantId";

  /**
   * {@link JCustosEventVerificationResult.PayloadMetadataMismatch#field()}:
   * the payload's subject differs.
   *
   * @since 00.84.00
   */
  public static final String FIELD_SUBJECT_ID = "subjectId";

  /**
   * {@link JCustosEventVerificationResult.PayloadMetadataMismatch#field()}:
   * the payload's business time differs.
   *
   * @since 00.84.00
   */
  public static final String FIELD_OCCURRED_AT = "occurredAt";

  /**
   * Default for the longest acceptance window this consumer accepts (ER27):
   * one hour. Both the window an envelope declares
   * ({@code expiresAt - issuedAt}) and the window left at verification
   * ({@code expiresAt - now}) must fit into it, and it is the longest time
   * the pipeline asks the replay store to remember an envelope id. It is
   * twelve times the five-minute time to live of the documented publish
   * set-up; a consumer of producers that sign with a longer time to live
   * raises it through
   * {@link #ConsumePipeline(JCustosEventVerificationKeyResolver, SignatureAlgorithms,
   * JCustosEventReplayStore, JCustosEventSequenceStore, SequenceValidator,
   * SequenceViolationStrategy, JCustosEventProducerPolicy, Collection, Duration)}.
   *
   * @since 00.84.00
   */
  public static final Duration DEFAULT_MAX_ACCEPTANCE_WINDOW = Duration.ofHours(1);

  private record PayloadCheck(CanonicalJCustosEventPayload payload, String mismatch) {
  }

  private final JCustosEventVerificationKeyResolver keyResolver;
  private final SignatureAlgorithms signatureAlgorithms;
  private final JCustosEventReplayStore replayStore;
  private final JCustosEventSequenceStore sequenceStore;
  private final SequenceValidator sequenceValidator;
  private final SequenceViolationStrategy sequenceStrategy;
  private final JCustosEventProducerPolicy producerPolicy;
  private final Map<PayloadContentType, PayloadCodec> payloadCodecs;
  private final Duration maxAcceptanceWindow;
  private final AtomicLong acceptedSequenceAnomalies = new AtomicLong();

  /**
   * Creates a pipeline that decodes payloads with the
   * {@link CanonicalJsonPayloadCodec} — the codec the publish side uses by
   * default. An envelope with any other payload content type is rejected, and
   * so is an envelope whose acceptance window exceeds
   * {@link #DEFAULT_MAX_ACCEPTANCE_WINDOW}.
   */
  public ConsumePipeline(JCustosEventVerificationKeyResolver keyResolver,
      SignatureAlgorithms signatureAlgorithms, JCustosEventReplayStore replayStore,
      JCustosEventSequenceStore sequenceStore, SequenceValidator sequenceValidator,
      SequenceViolationStrategy sequenceStrategy, JCustosEventProducerPolicy producerPolicy) {
    this(keyResolver, signatureAlgorithms, replayStore, sequenceStore, sequenceValidator,
        sequenceStrategy, producerPolicy, List.of(new CanonicalJsonPayloadCodec()));
  }

  /**
   * Creates a pipeline that rejects an envelope whose acceptance window
   * exceeds {@link #DEFAULT_MAX_ACCEPTANCE_WINDOW}.
   *
   * @param payloadCodecs the codecs this consumer decodes payloads with, keyed
   *     by their {@link PayloadCodec#contentType()}; an envelope whose content
   *     type has no codec here is rejected (JS-SEC-107)
   * @throws IllegalArgumentException if two codecs claim the same content type
   * @since 00.84.00
   */
  public ConsumePipeline(JCustosEventVerificationKeyResolver keyResolver,
      SignatureAlgorithms signatureAlgorithms, JCustosEventReplayStore replayStore,
      JCustosEventSequenceStore sequenceStore, SequenceValidator sequenceValidator,
      SequenceViolationStrategy sequenceStrategy, JCustosEventProducerPolicy producerPolicy,
      Collection<? extends PayloadCodec> payloadCodecs) {
    this(keyResolver, signatureAlgorithms, replayStore, sequenceStore, sequenceValidator,
        sequenceStrategy, producerPolicy, payloadCodecs, DEFAULT_MAX_ACCEPTANCE_WINDOW);
  }

  /**
   * @param payloadCodecs the codecs this consumer decodes payloads with, keyed
   *     by their {@link PayloadCodec#contentType()}; an envelope whose content
   *     type has no codec here is rejected (JS-SEC-107)
   * @param maxAcceptanceWindow the longest acceptance window this consumer
   *     accepts (ER27): an envelope whose declared window
   *     ({@code expiresAt - issuedAt}) or remaining window
   *     ({@code expiresAt - now}) is longer is rejected as
   *     {@link JCustosEventVerificationResult.AcceptanceWindowExceeded}. It
   *     must cover the time to live the producers sign with plus the clock
   *     drift between producer and consumer, and it is the longest time the
   *     replay store is asked to remember an envelope id; positive
   * @throws IllegalArgumentException if two codecs claim the same content
   *     type, or if {@code maxAcceptanceWindow} is zero or negative
   * @since 00.84.00
   */
  public ConsumePipeline(JCustosEventVerificationKeyResolver keyResolver,
      SignatureAlgorithms signatureAlgorithms, JCustosEventReplayStore replayStore,
      JCustosEventSequenceStore sequenceStore, SequenceValidator sequenceValidator,
      SequenceViolationStrategy sequenceStrategy, JCustosEventProducerPolicy producerPolicy,
      Collection<? extends PayloadCodec> payloadCodecs, Duration maxAcceptanceWindow) {
    Objects.requireNonNull(maxAcceptanceWindow, "maxAcceptanceWindow");
    if (maxAcceptanceWindow.isZero() || maxAcceptanceWindow.isNegative()) {
      throw new IllegalArgumentException("maxAcceptanceWindow must be positive, was "
          + maxAcceptanceWindow);
    }
    this.maxAcceptanceWindow = maxAcceptanceWindow;
    this.keyResolver = Objects.requireNonNull(keyResolver, "keyResolver");
    this.signatureAlgorithms = Objects.requireNonNull(signatureAlgorithms, "signatureAlgorithms");
    this.replayStore = Objects.requireNonNull(replayStore, "replayStore");
    this.sequenceStore = Objects.requireNonNull(sequenceStore, "sequenceStore");
    this.sequenceValidator = Objects.requireNonNull(sequenceValidator, "sequenceValidator");
    this.sequenceStrategy = Objects.requireNonNull(sequenceStrategy, "sequenceStrategy");
    this.producerPolicy = Objects.requireNonNull(producerPolicy, "producerPolicy");
    Objects.requireNonNull(payloadCodecs, "payloadCodecs");
    Map<PayloadContentType, PayloadCodec> codecs = new HashMap<>();
    for (PayloadCodec codec : payloadCodecs) {
      Objects.requireNonNull(codec, "payloadCodec");
      if (codecs.putIfAbsent(codec.contentType(), codec) != null) {
        throw new IllegalArgumentException("more than one payload codec for content type "
            + codec.contentType().value());
      }
    }
    this.payloadCodecs = Map.copyOf(codecs);
  }

  /**
   * @return how many envelopes were accepted although their sequence was not
   *     the next expected one — a gap within the validator's tolerance, or any
   *     violation under {@link SequenceViolationStrategy#ACCEPT_WITH_WARNING}.
   *     Each one is also logged as {@code events/sequence-anomaly-accepted}
   * @since 00.84.00
   */
  public long acceptedSequenceAnomalyCount() {
    return acceptedSequenceAnomalies.get();
  }

  /**
   * @return the longest acceptance window this consumer accepts — and with it
   *     the longest time this pipeline asks the replay store to remember an
   *     envelope id (ER27)
   * @since 00.84.00
   */
  public Duration maxAcceptanceWindow() {
    return maxAcceptanceWindow;
  }

  /**
   * Verifies an incoming envelope.
   *
   * @param envelope the envelope to verify
   * @param now the current instant (for the expiry check and the
   *     acceptance-window bound)
   * @return the verification result
   */
  public JCustosEventVerificationResult verify(SignedJCustosEventEnvelope envelope,
      Instant now) {
    Objects.requireNonNull(envelope, "envelope");
    Objects.requireNonNull(now, "now");

    KeyId keyId = envelope.keyId();
    Optional<PublicKey> publicKey = keyResolver.resolveVerificationKey(keyId);
    if (publicKey.isEmpty()) {
      return new JCustosEventVerificationResult.UnknownKey(keyId);
    }
    KeyStatus keyStatus = keyResolver.keyStatus(keyId);
    if (keyStatus == KeyStatus.REVOKED) {
      return new JCustosEventVerificationResult.KeyRevoked(keyId);
    }
    if (keyStatus == KeyStatus.EXPIRED) {
      return new JCustosEventVerificationResult.KeyExpired(keyId);
    }
    if (keyStatus != KeyStatus.ACTIVE && keyStatus != KeyStatus.ACCEPTED_FOR_VERIFICATION) {
      // Any other status (incl. UNKNOWN reported alongside a resolvable key) is
      // not usable for verification — fail closed rather than accept.
      return new JCustosEventVerificationResult.UnknownKey(keyId);
    }

    // JS-SEC-054 (CWE-755): payloadHashAlgorithm / signatureAlgorithm accept any non-blank string at
    // decode, so resolve them SOFTLY — an unavailable digest or an unregistered signature id must
    // map to a fail-closed verification result, never an uncaught IllegalState/IAE escaping the
    // documented-total verify(). An unavailable digest is treated as a hash mismatch (fail closed).
    var recomputedHash = PayloadDigest.tryHash(
        envelope.payloadHashAlgorithm(), envelope.canonicalPayload());
    if (recomputedHash.isEmpty() || !recomputedHash.get().equals(envelope.canonicalPayloadHash())) {
      return new JCustosEventVerificationResult.PayloadHashMismatch(envelope.envelopeId());
    }

    var maybeAlgorithm = signatureAlgorithms.find(envelope.signatureAlgorithm());
    if (maybeAlgorithm.isEmpty()) {
      return new JCustosEventVerificationResult.InvalidSignature("unsupported signature algorithm");
    }
    SignatureAlgorithm algorithm = maybeAlgorithm.get();
    byte[] signatureBase;
    try {
      signatureBase = EnvelopeSignatureBase.compute(envelope);
    } catch (IllegalArgumentException malformed) {
      // JS-SEC-111: a field that is not well-formed UTF-16 has no signature
      // base. The envelope constructor already refuses such a value; this
      // covers an envelope that reached the pipeline by another route.
      return new JCustosEventVerificationResult.InvalidSignature(
          "envelope metadata is not well-formed text");
    }
    boolean verified;
    try {
      verified = algorithm.verify(signatureBase, envelope.signature(), publicKey.get());
    } catch (RuntimeException verifyFailure) {
      // e.g. a key/algorithm-type mismatch surfaced as a SignatureOperationException — fail closed.
      return new JCustosEventVerificationResult.InvalidSignature("signature verification failed");
    }
    if (!verified) {
      return new JCustosEventVerificationResult.InvalidSignature(
          "signature does not verify under key " + keyId.value());
    }

    // JS-SEC-101 (CWE-290, CWE-863): the signature proves that SOME trusted key
    // signed. The producerId — and with it the scope of the sequence and the
    // subject of the producer policy below — is written by the signer, so it
    // only counts once the resolver confirms that this key belongs to that
    // producer. Without the binding every trusted key signs for every producer.
    TenantId tenantId = envelope.tenantId();
    EventProducerId producerId = envelope.producerId();
    if (!keyResolver.mayVerify(keyId, producerId, tenantId)) {
      return new JCustosEventVerificationResult.KeyNotAuthorizedForProducer(
          keyId, producerId, tenantId);
    }

    if (envelope.isExpiredAt(now)) {
      return new JCustosEventVerificationResult.Expired(envelope.expiresAt());
    }

    // ER27 (CWE-770): the signer chooses expiresAt, and markSeen below keeps
    // the id until then. Without a bound of the consumer's own, one signing
    // key — compromised or misconfigured — could pin the replay store with
    // ids valid until the year 9999, beyond the key's revocation, and the
    // store's capacity eviction would then drop legitimate ids instead.
    // Read-only like every gate before the commit.
    if (exceedsAcceptanceWindow(envelope, now)) {
      return new JCustosEventVerificationResult.AcceptanceWindowExceeded(
          envelope.envelopeId(), envelope.issuedAt(), envelope.expiresAt(),
          maxAcceptanceWindow);
    }

    // Replay: read-only check first, so a genuine duplicate is reported as
    // ReplayDetected even when a stricter sequence policy would also reject it.
    if (replayStore.hasSeen(envelope.envelopeId())) {
      return new JCustosEventVerificationResult.ReplayDetected(envelope.envelopeId());
    }

    // Sequence + producer policy are read-only gates here — decide, but record
    // no side effect yet (R003: a rejected envelope must neither poison the
    // replay store nor advance the per-producer sequence).
    Optional<EventSequence> last = sequenceStore.lastSequence(tenantId, producerId);
    SequenceDecision decision = sequenceValidator.decide(last, envelope.sequence(),
        sequenceStrategy);
    if (!decision.accepted()) {
      return new JCustosEventVerificationResult.SequenceViolation(
          tenantId, producerId, expectedAfter(last), envelope.sequence());
    }

    if (!producerPolicy.mayPublish(producerId, envelope.eventType(), tenantId)) {
      return new JCustosEventVerificationResult.ProducerNotAllowed(
          producerId, envelope.eventType(), tenantId);
    }

    // JS-SEC-107 (CWE-345, CWE-863): the payload repeats event type, event id,
    // tenant, subject and time, and it is the payload a consumer acts on. The
    // hash only proves the payload is the signed one, not that it describes the
    // event the envelope announces — and the policy above was decided on the
    // envelope. Last read-only gate: a mismatch leaves sequence and replay
    // store untouched.
    PayloadCheck payloadCheck = checkPayload(envelope);
    if (payloadCheck.mismatch() != null) {
      return new JCustosEventVerificationResult.PayloadMetadataMismatch(
          envelope.envelopeId(), payloadCheck.mismatch());
    }

    // Every gate passed — now commit the side effects: sequence CAS FIRST,
    // markSeen only on CAS success (R04). The previous order (markSeen before
    // the CAS) poisoned the replay store for a CAS-losing envelope — it was
    // rejected as SequenceViolation with its id already marked seen, so its
    // legitimate redelivery was forever misclassified as ReplayDetected.
    //
    // R016 (V00.76.10): the CAS advances the per-producer sequence atomically
    // against the value we observed at line `last = ...`. If a concurrent
    // envelope advanced the sequence between our read and this commit, the CAS
    // fails and we reject this one as a SequenceViolation — closing the
    // check-then-act race where two distinct envelopes both claiming the same
    // next sequence could both pass and both commit (lost update /
    // monotonicity break).
    if (!sequenceStore.compareAndAdvance(tenantId, producerId, last, envelope.sequence())) {
      return new JCustosEventVerificationResult.SequenceViolation(
          tenantId, producerId, expectedAfter(last), envelope.sequence());
    }
    // markSeen stays atomic to settle a concurrent duplicate that slipped past
    // the read-only hasSeen check above. Residual crash-window semantics (R04):
    // if the process dies between the successful CAS and this markSeen, the
    // sequence is advanced but the id is not recorded — a redelivery of the
    // same envelope is then rejected via SequenceViolation (its sequence is
    // already consumed), which is still fail-closed and leaves the replay
    // store unpoisoned.
    if (!replayStore.markSeen(envelope.envelopeId(), envelope.expiresAt())) {
      return new JCustosEventVerificationResult.ReplayDetected(envelope.envelopeId());
    }

    if (decision.state() != SequenceState.IN_ORDER) {
      reportAcceptedAnomaly(envelope, decision, expectedAfter(last));
    }
    return new JCustosEventVerificationResult.Valid(envelope, payloadCheck.payload());
  }

  // The declared window catches a producer that signs with too long a time to
  // live whenever its envelope arrives; the remaining window catches an
  // issuedAt in the future, which would keep the declared window short and
  // the replay entry long. Duration.between does not overflow for any two
  // instants, so the check stays total (JS-SEC-054).
  private boolean exceedsAcceptanceWindow(SignedJCustosEventEnvelope envelope, Instant now) {
    return Duration.between(envelope.issuedAt(), envelope.expiresAt())
        .compareTo(maxAcceptanceWindow) > 0
        || Duration.between(now, envelope.expiresAt()).compareTo(maxAcceptanceWindow) > 0;
  }

  // JS-SEC-105 (CWE-190): EventSequence#next throws at Long.MAX_VALUE, and
  // verify() is documented as total (JS-SEC-054). A stored Long.MAX_VALUE has
  // no successor — report the stored value itself as the expectation.
  private static EventSequence expectedAfter(Optional<EventSequence> last) {
    return last
        .map(sequence -> sequence.value() == Long.MAX_VALUE ? sequence : sequence.next())
        .orElse(EventSequence.FIRST);
  }

  private PayloadCheck checkPayload(SignedJCustosEventEnvelope envelope) {
    PayloadCodec codec = payloadCodecs.get(envelope.payloadContentType());
    if (codec == null) {
      return new PayloadCheck(null, FIELD_PAYLOAD_CONTENT_TYPE);
    }
    CanonicalJCustosEventPayload payload;
    try {
      payload = codec.decode(envelope.canonicalPayload());
    } catch (RuntimeException undecodable) {
      // Fail closed and stay total: whatever the codec throws on hostile bytes.
      return new PayloadCheck(null, FIELD_PAYLOAD);
    }
    if (payload == null) {
      return new PayloadCheck(null, FIELD_PAYLOAD);
    }
    // The payload must be in exactly the form its codec writes: re-encoding
    // the decoded payload has to reproduce the signed bytes. Otherwise the
    // signature covers bytes that another reader may decode differently —
    // duplicate keys (the last one wins here, the first one elsewhere),
    // escapes, whitespace — and the checks below would vouch for a reading a
    // downstream consumer of canonicalPayload does not share.
    try {
      if (!Arrays.equals(codec.encode(payload), envelope.canonicalPayload())) {
        return new PayloadCheck(null, FIELD_PAYLOAD);
      }
    } catch (RuntimeException unencodable) {
      return new PayloadCheck(null, FIELD_PAYLOAD);
    }
    if (!payload.eventType().equals(envelope.eventType().value())) {
      return new PayloadCheck(null, FIELD_EVENT_TYPE);
    }
    if (!payload.eventId().equals(envelope.eventId().value())) {
      return new PayloadCheck(null, FIELD_EVENT_ID);
    }
    if (!payload.tenantId().equals(envelope.tenantId().value())) {
      return new PayloadCheck(null, FIELD_TENANT_ID);
    }
    if (!payload.subjectId().equals(envelope.subjectId().value())) {
      return new PayloadCheck(null, FIELD_SUBJECT_ID);
    }
    // Compared as instants, so a producer that renders the same instant with
    // trailing zeros still matches.
    try {
      if (!Instant.parse(payload.occurredAt()).equals(envelope.occurredAt())) {
        return new PayloadCheck(null, FIELD_OCCURRED_AT);
      }
    } catch (DateTimeParseException unparsable) {
      return new PayloadCheck(null, FIELD_OCCURRED_AT);
    }
    return new PayloadCheck(payload, null);
  }

  // JS-SEC-108: an envelope accepted across a gap means envelopes were lost (or
  // withheld) — the stream goes on, but the loss must not go unnoticed.
  private void reportAcceptedAnomaly(SignedJCustosEventEnvelope envelope,
      SequenceDecision decision, EventSequence expected) {
    acceptedSequenceAnomalies.incrementAndGet();
    logger().warn("events/sequence-anomaly-accepted: producer {} (tenant {}) sent sequence {}"
            + " but {} was expected ({}) — the envelope was accepted under the configured"
            + " tolerance. Check the producer and the transport path for lost envelopes.",
        LogFieldScrubber.scrub(envelope.producerId().value()),
        LogFieldScrubber.scrub(envelope.tenantId().value()),
        envelope.sequence().value(), expected.value(), decision.state());
  }
}
