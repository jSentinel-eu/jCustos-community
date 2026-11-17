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

import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.types.EnvelopeRejectedEvent;
import eu.jsentinel.jcustos.events.types.EventBusSelfObservabilityEvent;
import eu.jsentinel.jcustos.events.types.ReplayDetectedEvent;
import eu.jsentinel.jcustos.events.types.SequenceViolationEvent;
import eu.jsentinel.jcustos.events.types.SignatureInvalidEvent;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Maps a {@link JCustosEventVerificationResult} to the self-observability
 * event describing it.
 *
 * <p>Mapping contract: every failure result maps to <em>exactly one</em>
 * event — the most specific one — never two. The monitoring bridge builds the
 * {@code security.eventbus.rejected.total} umbrella metric from the whole
 * rejection event family, so a double-publish here would double-count.
 * <ul>
 *   <li>{@link JCustosEventVerificationResult.InvalidSignature} and
 *       {@link JCustosEventVerificationResult.PayloadHashMismatch} both map
 *       to {@link SignatureInvalidEvent}: the canonical payload is bound to
 *       the signed metadata through its hash, so a hash mismatch is a failure
 *       of the same cryptographic content binding as an invalid signature
 *       (see {@link SignatureInvalidEvent}).</li>
 *   <li>{@link JCustosEventVerificationResult.ReplayDetected} maps to
 *       {@link ReplayDetectedEvent}.</li>
 *   <li>{@link JCustosEventVerificationResult.SequenceViolation} maps to
 *       {@link SequenceViolationEvent}.</li>
 *   <li>Every remaining failure (unknown / revoked / expired key, key not
 *       bound to the producer, expired envelope, acceptance window longer
 *       than the consumer accepts, producer not allowed, payload metadata
 *       mismatch) maps to {@link EnvelopeRejectedEvent} with one of the
 *       {@code REASON_*} constants.</li>
 * </ul>
 *
 * <p>Severity: every failure carries {@link JCustosEventSeverity#ERROR},
 * except a detected replay which carries
 * {@link JCustosEventSeverity#CRITICAL} — the Konzept mandates "erkannter
 * Replay fuehrt zu Reject und kritischem Security Event" and the severity
 * enum expresses that level directly. The subject is
 * {@link JCustosEvent#SYSTEM_SUBJECT} and the timestamp is the caller-supplied
 * {@code now}.
 *
 * <p>Unverified envelope fields are not adopted as facts (JS-SEC-104,
 * CWE-345). Tenant and envelope id come from the envelope only when the
 * result says the envelope was authenticated
 * ({@link JCustosEventVerificationResult#envelopeAuthenticated()}). For every
 * failure before that point — nobody needs a key to cause one — the event is
 * raised under {@link #UNAUTHENTICATED_TENANT} and carries the claimed
 * envelope id in the clipped, marked form of {@link #unverifiedId(String)}.
 * Otherwise any caller of the ingest path could raise alerts and audit
 * entries in the name of a tenant of its choosing. Listeners that must treat
 * such events differently (an audit chain, a pager) recognise them with
 * {@link #isUnauthenticatedRejection(JCustosEvent)}.
 *
 * <p>Publish-side note: the pipeline rejects a publish <em>before</em> an
 * envelope exists, so on that path (see {@code DefaultJCustosEventBus})
 * the event id doubles as the {@code rejectedEnvelopeId} of the emitted
 * {@link EnvelopeRejectedEvent}.
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class SelfObservabilityEvents {

  /** Rejection reason: the referenced key id is unknown. */
  public static final String REASON_UNKNOWN_KEY = "unknown-key";

  /** Rejection reason: the referenced key has been revoked. */
  public static final String REASON_KEY_REVOKED = "key-revoked";

  /** Rejection reason: the referenced key is past its validity window. */
  public static final String REASON_KEY_EXPIRED = "key-expired";

  /** Rejection reason: the envelope is past its acceptance window. */
  public static final String REASON_EXPIRED = "expired";

  /**
   * Rejection reason: the envelope's acceptance window is longer than the
   * consumer accepts (ER27).
   *
   * @since 00.84.00
   */
  public static final String REASON_ACCEPTANCE_WINDOW_EXCEEDED = "acceptance-window-exceeded";

  /** Rejection reason: the producer may not publish this event type. */
  public static final String REASON_PRODUCER_NOT_ALLOWED = "producer-not-allowed";

  /**
   * Rejection reason: the signature verified, but the key is not bound to the
   * producer the envelope claims.
   *
   * @since 00.84.00
   */
  public static final String REASON_KEY_NOT_AUTHORIZED = "key-not-authorized-for-producer";

  /**
   * Rejection reason: the payload does not describe the event the signed
   * envelope announces.
   *
   * @since 00.84.00
   */
  public static final String REASON_PAYLOAD_METADATA_MISMATCH = "payload-metadata-mismatch";

  /**
   * Rejection reason on the publish side: a field of the event that would
   * enter the signed envelope is not well-formed UTF-16 (JS-SEC-111).
   *
   * @since 00.84.00
   */
  public static final String REASON_MALFORMED_TEXT = "malformed-text";

  /**
   * The tenant under which a rejection of an <em>unauthenticated</em> envelope
   * is reported: the system tenant the bus also uses for its other events
   * about itself, never the tenant the envelope claims.
   *
   * @since 00.84.00
   */
  public static final TenantId UNAUTHENTICATED_TENANT = TenantId.DEFAULT;

  /**
   * Marker in front of an envelope id that was taken from an unauthenticated
   * envelope.
   *
   * @since 00.84.00
   */
  public static final String UNVERIFIED_ID_PREFIX = "unverified:";

  /**
   * How many characters (code points) of a claimed envelope id an event about
   * an unauthenticated envelope carries at most.
   *
   * @since 00.84.00
   */
  public static final int MAX_UNVERIFIED_ID_LENGTH = 64;

  // JS-SEC-101: REASON_KEY_NOT_AUTHORIZED is deliberately absent - only the
  // holder of a usable key can cause it, so it is no keyless noise.
  private static final Set<String> UNAUTHENTICATED_REASONS = Set.of(
      REASON_UNKNOWN_KEY, REASON_KEY_REVOKED, REASON_KEY_EXPIRED);

  private SelfObservabilityEvents() {
  }

  /**
   * Maps a verification result to its self-observability event.
   *
   * @param result the verification outcome
   * @param envelope the envelope the result is about (supplies tenant and
   *     envelope id — as facts only once it is authenticated, see the class
   *     Javadoc)
   * @param now the emission timestamp
   * @return the single most specific event, or empty for
   *     {@link JCustosEventVerificationResult.Valid}
   */
  public static Optional<EventBusSelfObservabilityEvent> fromVerification(
      JCustosEventVerificationResult result, SignedJCustosEventEnvelope envelope,
      Instant now) {
    Objects.requireNonNull(result, "result");
    Objects.requireNonNull(envelope, "envelope");
    Objects.requireNonNull(now, "now");
    boolean authenticated = result.envelopeAuthenticated();
    return switch (result) {
      case JCustosEventVerificationResult.Valid ignored -> Optional.empty();
      case JCustosEventVerificationResult.InvalidSignature ignored ->
          Optional.of(new SignatureInvalidEvent(
              failureMetadata(envelope, now, JCustosEventSeverity.ERROR, authenticated),
              reportedId(envelope.envelopeId().value(), authenticated)));
      case JCustosEventVerificationResult.PayloadHashMismatch mismatch ->
          Optional.of(new SignatureInvalidEvent(
              failureMetadata(envelope, now, JCustosEventSeverity.ERROR, authenticated),
              reportedId(mismatch.envelopeId().value(), authenticated)));
      case JCustosEventVerificationResult.ReplayDetected replay ->
          Optional.of(new ReplayDetectedEvent(
              failureMetadata(envelope, now, JCustosEventSeverity.CRITICAL, authenticated),
              reportedId(replay.envelopeId().value(), authenticated)));
      case JCustosEventVerificationResult.SequenceViolation violation ->
          Optional.of(new SequenceViolationEvent(
              failureMetadata(envelope, now, JCustosEventSeverity.ERROR, authenticated),
              violation.producerId().value(),
              violation.expected().value(),
              violation.actual().value()));
      case JCustosEventVerificationResult.UnknownKey ignored ->
          rejected(envelope, now, REASON_UNKNOWN_KEY, authenticated);
      case JCustosEventVerificationResult.KeyRevoked ignored ->
          rejected(envelope, now, REASON_KEY_REVOKED, authenticated);
      case JCustosEventVerificationResult.KeyExpired ignored ->
          rejected(envelope, now, REASON_KEY_EXPIRED, authenticated);
      // The signature verified under this key, so the key id is a fact even
      // though the producer the envelope claims is not (JS-SEC-101).
      case JCustosEventVerificationResult.KeyNotAuthorizedForProducer unbound ->
          Optional.of(new EnvelopeRejectedEvent(
              failureMetadata(envelope, now, JCustosEventSeverity.ERROR, authenticated),
              reportedId(envelope.envelopeId().value(), authenticated),
              REASON_KEY_NOT_AUTHORIZED, unbound.keyId().value()));
      case JCustosEventVerificationResult.Expired ignored ->
          rejected(envelope, now, REASON_EXPIRED, authenticated);
      case JCustosEventVerificationResult.AcceptanceWindowExceeded ignored ->
          rejected(envelope, now, REASON_ACCEPTANCE_WINDOW_EXCEEDED, authenticated);
      case JCustosEventVerificationResult.ProducerNotAllowed ignored ->
          rejected(envelope, now, REASON_PRODUCER_NOT_ALLOWED, authenticated);
      case JCustosEventVerificationResult.PayloadMetadataMismatch ignored ->
          rejected(envelope, now, REASON_PAYLOAD_METADATA_MISMATCH, authenticated);
    };
  }

  /**
   * Renders an envelope id claimed by an unauthenticated envelope: the
   * {@link #UNVERIFIED_ID_PREFIX} followed by at most
   * {@link #MAX_UNVERIFIED_ID_LENGTH} code points of the claim, scrubbed with
   * {@link LogFieldScrubber#scrub(String)}. The marker keeps a reader from
   * correlating the id with a genuine envelope, the clip keeps a sender from
   * inflating every event, alert and audit entry with an id of its own
   * length, and the scrub keeps line terminators (CR, LF, U+2028), bidi and
   * other format characters, spaces and unpaired surrogates of the sender's
   * choosing out of every log line and export the event reaches
   * (JS-SEC-110). Each replaced code point becomes one {@code '?'}.
   *
   * @param claimedId the id as the envelope states it
   * @return the marked, clipped, scrubbed form
   * @since 00.84.00
   */
  public static String unverifiedId(String claimedId) {
    Objects.requireNonNull(claimedId, "claimedId");
    int codePoints = claimedId.codePointCount(0, claimedId.length());
    String clipped = codePoints <= MAX_UNVERIFIED_ID_LENGTH
        ? claimedId
        : claimedId.substring(0, claimedId.offsetByCodePoints(0, MAX_UNVERIFIED_ID_LENGTH));
    return UNVERIFIED_ID_PREFIX + LogFieldScrubber.scrub(clipped);
  }

  /**
   * Tells whether an event reports the rejection of an envelope that was
   * never authenticated — raised by anyone who can reach the ingest path,
   * without a key. The decision rests on the event type and the fixed reason
   * code, never on content the sender controls.
   *
   * <p>Such events are a signal about the transport, not a statement about a
   * tenant or producer. A listener with a bounded or tamper-evident store
   * behind it (an audit chain) should not record every one of them, and an
   * alerting listener should throttle them.
   *
   * <p>A rejection with reason {@link #REASON_KEY_NOT_AUTHORIZED} is not one
   * of them (JS-SEC-101, CWE-290, CWE-778). Its signature verified, so only
   * the holder of a usable key can cause it, and it documents that this key
   * signed in the name of a producer it is not bound to - the misuse an audit
   * chain exists to record. The event is still raised under
   * {@link #UNAUTHENTICATED_TENANT} with an unverified envelope id, because
   * the producer and tenant the envelope claims are not facts; the key id it
   * carries is.</p>
   *
   * @param event any event
   * @return {@code true} for a {@link SignatureInvalidEvent} and for an
   *     {@link EnvelopeRejectedEvent} whose reason is unknown key, revoked
   *     key or expired key
   * @since 00.84.00
   */
  public static boolean isUnauthenticatedRejection(JCustosEvent event) {
    if (event instanceof SignatureInvalidEvent) {
      return true;
    }
    return event instanceof EnvelopeRejectedEvent rejected
        && rejected.reason() != null
        && UNAUTHENTICATED_REASONS.contains(rejected.reason());
  }

  private static Optional<EventBusSelfObservabilityEvent> rejected(
      SignedJCustosEventEnvelope envelope, Instant now, String reason,
      boolean authenticated) {
    return Optional.of(new EnvelopeRejectedEvent(
        failureMetadata(envelope, now, JCustosEventSeverity.ERROR, authenticated),
        reportedId(envelope.envelopeId().value(), authenticated), reason));
  }

  private static String reportedId(String envelopeId, boolean authenticated) {
    return authenticated ? envelopeId : unverifiedId(envelopeId);
  }

  private static EventMetadata failureMetadata(SignedJCustosEventEnvelope envelope,
      Instant now, JCustosEventSeverity severity, boolean authenticated) {
    return EventMetadata.create(
        authenticated ? envelope.tenantId() : UNAUTHENTICATED_TENANT,
        JCustosEvent.SYSTEM_SUBJECT, now, severity);
  }
}
