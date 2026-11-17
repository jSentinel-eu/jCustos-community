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
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventEnvelopeId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventSequence;
import eu.jsentinel.jcustos.events.api.EventType;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.codec.CanonicalJCustosEventPayload;

import java.time.Duration;
import java.time.Instant;

/**
 * Structured outcome of verifying an incoming envelope (Konzept §878).
 * Verification yields differentiated results rather than a bare boolean, for
 * audit, monitoring and diagnosis.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public sealed interface JCustosEventVerificationResult {

  /** @return {@code true} only for {@link Valid}. */
  default boolean isValid() {
    return this instanceof Valid;
  }

  /**
   * Tells whether the envelope's metadata is attributable to a producer: the
   * signature verified under a usable key <em>and</em> that key is bound to
   * the claimed producer. Until both hold, every envelope field — tenant,
   * envelope id, producer id — is just what an unknown sender wrote, and must
   * not be adopted as a fact in alerts, audit entries or log attribution
   * (JS-SEC-104, CWE-345).
   *
   * <p>{@code false} for {@link InvalidSignature}, {@link UnknownKey},
   * {@link KeyRevoked}, {@link KeyExpired}, {@link PayloadHashMismatch} and
   * {@link KeyNotAuthorizedForProducer}; {@code true} for every result the
   * pipeline reaches after those gates, {@link Valid} included.
   *
   * @return {@code true} if the result was reached after the envelope was
   *     authenticated
   * @since 00.84.00
   */
  default boolean envelopeAuthenticated() {
    return switch (this) {
      case InvalidSignature ignored -> false;
      case UnknownKey ignored -> false;
      case KeyRevoked ignored -> false;
      case KeyExpired ignored -> false;
      case PayloadHashMismatch ignored -> false;
      case KeyNotAuthorizedForProducer ignored -> false;
      case Valid ignored -> true;
      case Expired ignored -> true;
      case AcceptanceWindowExceeded ignored -> true;
      case ReplayDetected ignored -> true;
      case SequenceViolation ignored -> true;
      case ProducerNotAllowed ignored -> true;
      case PayloadMetadataMismatch ignored -> true;
    };
  }

  /**
   * The envelope passed every verification stage.
   *
   * @param envelope the verified envelope
   * @param payload the canonical payload decoded from the envelope, whose
   *     event type, event id, tenant, subject and time were checked against
   *     the signed envelope (JS-SEC-107) — consumers read the event from here
   *     instead of decoding {@code canonicalPayload} themselves. {@code null}
   *     only for a result built through the one-argument constructor, which
   *     the pipeline never uses
   */
  record Valid(SignedJCustosEventEnvelope envelope, CanonicalJCustosEventPayload payload)
      implements JCustosEventVerificationResult {

    /**
     * Result without a decoded payload — kept for callers that build a
     * {@code Valid} themselves.
     *
     * @param envelope the verified envelope
     */
    public Valid(SignedJCustosEventEnvelope envelope) {
      this(envelope, null);
    }
  }

  /** The signature did not verify. */
  record InvalidSignature(String reason) implements JCustosEventVerificationResult {
  }

  /** The referenced key id is unknown. */
  record UnknownKey(KeyId keyId) implements JCustosEventVerificationResult {
  }

  /** The referenced key has been revoked. */
  record KeyRevoked(KeyId keyId) implements JCustosEventVerificationResult {
  }

  /**
   * The referenced key is past its validity window. Signatures under an expired
   * key must be rejected just like a revoked one.
   *
   * @since 00.75.10
   */
  record KeyExpired(KeyId keyId) implements JCustosEventVerificationResult {
  }

  /** The envelope is past its acceptance window. */
  record Expired(Instant expiresAt) implements JCustosEventVerificationResult {
  }

  /**
   * The envelope's acceptance window is longer than this consumer accepts
   * (ER27, CWE-770): the window it declares ({@code expiresAt - issuedAt})
   * or the window still left at verification ({@code expiresAt - now})
   * exceeds the consumer's maximum. The producer chooses {@code expiresAt},
   * and a consumer remembers an accepted envelope id until then, so without
   * this bound one signing key could occupy the replay store for as long as
   * it liked.
   *
   * @param envelopeId the rejected envelope
   * @param issuedAt the envelope's signed issue time
   * @param expiresAt the envelope's signed end of the acceptance window
   * @param maxAcceptanceWindow the longest window this consumer accepts
   * @since 00.84.00
   */
  record AcceptanceWindowExceeded(
      EventEnvelopeId envelopeId,
      Instant issuedAt,
      Instant expiresAt,
      Duration maxAcceptanceWindow) implements JCustosEventVerificationResult {
  }

  /** The recomputed payload hash did not match the envelope's. */
  record PayloadHashMismatch(EventEnvelopeId envelopeId)
      implements JCustosEventVerificationResult {
  }

  /** The envelope was a replay of an already-seen envelope. */
  record ReplayDetected(EventEnvelopeId envelopeId)
      implements JCustosEventVerificationResult {
  }

  /** The sequence violated the configured policy. */
  record SequenceViolation(
      TenantId tenantId,
      EventProducerId producerId,
      EventSequence expected,
      EventSequence actual) implements JCustosEventVerificationResult {
  }

  /** The producer is not allowed to publish this event type. */
  record ProducerNotAllowed(
      EventProducerId producerId,
      EventType eventType,
      TenantId tenantId) implements JCustosEventVerificationResult {
  }

  /**
   * The signature verified, but the key is not bound to the producer the
   * envelope claims — a trusted key was used to sign in another producer's
   * name (JS-SEC-101).
   *
   * @param keyId the key the signature verified under
   * @param producerId the producer id the envelope claims
   * @param tenantId the tenant the envelope claims
   * @since 00.84.00
   */
  record KeyNotAuthorizedForProducer(
      KeyId keyId,
      EventProducerId producerId,
      TenantId tenantId) implements JCustosEventVerificationResult {
  }

  /**
   * The payload does not describe the event the signed envelope announces:
   * it could not be decoded with the codec of its content type, or one of the
   * fields it repeats differs from the envelope (JS-SEC-107).
   *
   * @param envelopeId the rejected envelope
   * @param field the first deviating field — one of the
   *     {@code ConsumePipeline.FIELD_*} constants, never payload content
   * @since 00.84.00
   */
  record PayloadMetadataMismatch(EventEnvelopeId envelopeId, String field)
      implements JCustosEventVerificationResult {
  }
}
