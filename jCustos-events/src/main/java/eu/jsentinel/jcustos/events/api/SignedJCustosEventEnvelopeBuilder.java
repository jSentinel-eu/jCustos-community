package eu.jsentinel.jcustos.events.api;

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
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Instant;

/**
 * Fluent builder for {@link SignedJCustosEventEnvelope}.
 *
 * <p>The builder is a thin assembler: {@link #build()} delegates to the
 * record's compact constructor, so any missing mandatory field (everything
 * except {@code causationId}) fails fast with the same validation the record
 * enforces. Defaulting (random {@code envelopeId} / {@code correlationId},
 * {@code issuedAt = now}) is the caller's responsibility via the publish
 * pipeline; the builder itself stays defaulting-free so tests can assert that
 * each required field is genuinely mandatory.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class SignedJCustosEventEnvelopeBuilder {

  private EventEnvelopeId envelopeId;
  private EventId eventId;
  private EventType eventType;
  private TenantId tenantId;
  private SubjectId subjectId;
  private EventProducerId producerId;
  private Instant occurredAt;
  private Instant issuedAt;
  private Instant expiresAt;
  private CorrelationId correlationId;
  private CausationId causationId;
  private EventSequence sequence;
  private KeyId keyId;
  private SignatureAlgorithmId signatureAlgorithm;
  private PayloadContentType payloadContentType;
  private PayloadHashAlgorithm payloadHashAlgorithm;
  private String canonicalPayloadHash;
  private byte[] canonicalPayload;
  private byte[] signature;

  private SignedJCustosEventEnvelopeBuilder() {
  }

  /**
   * @return a fresh, empty builder
   */
  public static SignedJCustosEventEnvelopeBuilder create() {
    return new SignedJCustosEventEnvelopeBuilder();
  }

  public SignedJCustosEventEnvelopeBuilder envelopeId(EventEnvelopeId v) {
    this.envelopeId = v;
    return this;
  }

  public SignedJCustosEventEnvelopeBuilder eventId(EventId v) {
    this.eventId = v;
    return this;
  }

  public SignedJCustosEventEnvelopeBuilder eventType(EventType v) {
    this.eventType = v;
    return this;
  }

  public SignedJCustosEventEnvelopeBuilder tenantId(TenantId v) {
    this.tenantId = v;
    return this;
  }

  public SignedJCustosEventEnvelopeBuilder subjectId(SubjectId v) {
    this.subjectId = v;
    return this;
  }

  public SignedJCustosEventEnvelopeBuilder producerId(EventProducerId v) {
    this.producerId = v;
    return this;
  }

  public SignedJCustosEventEnvelopeBuilder occurredAt(Instant v) {
    this.occurredAt = v;
    return this;
  }

  public SignedJCustosEventEnvelopeBuilder issuedAt(Instant v) {
    this.issuedAt = v;
    return this;
  }

  public SignedJCustosEventEnvelopeBuilder expiresAt(Instant v) {
    this.expiresAt = v;
    return this;
  }

  public SignedJCustosEventEnvelopeBuilder correlationId(CorrelationId v) {
    this.correlationId = v;
    return this;
  }

  public SignedJCustosEventEnvelopeBuilder causationId(CausationId v) {
    this.causationId = v;
    return this;
  }

  public SignedJCustosEventEnvelopeBuilder sequence(EventSequence v) {
    this.sequence = v;
    return this;
  }

  public SignedJCustosEventEnvelopeBuilder keyId(KeyId v) {
    this.keyId = v;
    return this;
  }

  public SignedJCustosEventEnvelopeBuilder signatureAlgorithm(SignatureAlgorithmId v) {
    this.signatureAlgorithm = v;
    return this;
  }

  public SignedJCustosEventEnvelopeBuilder payloadContentType(PayloadContentType v) {
    this.payloadContentType = v;
    return this;
  }

  public SignedJCustosEventEnvelopeBuilder payloadHashAlgorithm(PayloadHashAlgorithm v) {
    this.payloadHashAlgorithm = v;
    return this;
  }

  public SignedJCustosEventEnvelopeBuilder canonicalPayloadHash(String v) {
    this.canonicalPayloadHash = v;
    return this;
  }

  public SignedJCustosEventEnvelopeBuilder canonicalPayload(byte[] v) {
    this.canonicalPayload = v;
    return this;
  }

  public SignedJCustosEventEnvelopeBuilder signature(byte[] v) {
    this.signature = v;
    return this;
  }

  /**
   * Assembles the envelope, delegating validation to the record constructor.
   *
   * @return the validated envelope
   * @throws NullPointerException if any mandatory field is null
   * @throws IllegalArgumentException if {@code canonicalPayloadHash} is blank,
   *     a textual field is not well-formed UTF-16, or {@code expiresAt} lies
   *     before {@code issuedAt}
   */
  public SignedJCustosEventEnvelope build() {
    return new SignedJCustosEventEnvelope(
        envelopeId, eventId, eventType, tenantId, subjectId, producerId,
        occurredAt, issuedAt, expiresAt, correlationId, causationId, sequence,
        keyId, signatureAlgorithm, payloadContentType, payloadHashAlgorithm,
        canonicalPayloadHash, canonicalPayload, signature);
  }
}
