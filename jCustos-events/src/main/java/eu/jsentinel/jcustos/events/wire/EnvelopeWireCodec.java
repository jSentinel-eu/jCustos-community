package eu.jsentinel.jcustos.events.wire;

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

import com.svenruppert.functional.result.Result;
import com.svenruppert.functional.result.functions.CheckedSupplier;
import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.CausationId;
import eu.jsentinel.jcustos.events.api.CorrelationId;
import eu.jsentinel.jcustos.events.api.EventEnvelopeId;
import eu.jsentinel.jcustos.events.api.EventId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventSequence;
import eu.jsentinel.jcustos.events.api.EventType;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.api.PayloadContentType;
import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;
import eu.jsentinel.jcustos.events.api.SignatureAlgorithmId;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelopeBuilder;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Serializes a {@link SignedJCustosEventEnvelope} to and from a flat JSON
 * object for REST/SSE transport (Konzept §111, §939). Binary fields
 * ({@code canonicalPayload}, {@code signature}) are Base64-encoded; the
 * {@code sequence} is a JSON number; every other field is a string.
 *
 * <p>Moved unchanged from {@code eu.jsentinel.jcustos.events.rest}
 * (present since 00.75.00) so transport-independent consumers can encode
 * without a REST dependency; {@link #encodeMetadata(SignedJCustosEventEnvelope)}
 * is the V00.80.00 addition.
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class EnvelopeWireCodec {

  private static final Base64.Encoder ENCODER = Base64.getEncoder();
  private static final Base64.Decoder DECODER = Base64.getDecoder();

  // Wire field names — one home so encode() and decode() cannot drift apart.
  private static final String F_ENVELOPE_ID = "envelopeId";
  private static final String F_EVENT_ID = "eventId";
  private static final String F_EVENT_TYPE = "eventType";
  private static final String F_TENANT_ID = "tenantId";
  private static final String F_SUBJECT_ID = "subjectId";
  private static final String F_PRODUCER_ID = "producerId";
  private static final String F_OCCURRED_AT = "occurredAt";
  private static final String F_ISSUED_AT = "issuedAt";
  private static final String F_EXPIRES_AT = "expiresAt";
  private static final String F_CORRELATION_ID = "correlationId";
  private static final String F_CAUSATION_ID = "causationId";
  private static final String F_SEQUENCE = "sequence";
  private static final String F_KEY_ID = "keyId";
  private static final String F_SIGNATURE_ALGORITHM = "signatureAlgorithm";
  private static final String F_PAYLOAD_CONTENT_TYPE = "payloadContentType";
  private static final String F_PAYLOAD_HASH_ALGORITHM = "payloadHashAlgorithm";
  private static final String F_CANONICAL_PAYLOAD_HASH = "canonicalPayloadHash";
  private static final String F_CANONICAL_PAYLOAD = "canonicalPayload";
  private static final String F_SIGNATURE = "signature";

  /**
   * Default upper bound, in UTF-16 code units, for every textual envelope
   * field on decode (JS-SEC-104, CWE-770). Identifiers are UUIDs, short names
   * or timestamps; without a bound a single field could fill the whole request
   * body and travel on into alerts, audit entries and log lines.
   *
   * @since 00.84.00
   */
  public static final int DEFAULT_MAX_FIELD_LENGTH = 256;

  private final int maxFieldLength;

  /** Creates a codec that decodes with {@link #DEFAULT_MAX_FIELD_LENGTH}. */
  public EnvelopeWireCodec() {
    this(DEFAULT_MAX_FIELD_LENGTH);
  }

  /**
   * @param maxFieldLength the upper bound, in UTF-16 code units, for every
   *     textual envelope field on decode — raise it only for installations
   *     whose identifiers (typically subject ids) are legitimately longer
   *     than the default; the Base64 payload and signature are not subject
   *     to it
   * @since 00.84.00
   */
  public EnvelopeWireCodec(int maxFieldLength) {
    if (maxFieldLength < 1) {
      throw new IllegalArgumentException(
          "maxFieldLength must be >= 1, was " + maxFieldLength);
    }
    this.maxFieldLength = maxFieldLength;
  }

  /**
   * @param envelope the envelope
   * @return its JSON wire form
   */
  public String encode(SignedJCustosEventEnvelope envelope) {
    Map<String, Object> f = metadataFields(envelope);
    f.put(F_CANONICAL_PAYLOAD, ENCODER.encodeToString(envelope.canonicalPayload()));
    f.put(F_SIGNATURE, ENCODER.encodeToString(envelope.signature()));
    return WireJson.writeObject(f);
  }

  /**
   * Secret-free metadata projection for logging / SIEM-style consumers: the
   * same field set as {@link #encode(SignedJCustosEventEnvelope)} minus
   * {@code canonicalPayload} and {@code signature} (the
   * {@code canonicalPayloadHash} is kept). Not decodable back into an
   * envelope — it is a one-way projection.
   *
   * @param envelope the envelope
   * @return the metadata-only JSON form
   * @since 00.80.00
   */
  public String encodeMetadata(SignedJCustosEventEnvelope envelope) {
    return WireJson.writeObject(metadataFields(envelope));
  }

  private static Map<String, Object> metadataFields(SignedJCustosEventEnvelope envelope) {
    Map<String, Object> f = new LinkedHashMap<>();
    f.put(F_ENVELOPE_ID, envelope.envelopeId().value());
    f.put(F_EVENT_ID, envelope.eventId().value());
    f.put(F_EVENT_TYPE, envelope.eventType().value());
    f.put(F_TENANT_ID, envelope.tenantId().value());
    f.put(F_SUBJECT_ID, envelope.subjectId().value());
    f.put(F_PRODUCER_ID, envelope.producerId().value());
    f.put(F_OCCURRED_AT, envelope.occurredAt().toString());
    f.put(F_ISSUED_AT, envelope.issuedAt().toString());
    f.put(F_EXPIRES_AT, envelope.expiresAt().toString());
    f.put(F_CORRELATION_ID, envelope.correlationId().value());
    if (envelope.causationId() != null) {
      f.put(F_CAUSATION_ID, envelope.causationId().value());
    }
    f.put(F_SEQUENCE, envelope.sequence().value());
    f.put(F_KEY_ID, envelope.keyId().value());
    f.put(F_SIGNATURE_ALGORITHM, envelope.signatureAlgorithm().value());
    f.put(F_PAYLOAD_CONTENT_TYPE, envelope.payloadContentType().value());
    f.put(F_PAYLOAD_HASH_ALGORITHM, envelope.payloadHashAlgorithm().value());
    f.put(F_CANONICAL_PAYLOAD_HASH, envelope.canonicalPayloadHash());
    return f;
  }

  /**
   * Decodes a wire envelope, capturing any malformed-input failure in the
   * error channel instead of throwing — the caller (e.g. the publish endpoint)
   * maps it to a 400 rather than catching an exception.
   *
   * @param json the JSON wire form
   * @return the decoded envelope on success, or a short error description on
   *     malformed / incomplete input
   */
  public Result<SignedJCustosEventEnvelope, String> decode(String json) {
    CheckedSupplier<SignedJCustosEventEnvelope> step = () -> decodeOrThrow(json);
    return step.get().mapError(t -> scrub(t.getClass().getSimpleName()
        + (t.getMessage() == null ? "" : ": " + t.getMessage())));
  }

  // JS-SEC-019 (CWE-117): parse-exception messages embed attacker-influenced
  // wire fragments; neutralise everything that can break or reorder a log line
  // when a consumer (e.g. the publish endpoint) logs this error. JS-SEC-110:
  // the shared scrubber also covers the Unicode line separators and format
  // characters the former ISO-control filter let through.
  private static String scrub(String s) {
    return LogFieldScrubber.scrubMessage(s);
  }

  private SignedJCustosEventEnvelope decodeOrThrow(String json) {
    Map<String, Object> f = WireJson.parseObject(json);
    SignedJCustosEventEnvelopeBuilder builder = SignedJCustosEventEnvelopeBuilder.create()
        .envelopeId(EventEnvelopeId.of(str(f, F_ENVELOPE_ID)))
        .eventId(EventId.of(str(f, F_EVENT_ID)))
        .eventType(EventType.of(str(f, F_EVENT_TYPE)))
        .tenantId(TenantId.of(str(f, F_TENANT_ID)))
        .subjectId(SubjectId.of(str(f, F_SUBJECT_ID)))
        .producerId(EventProducerId.of(str(f, F_PRODUCER_ID)))
        .occurredAt(Instant.parse(str(f, F_OCCURRED_AT)))
        .issuedAt(Instant.parse(str(f, F_ISSUED_AT)))
        .expiresAt(Instant.parse(str(f, F_EXPIRES_AT)))
        .correlationId(CorrelationId.of(str(f, F_CORRELATION_ID)))
        .sequence(EventSequence.of(num(f, F_SEQUENCE)))
        .keyId(KeyId.of(str(f, F_KEY_ID)))
        .signatureAlgorithm(SignatureAlgorithmId.of(str(f, F_SIGNATURE_ALGORITHM)))
        .payloadContentType(PayloadContentType.of(str(f, F_PAYLOAD_CONTENT_TYPE)))
        .payloadHashAlgorithm(PayloadHashAlgorithm.of(str(f, F_PAYLOAD_HASH_ALGORITHM)))
        .canonicalPayloadHash(str(f, F_CANONICAL_PAYLOAD_HASH))
        .canonicalPayload(DECODER.decode(raw(f, F_CANONICAL_PAYLOAD)))
        .signature(DECODER.decode(raw(f, F_SIGNATURE)));
    if (f.get(F_CAUSATION_ID) instanceof String) {
      builder.causationId(CausationId.of(str(f, F_CAUSATION_ID)));
    }
    return builder.build();
  }

  // Textual metadata field: present, a string, and within the length bound.
  // The message carries the field name and the lengths only, never the value.
  private String str(Map<String, Object> f, String key) {
    String s = raw(f, key);
    if (s.length() > maxFieldLength) {
      throw new EventWireException("field '" + key + "' is too long: " + s.length()
          + " characters, at most " + maxFieldLength + " are accepted");
    }
    return s;
  }

  // Base64 body field (payload, signature): bounded by the transport's body
  // limit, not by the identifier bound.
  private static String raw(Map<String, Object> f, String key) {
    Object value = f.get(key);
    if (!(value instanceof String s)) {
      throw new EventWireException("missing or non-string field '" + key + "'");
    }
    return s;
  }

  private static long num(Map<String, Object> f, String key) {
    Object value = f.get(key);
    if (!(value instanceof Long l)) {
      throw new EventWireException("missing or non-numeric field '" + key + "'");
    }
    return l;
  }
}
