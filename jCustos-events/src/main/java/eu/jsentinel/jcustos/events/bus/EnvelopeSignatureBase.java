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

import eu.jsentinel.jcustos.events.api.CausationId;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * Builds the deterministic signature base over the security-relevant envelope
 * metadata (Konzept §353-§373). The payload is bound through {@code
 * canonicalPayloadHash}; the raw payload bytes are <em>not</em> part of the
 * base, so the verifier can check the payload hash first and the signature base
 * afterwards.
 *
 * <p>Each field is emitted <strong>length-prefixed</strong>
 * ({@code key '=' <utf8-byte-length> ':' value '\n'}). The explicit byte length
 * makes the encoding unambiguous for <em>any</em> value content — a value
 * containing {@code '='} or {@code '\n'} cannot be reframed as a different
 * field set. The base is therefore injective over the field tuple without
 * relying on the value types rejecting the separator (V00.75.10, R005:
 * the previous {@code key=value\n} framing rested on that unenforced invariant).
 * Injectivity also needs every value to have exactly one UTF-8 encoding: a
 * value that is not well-formed UTF-16 is refused with an
 * {@link IllegalArgumentException} rather than encoded lossily (JS-SEC-111).
 * The bytes for every well-formed value are unchanged.
 *
 * <p><strong>Wire-format note:</strong> this changed the signing base in
 * V00.75.10; signatures produced by V00.75.00 do not verify under it. The event
 * bus is {@code @ExperimentalJCustosApi}, so the format may still change.
 */
final class EnvelopeSignatureBase {

  private EnvelopeSignatureBase() {
  }

  static byte[] compute(SignedJCustosEventEnvelope e) {
    ByteArrayOutputStream out = new ByteArrayOutputStream(256);
    field(out, "envelopeId", e.envelopeId().value());
    field(out, "eventId", e.eventId().value());
    field(out, "eventType", e.eventType().value());
    field(out, "tenantId", e.tenantId().value());
    field(out, "subjectId", e.subjectId().value());
    field(out, "producerId", e.producerId().value());
    field(out, "occurredAt", e.occurredAt().toString());
    field(out, "issuedAt", e.issuedAt().toString());
    field(out, "expiresAt", e.expiresAt().toString());
    field(out, "correlationId", e.correlationId().value());
    CausationId causation = e.causationId();
    field(out, "causationId", causation == null ? "" : causation.value());
    field(out, "sequence", Long.toString(e.sequence().value()));
    field(out, "keyId", e.keyId().value());
    field(out, "signatureAlgorithm", e.signatureAlgorithm().value());
    field(out, "payloadContentType", e.payloadContentType().value());
    field(out, "payloadHashAlgorithm", e.payloadHashAlgorithm().value());
    field(out, "canonicalPayloadHash", e.canonicalPayloadHash());
    return out.toByteArray();
  }

  private static void field(ByteArrayOutputStream out, String key, String value) {
    byte[] v = strictUtf8(key, value);
    out.writeBytes((key + '=' + v.length + ':').getBytes(StandardCharsets.UTF_8));
    out.writeBytes(v);
    out.write('\n');
  }

  // JS-SEC-111 (CWE-176, CWE-347): String#getBytes(UTF_8) replaces an unpaired
  // surrogate by '?', so "a?b" and 'a', U+D800, 'b' produced the same base and
  // a signed '?' could be swapped for a lone surrogate without invalidating the
  // signature. A reporting encoder turns such a value into an error instead;
  // every encodable value yields exactly the bytes getBytes produced.
  static byte[] strictUtf8(String key, String value) {
    try {
      ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .encode(CharBuffer.wrap(value));
      byte[] bytes = new byte[encoded.remaining()];
      encoded.get(bytes);
      return bytes;
    } catch (CharacterCodingException malformed) {
      throw new IllegalArgumentException("envelope field '" + key
          + "' is not well-formed UTF-16 and cannot enter the signature base", malformed);
    }
  }
}
