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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.bus.ConsumePipeline;
import eu.jsentinel.jcustos.events.bus.JCustosEventVerificationResult;
import eu.jsentinel.jcustos.events.replay.InMemoryReplayStore;
import eu.jsentinel.jcustos.events.sequence.InMemorySequenceStore;
import eu.jsentinel.jcustos.events.sequence.SequenceValidator;
import eu.jsentinel.jcustos.events.sequence.SequenceViolationStrategy;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithms;
import eu.jsentinel.jcustos.events.types.LoginSucceededEvent;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Wire-level regression tests of the 2026-11-10 security analysis: field
 * length bound (JS-SEC-104), Unicode line separators (JS-SEC-110) and
 * unpaired surrogates (JS-SEC-111). Real signing and verification. No mocks.
 */
@DisplayName("EnvelopeWireCodec / WireJson — hardening (JS-SEC-104, -110, -111)")
class EnvelopeWireHardeningTest {

  private final EnvelopeWireCodec codec = new EnvelopeWireCodec();
  private final WireFixtures fx = new WireFixtures();

  private SignedJCustosEventEnvelope signedFor(String subject) {
    EventMetadata meta = EventMetadata.create(TenantId.DEFAULT, SubjectId.of(subject),
        WireFixtures.T0, JCustosEventSeverity.INFO);
    return fx.newPublishPipeline().toEnvelope(new LoginSucceededEvent(meta, "password"));
  }

  private ConsumePipeline consumer() {
    return new ConsumePipeline(fx.keyManagement, SignatureAlgorithms.defaults(),
        new InMemoryReplayStore(), new InMemorySequenceStore(), new SequenceValidator(),
        SequenceViolationStrategy.REJECT, fx.allowAll);
  }

  private static List<String> lines(String text) {
    List<String> lines = new ArrayList<>();
    try (Scanner scanner = new Scanner(text)) {
      while (scanner.hasNextLine()) {
        lines.add(scanner.nextLine());
      }
    }
    return lines;
  }

  // ---- JS-SEC-111 ----------------------------------------------------------

  @Test
  @DisplayName("JS-SEC-111: a signed '?' cannot be swapped for a lone surrogate on the wire")
  void loneSurrogateEscapeIsADecodeError() {
    SignedJCustosEventEnvelope signed = signedFor("a?b");
    String wire = codec.encode(signed);
    assertTrue(wire.contains("\"subjectId\":\"a?b\""));
    // the transport attacker rewrites the signed '?' into an escaped lone surrogate
    String swapped = wire.replace("\"subjectId\":\"a?b\"", "\"subjectId\":\"a\\ud800b\"");
    assertFalse(wire.equals(swapped));

    assertTrue(codec.decode(swapped).isFailure(),
        "an envelope with an unpaired surrogate must not decode");
    // the untouched envelope still decodes and verifies
    SignedJCustosEventEnvelope decoded = codec.decode(wire).getOrThrow();
    assertEquals(signed, decoded);
    assertTrue(consumer().verify(decoded, WireFixtures.T0).isValid());
  }

  @Test
  @DisplayName("JS-SEC-111: lone surrogates are refused raw, escaped, high, low and reversed")
  void everyFormOfLoneSurrogateIsRefused() {
    for (String value : List.of(
        "a\\ud800b",                 // escaped lone high surrogate
        "a\\udc00b",                 // escaped lone low surrogate
        "a\\udc00\\ud800b",          // escaped pair in the wrong order
        "a\\ud800",                  // high surrogate at the end
        "a" + (char) 0xD800 + "b",   // raw lone high surrogate
        "a" + (char) 0xDC00 + "b")) {
      assertThrows(EventWireException.class,
          () -> WireJson.parseObject("{\"subjectId\":\"" + value + "\"}"), value);
    }
  }

  @Test
  @DisplayName("JS-SEC-111: a proper surrogate pair still round-trips and verifies")
  void surrogatePairStillWorks() {
    String emoji = new String(Character.toChars(0x1F600));
    SignedJCustosEventEnvelope signed = signedFor("user-" + emoji);

    SignedJCustosEventEnvelope decoded = codec.decode(codec.encode(signed)).getOrThrow();

    assertEquals(signed, decoded);
    assertTrue(consumer().verify(decoded, WireFixtures.T0).isValid());
    assertEquals("user-" + emoji,
        WireJson.parseObject("{\"s\":\"user-\\ud83d\\ude00\"}").get("s"),
        "an escaped pair decodes to the supplementary character");
  }

  // ---- JS-SEC-104 ----------------------------------------------------------

  @Test
  @DisplayName("JS-SEC-104: an identifier field beyond the bound is a decode error that names no value")
  void oversizedFieldIsADecodeError() {
    String wire = codec.encode(fx.signedEnvelope());
    String marker = "ZZ-oversized-ZZ";
    String oversized = wire.replaceFirst("\"envelopeId\":\"[^\"]*\"",
        "\"envelopeId\":\"" + marker + "A".repeat(1_000_000) + "\"");

    String error = codec.decode(oversized).fold(ok -> "", failure -> failure);
    assertTrue(error.contains("envelopeId"), error);
    assertTrue(error.contains(String.valueOf(EnvelopeWireCodec.DEFAULT_MAX_FIELD_LENGTH)), error);
    assertFalse(error.contains(marker), "the error must not echo the value");
    assertTrue(error.length() < 200, "the error itself stays short: " + error.length());
  }

  @Test
  @DisplayName("JS-SEC-104: the bound is inclusive, applies to every textual field and is configurable")
  void boundIsInclusiveAndConfigurable() {
    String wire = codec.encode(fx.signedEnvelope());
    String atLimit = "c".repeat(EnvelopeWireCodec.DEFAULT_MAX_FIELD_LENGTH);
    String overLimit = atLimit + "c";

    assertTrue(codec.decode(wire.replaceFirst("\"correlationId\":\"[^\"]*\"",
        "\"correlationId\":\"" + atLimit + "\"")).isSuccess());
    for (String field : List.of("envelopeId", "eventId", "eventType", "tenantId", "subjectId",
        "producerId", "correlationId", "keyId", "signatureAlgorithm", "payloadContentType",
        "payloadHashAlgorithm", "canonicalPayloadHash")) {
      assertTrue(codec.decode(wire.replaceFirst("\"" + field + "\":\"[^\"]*\"",
          "\"" + field + "\":\"" + overLimit + "\"")).isFailure(), field);
    }
    assertTrue(new EnvelopeWireCodec(1_024).decode(wire.replaceFirst(
        "\"subjectId\":\"[^\"]*\"", "\"subjectId\":\"" + overLimit + "\"")).isSuccess(),
        "an installation with long subject ids raises the bound");
    assertThrows(IllegalArgumentException.class, () -> new EnvelopeWireCodec(0));
  }

  // ---- JS-SEC-110 ----------------------------------------------------------

  @Test
  @DisplayName("JS-SEC-110: Unicode line terminators are escaped, so one envelope is one line")
  void lineTerminatorsAreEscapedOnTheWire() {
    for (int separator : new int[]{0x0085, 0x2028, 0x2029, 0x007F, 0x009F}) {
      String hostile = "x" + (char) separator + "{\"forged\":\"record\"}";
      SignedJCustosEventEnvelope signed = signedFor(hostile);

      String wire = codec.encode(signed);
      String metadata = codec.encodeMetadata(signed);

      assertEquals(1, lines(wire).size(), "U+" + Integer.toHexString(separator));
      assertEquals(1, lines(metadata).size(), "U+" + Integer.toHexString(separator));
      assertTrue(wire.indexOf(separator) < 0, "the raw character must not be on the wire");
      assertTrue(wire.contains(String.format("x\\u%04x", separator)), wire);
      // the escape is plain JSON: the value, and with it the signature, is unchanged
      SignedJCustosEventEnvelope decoded = codec.decode(wire).getOrThrow();
      assertEquals(signed, decoded);
      assertTrue(consumer().verify(decoded, WireFixtures.T0).isValid());
    }
  }

  @Test
  @DisplayName("JS-SEC-110: ordinary text, non-ASCII letters included, is written byte for byte as before")
  void ordinaryTextIsNotEscaped() {
    Map<String, Object> fields = new LinkedHashMap<>();
    fields.put("subjectId", "Zoë Müller <zoe@example.org>");
    fields.put("sequence", 7L);

    assertEquals("{\"subjectId\":\"Zoë Müller <zoe@example.org>\",\"sequence\":7}",
        WireJson.writeObject(fields));
  }

  @Test
  @DisplayName("JS-SEC-110: a decode error carries neither Unicode line separators nor format characters")
  void decodeErrorIsOneLine() {
    String wire = codec.encode(fx.signedEnvelope());
    for (int separator : new int[]{0x2028, 0x2029, 0x0085, 0x202E, 0x000A}) {
      String hostileInstant = "2026" + (char) separator + "FORGED LINE";
      String bad = wire.replaceFirst("\"occurredAt\":\"[^\"]*\"",
          "\"occurredAt\":\"" + hostileInstant + "\"");

      String error = codec.decode(bad).fold(ok -> "", failure -> failure);

      assertFalse(error.isEmpty());
      assertTrue(error.indexOf(separator) < 0, "U+" + Integer.toHexString(separator));
      assertEquals(1, lines(error).size(), error);
      assertTrue(error.contains("2026?FORGED LINE"), error);
    }
  }
}
