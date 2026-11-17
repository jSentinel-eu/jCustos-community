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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SignedJCustosEventEnvelopeBuilder")
class EnvelopeBuilderTest {

  @Test
  @DisplayName("a fully-populated builder produces an envelope")
  void buildsWhenComplete() {
    SignedJCustosEventEnvelope envelope = EnvelopeFixtures.validBuilder().build();
    assertEquals(EventEnvelopeId.of("env-1"), envelope.envelopeId());
    assertEquals(EventType.of("LoginSucceeded"), envelope.eventType());
    assertEquals(EventSequence.of(7), envelope.sequence());
    assertEquals("abc123", envelope.canonicalPayloadHash());
  }

  @Test
  @DisplayName("a missing causationId is allowed (root events have no cause)")
  void causationIdIsOptional() {
    SignedJCustosEventEnvelope envelope =
        EnvelopeFixtures.validBuilder().causationId(null).build();
    assertEquals(null, envelope.causationId());
  }

  @Test
  @DisplayName("null envelopeId throws on build")
  void envelopeIdRequired() {
    assertThrows(NullPointerException.class,
        () -> EnvelopeFixtures.validBuilder().envelopeId(null).build());
  }

  @Test
  @DisplayName("null eventId throws on build")
  void eventIdRequired() {
    assertThrows(NullPointerException.class,
        () -> EnvelopeFixtures.validBuilder().eventId(null).build());
  }

  @Test
  @DisplayName("null eventType throws on build")
  void eventTypeRequired() {
    assertThrows(NullPointerException.class,
        () -> EnvelopeFixtures.validBuilder().eventType(null).build());
  }

  @Test
  @DisplayName("null subjectId throws on build")
  void subjectIdRequired() {
    assertThrows(NullPointerException.class,
        () -> EnvelopeFixtures.validBuilder().subjectId(null).build());
  }

  @Test
  @DisplayName("null producerId throws on build")
  void producerIdRequired() {
    assertThrows(NullPointerException.class,
        () -> EnvelopeFixtures.validBuilder().producerId(null).build());
  }

  @Test
  @DisplayName("null occurredAt / issuedAt / expiresAt throw on build")
  void instantsRequired() {
    assertThrows(NullPointerException.class,
        () -> EnvelopeFixtures.validBuilder().occurredAt(null).build());
    assertThrows(NullPointerException.class,
        () -> EnvelopeFixtures.validBuilder().issuedAt(null).build());
    assertThrows(NullPointerException.class,
        () -> EnvelopeFixtures.validBuilder().expiresAt(null).build());
  }

  @Test
  @DisplayName("ER27: an expiresAt before issuedAt throws on build and names no value; equal instants are allowed")
  void acceptanceWindowMustNotEndBeforeItBegins() {
    Instant before = EnvelopeFixtures.ISSUED.minusMillis(1);
    IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
        () -> EnvelopeFixtures.validBuilder().expiresAt(before).build());
    assertTrue(refused.getMessage().contains("'expiresAt'"), refused.getMessage());
    assertTrue(refused.getMessage().contains("'issuedAt'"), refused.getMessage());
    assertFalse(refused.getMessage().contains(before.toString()),
        "the message must not echo the value");

    SignedJCustosEventEnvelope zeroWindow = EnvelopeFixtures.validBuilder()
        .expiresAt(EnvelopeFixtures.ISSUED).build();
    assertEquals(zeroWindow.issuedAt(), zeroWindow.expiresAt());
  }

  @Test
  @DisplayName("null correlationId throws on build")
  void correlationIdRequired() {
    assertThrows(NullPointerException.class,
        () -> EnvelopeFixtures.validBuilder().correlationId(null).build());
  }

  @Test
  @DisplayName("null sequence / keyId / algorithm / codec / hash-algo throw on build")
  void cryptoMetadataRequired() {
    assertThrows(NullPointerException.class,
        () -> EnvelopeFixtures.validBuilder().sequence(null).build());
    assertThrows(NullPointerException.class,
        () -> EnvelopeFixtures.validBuilder().keyId(null).build());
    assertThrows(NullPointerException.class,
        () -> EnvelopeFixtures.validBuilder().signatureAlgorithm(null).build());
    assertThrows(NullPointerException.class,
        () -> EnvelopeFixtures.validBuilder().payloadContentType(null).build());
    assertThrows(NullPointerException.class,
        () -> EnvelopeFixtures.validBuilder().payloadHashAlgorithm(null).build());
  }

  @Test
  @DisplayName("null or blank canonicalPayloadHash throws on build")
  void payloadHashRequired() {
    assertThrows(IllegalArgumentException.class,
        () -> EnvelopeFixtures.validBuilder().canonicalPayloadHash(null).build());
    assertThrows(IllegalArgumentException.class,
        () -> EnvelopeFixtures.validBuilder().canonicalPayloadHash("  ").build());
  }

  @Test
  @DisplayName("null canonicalPayload / signature bytes throw on build")
  void payloadBytesRequired() {
    assertThrows(NullPointerException.class,
        () -> EnvelopeFixtures.validBuilder().canonicalPayload(null).build());
    assertThrows(NullPointerException.class,
        () -> EnvelopeFixtures.validBuilder().signature(null).build());
  }

  @Test
  @DisplayName("byte[] fields are defensively copied in and out")
  void byteArraysAreDefensivelyCopied() {
    byte[] payload = "mutate-me".getBytes(StandardCharsets.UTF_8);
    SignedJCustosEventEnvelope envelope =
        EnvelopeFixtures.validBuilder().canonicalPayload(payload).build();

    payload[0] = 0; // mutate caller's array after build
    byte[] stored = envelope.canonicalPayload();
    assertFalse(stored[0] == 0, "envelope must not reflect post-build caller mutation");

    stored[0] = 99; // mutate the returned copy
    assertNotSame(envelope.canonicalPayload(), stored);
    assertFalse(envelope.canonicalPayload()[0] == 99,
        "accessor must hand out a fresh copy each call");
  }

  @Test
  @DisplayName("equals / hashCode use content semantics over the byte[] fields")
  void valueSemantics() {
    SignedJCustosEventEnvelope a = EnvelopeFixtures.validBuilder().build();
    SignedJCustosEventEnvelope b = EnvelopeFixtures.validBuilder().build();
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());

    SignedJCustosEventEnvelope different = EnvelopeFixtures.validBuilder()
        .signature(new byte[]{9, 9, 9}).build();
    assertFalse(a.equals(different));
  }

  @Test
  @DisplayName("isExpiredAt compares against the acceptance window")
  void expiryWindow() {
    SignedJCustosEventEnvelope envelope = EnvelopeFixtures.validBuilder().build();
    assertFalse(envelope.isExpiredAt(EnvelopeFixtures.ISSUED));
    assertTrue(envelope.isExpiredAt(EnvelopeFixtures.EXPIRES.plusSeconds(1)));
  }

  @Test
  @DisplayName("toString stays secret-free (no raw payload / signature bytes)")
  void toStringIsSecretFree() {
    String text = EnvelopeFixtures.validBuilder().build().toString();
    assertTrue(text.contains("LoginSucceeded"));
    // raw payload content must not leak; only its length is shown
    assertFalse(text.contains("\"k\":\"v\""));
    assertTrue(Arrays.asList(text.split(" ")).stream().anyMatch(s -> s.contains("B")));
  }
}
