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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.function.BiFunction;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * JS-SEC-111: an envelope never carries a textual field with an unpaired
 * surrogate — such a character has no UTF-8 encoding, so it would be signed
 * as {@code '?'} and two different values would share one signature.
 */
@DisplayName("SignedJCustosEventEnvelope — well-formed text only (JS-SEC-111)")
class EnvelopeWellFormedTextTest {

  private static final String LONE_HIGH = "a" + (char) 0xD800 + "b";
  private static final String LONE_LOW = "a" + (char) 0xDC00 + "b";
  private static final String REVERSED = "a" + (char) 0xDC00 + (char) 0xD800 + "b";
  private static final String TRAILING_HIGH = "ab" + (char) 0xD83D;

  private interface FieldSetter
      extends BiFunction<SignedJCustosEventEnvelopeBuilder, String,
          SignedJCustosEventEnvelopeBuilder> {
  }

  static Stream<Arguments> textualFields() {
    return Stream.of(
        arguments("envelopeId", (FieldSetter) (b, v) -> b.envelopeId(EventEnvelopeId.of(v))),
        arguments("eventId", (FieldSetter) (b, v) -> b.eventId(EventId.of(v))),
        arguments("eventType", (FieldSetter) (b, v) -> b.eventType(EventType.of(v))),
        arguments("tenantId", (FieldSetter) (b, v) -> b.tenantId(TenantId.of(v))),
        arguments("subjectId", (FieldSetter) (b, v) -> b.subjectId(SubjectId.of(v))),
        arguments("producerId", (FieldSetter) (b, v) -> b.producerId(EventProducerId.of(v))),
        arguments("correlationId",
            (FieldSetter) (b, v) -> b.correlationId(CorrelationId.of(v))),
        arguments("causationId", (FieldSetter) (b, v) -> b.causationId(CausationId.of(v))),
        arguments("keyId", (FieldSetter) (b, v) -> b.keyId(KeyId.of(v))),
        arguments("signatureAlgorithm",
            (FieldSetter) (b, v) -> b.signatureAlgorithm(SignatureAlgorithmId.of(v))),
        arguments("payloadContentType",
            (FieldSetter) (b, v) -> b.payloadContentType(PayloadContentType.of(v))),
        arguments("payloadHashAlgorithm",
            (FieldSetter) (b, v) -> b.payloadHashAlgorithm(PayloadHashAlgorithm.of(v))),
        arguments("canonicalPayloadHash", (FieldSetter) (b, v) -> b.canonicalPayloadHash(v)));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("textualFields")
  @DisplayName("an unpaired surrogate in any textual field is rejected on construction")
  void unpairedSurrogateIsRejected(String field, FieldSetter setter) {
    for (String malformed : new String[]{LONE_HIGH, LONE_LOW, REVERSED, TRAILING_HIGH}) {
      IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
          () -> setter.apply(EnvelopeFixtures.validBuilder(), malformed).build());
      assertTrue(rejected.getMessage().contains("'" + field + "'"), rejected.getMessage());
      assertFalse(rejected.getMessage().contains(malformed),
          "the message names the field, not the value");
    }
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("textualFields")
  @DisplayName("a proper surrogate pair and other non-ASCII text are accepted in every field")
  void wellFormedTextIsAccepted(String field, FieldSetter setter) {
    String emoji = new String(Character.toChars(0x1F600));
    for (String wellFormed : new String[]{"plain", "Zoë-Müller", "x" + emoji, emoji + emoji}) {
      assertDoesNotThrow(
          () -> setter.apply(EnvelopeFixtures.validBuilder(), wellFormed).build(),
          field + " = " + wellFormed);
    }
  }

  @Test
  @DisplayName("an absent causationId is still allowed")
  void absentCausationIdIsStillAllowed() {
    assertEquals(null, EnvelopeFixtures.validBuilder().causationId(null).build().causationId());
  }

  @Test
  @DisplayName("WellFormedText accepts paired surrogates only")
  void wellFormedTextPredicate() {
    String emoji = new String(Character.toChars(0x1F600));
    for (String wellFormed : new String[]{"", "plain", "a?b", emoji, "x" + emoji + "y"}) {
      assertTrue(WellFormedText.isWellFormed(wellFormed), wellFormed);
    }
    for (String malformed : new String[]{LONE_HIGH, LONE_LOW, REVERSED, TRAILING_HIGH,
        String.valueOf((char) 0xDC00), emoji + (char) 0xD800}) {
      assertFalse(WellFormedText.isWellFormed(malformed));
    }
  }
}
