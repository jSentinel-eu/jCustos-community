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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.PayloadContentType;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.codec.CanonicalJCustosEventPayload;
import eu.jsentinel.jcustos.events.codec.CanonicalJsonPayloadCodec;
import eu.jsentinel.jcustos.events.codec.PayloadCodec;
import eu.jsentinel.jcustos.events.sequence.SequenceValidator;
import eu.jsentinel.jcustos.events.sequence.SequenceViolationStrategy;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithms;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.TreeMap;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * JS-SEC-107: the payload repeats event type, event id, tenant, subject and
 * time; a producer with a valid key and one allowed event type must not be
 * able to ship a payload that says something else than the signed envelope.
 * The contradicting envelopes are signed with the producer's real key. No mocks.
 */
@DisplayName("ConsumePipeline — payload metadata check (JS-SEC-107)")
class PayloadMetadataCheckTest {

  private final BusFixtures fx = new BusFixtures();
  private final SignedJCustosEventEnvelope genuine =
      fx.publishPipeline().toEnvelope(BusFixtures.event());
  private final CanonicalJCustosEventPayload genuinePayload =
      new CanonicalJsonPayloadCodec().decode(genuine.canonicalPayload());

  /** The genuine envelope, re-signed by its producer around a different payload. */
  private SignedJCustosEventEnvelope resignedWith(CanonicalJCustosEventPayload payload) {
    return SignedEnvelopes.sign(
        SignedEnvelopes.withPayload(BusFixtures.rebuild(genuine), payload), fx.keyManagement);
  }

  private static CanonicalJCustosEventPayload copy(CanonicalJCustosEventPayload p,
      String eventType, String eventId, String tenantId, String subjectId, String occurredAt) {
    return new CanonicalJCustosEventPayload(p.schemaVersion(), eventType, eventId, tenantId,
        subjectId, occurredAt, p.severity(), p.category(), p.attributes());
  }

  static Stream<Arguments> contradictions() {
    return Stream.of(
        arguments(ConsumePipeline.FIELD_EVENT_TYPE,
            (UnaryOperator<CanonicalJCustosEventPayload>) p -> copy(p, "RoleAssigned",
                p.eventId(), p.tenantId(), p.subjectId(), p.occurredAt())),
        arguments(ConsumePipeline.FIELD_EVENT_ID,
            (UnaryOperator<CanonicalJCustosEventPayload>) p -> copy(p, p.eventType(),
                "another-event", p.tenantId(), p.subjectId(), p.occurredAt())),
        arguments(ConsumePipeline.FIELD_TENANT_ID,
            (UnaryOperator<CanonicalJCustosEventPayload>) p -> copy(p, p.eventType(),
                p.eventId(), "globex", p.subjectId(), p.occurredAt())),
        arguments(ConsumePipeline.FIELD_SUBJECT_ID,
            (UnaryOperator<CanonicalJCustosEventPayload>) p -> copy(p, p.eventType(),
                p.eventId(), p.tenantId(), "mallory", p.occurredAt())),
        arguments(ConsumePipeline.FIELD_OCCURRED_AT,
            (UnaryOperator<CanonicalJCustosEventPayload>) p -> copy(p, p.eventType(),
                p.eventId(), p.tenantId(), p.subjectId(), "2020-01-01T00:00:00Z")),
        arguments(ConsumePipeline.FIELD_OCCURRED_AT,
            (UnaryOperator<CanonicalJCustosEventPayload>) p -> copy(p, p.eventType(),
                p.eventId(), p.tenantId(), p.subjectId(), "yesterday")));
  }

  @ParameterizedTest(name = "payload deviates in {0}")
  @MethodSource("contradictions")
  @DisplayName("a payload that contradicts the signed envelope is rejected without side effects")
  void contradictingPayloadIsRejected(String field,
      UnaryOperator<CanonicalJCustosEventPayload> tamper) {
    SignedJCustosEventEnvelope contradicting = resignedWith(tamper.apply(genuinePayload));

    JCustosEventVerificationResult result =
        fx.consumePipeline().verify(contradicting, BusFixtures.T0);

    JCustosEventVerificationResult.PayloadMetadataMismatch mismatch = assertInstanceOf(
        JCustosEventVerificationResult.PayloadMetadataMismatch.class, result);
    assertEquals(field, mismatch.field());
    assertEquals(contradicting.envelopeId(), mismatch.envelopeId());
    assertTrue(result.envelopeAuthenticated());
    assertFalse(fx.consumeReplay.hasSeen(contradicting.envelopeId()),
        "a rejected envelope must not be recorded in the replay store");
    assertTrue(fx.consumeSequence.lastSequence(TenantId.DEFAULT, BusFixtures.PRODUCER).isEmpty(),
        "a rejected envelope must not advance the sequence");
  }

  @Test
  @DisplayName("the PoC: an allowed envelope type around a RoleAssigned payload for another tenant")
  void allowedEnvelopeAroundPrivilegedPayload() {
    TreeMap<String, String> attributes = new TreeMap<>();
    attributes.put("role", "ADMIN");
    CanonicalJCustosEventPayload privileged = new CanonicalJCustosEventPayload(
        CanonicalJCustosEventPayload.SCHEMA_VERSION, "RoleAssigned", genuinePayload.eventId(),
        "globex", "mallory", genuinePayload.occurredAt(), "INFO", "ADMIN", attributes);

    assertInstanceOf(JCustosEventVerificationResult.PayloadMetadataMismatch.class,
        fx.consumePipeline().verify(resignedWith(privileged), BusFixtures.T0));
  }

  @Test
  @DisplayName("a consistent envelope stays Valid and hands the checked payload to the consumer")
  void consistentEnvelopeCarriesItsPayload() {
    JCustosEventVerificationResult result = fx.consumePipeline().verify(genuine, BusFixtures.T0);

    JCustosEventVerificationResult.Valid valid =
        assertInstanceOf(JCustosEventVerificationResult.Valid.class, result);
    assertNotNull(valid.payload());
    assertEquals(genuinePayload, valid.payload());
    assertEquals(genuine.eventType().value(), valid.payload().eventType());
    assertEquals("password", valid.payload().attributes().get("authenticationMethod"));
  }

  @Test
  @DisplayName("the same instant rendered differently in the payload still matches")
  void equivalentInstantRenderingMatches() {
    // BusFixtures.T0 renders as ...T10:00:00Z; a non-Java producer may write the millis.
    CanonicalJCustosEventPayload millis = copy(genuinePayload, genuinePayload.eventType(),
        genuinePayload.eventId(), genuinePayload.tenantId(), genuinePayload.subjectId(),
        "2026-06-24T10:00:00.000Z");

    assertTrue(fx.consumePipeline().verify(resignedWith(millis), BusFixtures.T0).isValid());
  }

  @Test
  @DisplayName("a payload the codec cannot decode is rejected, not thrown")
  void undecodablePayloadIsRejected() {
    for (String bytes : List.of("{\"id\":\"x\"}", "not json", "", "[[[[[[[[")) {
      SignedJCustosEventEnvelope undecodable = SignedEnvelopes.sign(
          SignedEnvelopes.withPayloadBytes(BusFixtures.rebuild(genuine),
              bytes.getBytes(StandardCharsets.UTF_8)), fx.keyManagement);

      JCustosEventVerificationResult.PayloadMetadataMismatch mismatch = assertInstanceOf(
          JCustosEventVerificationResult.PayloadMetadataMismatch.class,
          fx.consumePipeline().verify(undecodable, BusFixtures.T0), bytes);
      assertEquals(ConsumePipeline.FIELD_PAYLOAD, mismatch.field());
    }
  }

  /** The genuine envelope, re-signed by its producer around the given payload text. */
  private SignedJCustosEventEnvelope resignedWithText(String payload) {
    return SignedEnvelopes.sign(SignedEnvelopes.withPayloadBytes(BusFixtures.rebuild(genuine),
        payload.getBytes(StandardCharsets.UTF_8)), fx.keyManagement);
  }

  @Test
  @DisplayName("a signed payload that names tenantId twice is rejected, whichever value comes last")
  void duplicateKeyInSignedPayloadIsRejected() {
    String canonical = new String(genuine.canonicalPayload(), StandardCharsets.UTF_8);
    String tenantKey = "\"tenantId\":\"" + genuine.tenantId().value() + "\"";
    assertTrue(canonical.contains(tenantKey), canonical);
    // A last-key-wins reader sees the envelope's tenant, a first-key-wins
    // reader sees globex: the signature covers both readings.
    String twoTenants = canonical.replace(tenantKey, "\"tenantId\":\"globex\"," + tenantKey);

    JCustosEventVerificationResult.PayloadMetadataMismatch mismatch = assertInstanceOf(
        JCustosEventVerificationResult.PayloadMetadataMismatch.class,
        fx.consumePipeline().verify(resignedWithText(twoTenants), BusFixtures.T0));
    assertEquals(ConsumePipeline.FIELD_PAYLOAD, mismatch.field());
  }

  @Test
  @DisplayName("a signed payload in another spelling than the codec writes is rejected")
  void nonCanonicalSpellingIsRejected() {
    String canonical = new String(genuine.canonicalPayload(), StandardCharsets.UTF_8);
    String tenantKey = "\"tenantId\":";
    assertTrue(canonical.contains(tenantKey), canonical);
    List<String> respelled = List.of(
        canonical.replace(tenantKey, "\"tenant\\u0049d\":"),
        canonical.replace(tenantKey, "\"tenantId\" : "),
        " " + canonical);

    for (String variant : respelled) {
      // Each variant decodes to the genuine payload ...
      assertEquals(genuinePayload,
          new CanonicalJsonPayloadCodec().decode(variant.getBytes(StandardCharsets.UTF_8)),
          variant);
      // ... but is not the spelling the signature should cover.
      JCustosEventVerificationResult.PayloadMetadataMismatch mismatch = assertInstanceOf(
          JCustosEventVerificationResult.PayloadMetadataMismatch.class,
          fx.consumePipeline().verify(resignedWithText(variant), BusFixtures.T0), variant);
      assertEquals(ConsumePipeline.FIELD_PAYLOAD, mismatch.field());
    }
    assertTrue(fx.consumePipeline().verify(resignedWithText(canonical), BusFixtures.T0).isValid(),
        "the canonical spelling itself stays valid");
  }

  @Test
  @DisplayName("an envelope with a content type no codec is registered for is rejected")
  void unknownContentTypeIsRejected() {
    SignedJCustosEventEnvelope foreign = SignedEnvelopes.sign(
        BusFixtures.rebuild(genuine).payloadContentType(PayloadContentType.ECLIPSE_SERIALIZER),
        fx.keyManagement);

    JCustosEventVerificationResult.PayloadMetadataMismatch mismatch = assertInstanceOf(
        JCustosEventVerificationResult.PayloadMetadataMismatch.class,
        fx.consumePipeline().verify(foreign, BusFixtures.T0));
    assertEquals(ConsumePipeline.FIELD_PAYLOAD_CONTENT_TYPE, mismatch.field());
  }

  @Test
  @DisplayName("a codec registered for another content type is used for it; duplicates are refused")
  void additionalCodecIsUsedForItsContentType() {
    PayloadCodec relabelled = new PayloadCodec() {
      private final CanonicalJsonPayloadCodec json = new CanonicalJsonPayloadCodec();

      @Override
      public PayloadContentType contentType() {
        return PayloadContentType.ECLIPSE_SERIALIZER;
      }

      @Override
      public byte[] encode(CanonicalJCustosEventPayload payload) {
        return json.encode(payload);
      }

      @Override
      public CanonicalJCustosEventPayload decode(byte[] bytes) {
        return json.decode(bytes);
      }
    };
    SignedJCustosEventEnvelope foreign = SignedEnvelopes.sign(
        BusFixtures.rebuild(genuine).payloadContentType(PayloadContentType.ECLIPSE_SERIALIZER),
        fx.keyManagement);
    ConsumePipeline consumer = new ConsumePipeline(fx.keyManagement,
        SignatureAlgorithms.defaults(), fx.consumeReplay, fx.consumeSequence,
        new SequenceValidator(), SequenceViolationStrategy.REJECT, fx.allowAll,
        List.of(new CanonicalJsonPayloadCodec(), relabelled));

    assertTrue(consumer.verify(foreign, BusFixtures.T0).isValid());
    assertThrows(IllegalArgumentException.class, () -> new ConsumePipeline(fx.keyManagement,
        SignatureAlgorithms.defaults(), fx.consumeReplay, fx.consumeSequence,
        new SequenceValidator(), SequenceViolationStrategy.REJECT, fx.allowAll,
        List.of(new CanonicalJsonPayloadCodec(), new CanonicalJsonPayloadCodec())));
  }
}
