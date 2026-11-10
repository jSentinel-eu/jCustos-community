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
import eu.jsentinel.jcustos.events.api.CausationId;
import eu.jsentinel.jcustos.events.api.CorrelationId;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.types.EnvelopeRejectedEvent;
import eu.jsentinel.jcustos.events.types.LoginSucceededEvent;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("EnvelopeSignatureBase — length-prefixed framing (R005)")
class EnvelopeSignatureBaseTest {

  @Test
  @DisplayName("each field is length-prefixed (key=<bytes>:value)")
  void framingIsLengthPrefixed() {
    BusFixtures fx = new BusFixtures();
    SignedJCustosEventEnvelope base = fx.publishPipeline().toEnvelope(BusFixtures.event());
    SignedJCustosEventEnvelope env = BusFixtures.rebuild(base)
        .correlationId(CorrelationId.of("ab")).build();

    String wire = new String(EnvelopeSignatureBase.compute(env), StandardCharsets.UTF_8);
    // "ab" is 2 UTF-8 bytes → the explicit byte length appears before the value.
    // (The pre-R005 framing emitted "correlationId=ab\n" with no length.)
    assertTrue(wire.contains("correlationId=2:ab\n"),
        "expected length-prefixed field, got:\n" + wire);
  }

  @Test
  @DisplayName("a separator-containing value cannot reframe into a neighbouring field")
  void separatorInValueDoesNotCollide() {
    BusFixtures fx = new BusFixtures();
    SignedJCustosEventEnvelope base = fx.publishPipeline().toEnvelope(BusFixtures.event());

    // The id types only reject blank values — a newline + '=' IS accepted, so
    // this is the exact shape the old framing's unenforced invariant assumed away.
    SignedJCustosEventEnvelope a = BusFixtures.rebuild(base)
        .correlationId(CorrelationId.of("a"))
        .causationId(CausationId.of("b")).build();
    SignedJCustosEventEnvelope b = BusFixtures.rebuild(base)
        .correlationId(CorrelationId.of("a\ncausationId=b"))
        .causationId(CausationId.of("b")).build();

    assertFalse(
        Arrays.equals(EnvelopeSignatureBase.compute(a), EnvelopeSignatureBase.compute(b)),
        "distinct envelopes must never share a signature base");
  }

  @Test
  @DisplayName("JS-SEC-111: a value with an unpaired surrogate has no signature base")
  void unpairedSurrogateIsRefused() {
    for (String malformed : new String[]{
        "a" + (char) 0xD800 + "b",
        "a" + (char) 0xDC00 + "b",
        "a" + (char) 0xDC00 + (char) 0xD800 + "b",
        "ab" + (char) 0xD83D}) {
      IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
          () -> EnvelopeSignatureBase.strictUtf8("subjectId", malformed));
      assertTrue(refused.getMessage().contains("'subjectId'"), refused.getMessage());
      assertFalse(refused.getMessage().contains(malformed),
          "the message names the field, not the value");
    }
    // The collision the lossy encoding produced: both values encoded to "a?b".
    assertArrayEquals("a?b".getBytes(StandardCharsets.UTF_8),
        ("a" + (char) 0xD800 + "b").getBytes(StandardCharsets.UTF_8),
        "String#getBytes replaces the lone surrogate by '?' — the premise of JS-SEC-111");
  }

  @Test
  @DisplayName("JS-SEC-111: every well-formed value encodes to the bytes it always had")
  void wellFormedValuesKeepTheirBytes() {
    String emoji = new String(Character.toChars(0x1F600));
    for (String value : new String[]{"", "a?b", "alice", "Zoë-Müller", "日本語",
        "x" + emoji + "y", "line\nbreak=and|separators", String.valueOf((char) 0x2028)}) {
      assertArrayEquals(value.getBytes(StandardCharsets.UTF_8),
          EnvelopeSignatureBase.strictUtf8("subjectId", value), value);
    }
  }

  @Test
  @DisplayName("JS-SEC-111: publishing an event with an unpaired surrogate is a typed rejection that burns no sequence")
  void publishRefusesUnpairedSurrogate() {
    BusFixtures fx = new BusFixtures();
    PublishPipeline publisher = fx.publishPipeline();
    LoginSucceededEvent malformed = new LoginSucceededEvent(
        EventMetadata.create(TenantId.DEFAULT, SubjectId.of("a" + (char) 0xD800 + "b"),
            BusFixtures.T0, JCustosEventSeverity.INFO), "password");

    EventPublishException rejected =
        assertThrows(EventPublishException.class, () -> publisher.toEnvelope(malformed));

    assertEquals(SelfObservabilityEvents.REASON_MALFORMED_TEXT, rejected.reason());
    assertTrue(rejected.getMessage().contains("'subjectId'"), rejected.getMessage());
    assertTrue(fx.publishSequence.lastSequence(TenantId.DEFAULT, BusFixtures.PRODUCER).isEmpty());
    assertEquals(1L, publisher.toEnvelope(BusFixtures.event()).sequence().value());
  }

  @Test
  @DisplayName("JS-SEC-111: the bus reports such a publish as EnvelopeRejected instead of losing it silently")
  void busReportsMalformedPublish() {
    BusFixtures fx = new BusFixtures();
    DefaultJCustosEventBus bus = new DefaultJCustosEventBus(fx.publishPipeline());
    List<EnvelopeRejectedEvent> rejections = new ArrayList<>();
    bus.subscribe(EnvelopeRejectedEvent.class, rejections::add);
    LoginSucceededEvent malformed = new LoginSucceededEvent(
        EventMetadata.create(TenantId.DEFAULT, SubjectId.of("a" + (char) 0xDC00 + "b"),
            BusFixtures.T0, JCustosEventSeverity.INFO), "password");

    assertThrows(EventPublishException.class, () -> bus.publish(malformed));

    assertEquals(1, rejections.size());
    assertEquals("malformed-text", rejections.get(0).reason());
    assertEquals(malformed.eventId().value(), rejections.get(0).rejectedEnvelopeId());
    // the producer-policy rejection keeps its own reason
    assertEquals(SelfObservabilityEvents.REASON_PRODUCER_NOT_ALLOWED,
        new EventPublishException("denied").reason());
  }
}
