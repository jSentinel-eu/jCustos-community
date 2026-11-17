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
import eu.jsentinel.jcustos.events.api.EventEnvelopeId;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.keys.InMemoryKeyManagement;
import eu.jsentinel.jcustos.events.keys.JCustosEventVerificationKeyResolver;
import eu.jsentinel.jcustos.events.keys.KeyStatus;
import eu.jsentinel.jcustos.events.publisher.JCustosAlert;
import eu.jsentinel.jcustos.events.publisher.JCustosAlertPublisher;
import eu.jsentinel.jcustos.events.sequence.SequenceValidator;
import eu.jsentinel.jcustos.events.sequence.SequenceViolationStrategy;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithms;
import eu.jsentinel.jcustos.events.store.InMemoryDeadLetterStore;
import eu.jsentinel.jcustos.events.types.DeadLetteredEvent;
import eu.jsentinel.jcustos.events.types.EnvelopeRejectedEvent;
import eu.jsentinel.jcustos.events.types.LoginSucceededEvent;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-104: a caller without any key floods the ingest path with envelopes
 * that claim a foreign tenant. Real bus, real alert publisher, real consume
 * pipeline and failure handler; the bus listener that collects every event
 * stands where an audit chain would be subscribed. No mocks.
 */
@DisplayName("ConsumeFailureHandler — unauthenticated rejections (JS-SEC-104)")
class UnauthenticatedRejectionFloodTest {

  private static final TenantId VICTIM = TenantId.of("victim-tenant");

  private final BusFixtures fx = new BusFixtures();
  private final DefaultJCustosEventBus bus = new DefaultJCustosEventBus(fx.publishPipeline());
  private final List<JCustosAlert> alerts = new ArrayList<>();
  private final List<JCustosEvent> chained = new ArrayList<>();
  private final AtomicReference<Instant> now = new AtomicReference<>(BusFixtures.T0);
  private final SignedJCustosEventEnvelope genuine =
      fx.publishPipeline().toEnvelope(BusFixtures.event());

  UnauthenticatedRejectionFloodTest() {
    new JCustosAlertPublisher(alerts::add).subscribeTo(bus);
    bus.subscribe(JCustosEvent.class, chained::add);
  }

  /** No key needed: an unknown key id, a tenant of the sender's choosing, an oversized id. */
  private SignedJCustosEventEnvelope junk(int n) {
    return BusFixtures.rebuild(genuine)
        .keyId(KeyId.of("nope"))
        .tenantId(VICTIM)
        .envelopeId(EventEnvelopeId.of("X".repeat(4_000) + n))
        .build();
  }

  @Test
  @DisplayName("1000 unsigned envelopes raise a bounded number of alerts, none under the claimed tenant")
  void floodIsBoundedAndNotAttributedToTheClaimedTenant() {
    ConsumePipeline consumer = fx.consumePipeline();
    ConsumeFailureHandler handler = new ConsumeFailureHandler(
        ConsumeFailurePolicy.strict(), null, bus, now::get);

    for (int i = 0; i < 1_000; i++) {
      SignedJCustosEventEnvelope junk = junk(i);
      JCustosEventVerificationResult result = consumer.verify(junk, now.get());
      assertInstanceOf(JCustosEventVerificationResult.UnknownKey.class, result);
      assertEquals(ConsumeFailureAction.REJECT, handler.handle(junk, result));
    }

    int limit = ConsumeFailureHandler.DEFAULT_UNAUTHENTICATED_EVENT_LIMIT;
    assertEquals(limit, alerts.size(), "alerts are bounded by the configured limit");
    assertEquals(limit, chained.size(), "so is what a listener behind the bus would record");
    assertEquals(1_000L - limit, handler.suppressedUnauthenticatedCount());
    for (JCustosAlert alert : alerts) {
      assertFalse(VICTIM.equals(alert.tenantId()),
          "no alert may carry the tenant the junk claims");
      assertEquals(SelfObservabilityEvents.UNAUTHENTICATED_TENANT, alert.tenantId());
    }
    for (JCustosEvent event : chained) {
      EnvelopeRejectedEvent rejected = assertInstanceOf(EnvelopeRejectedEvent.class, event);
      assertTrue(rejected.rejectedEnvelopeId().startsWith("unverified:"));
      assertTrue(rejected.rejectedEnvelopeId().length() <= "unverified:".length() + 64,
          "the 4000-character id must not travel into the event");
      assertTrue(SelfObservabilityEvents.isUnauthenticatedRejection(event));
    }
  }

  @Test
  @DisplayName("a rejection of an authenticated envelope is reported in full while the junk budget is spent")
  void authenticatedRejectionIsNeverThrottled() {
    ConsumePipeline consumer = fx.consumePipeline();
    ConsumeFailureHandler handler = new ConsumeFailureHandler(
        ConsumeFailurePolicy.strict(), null, bus, now::get);
    for (int i = 0; i < 100; i++) {
      SignedJCustosEventEnvelope junk = junk(i);
      handler.handle(junk, consumer.verify(junk, now.get()));
    }
    int afterFlood = chained.size();

    // A genuine envelope of tenant acme arrives after its window: Expired is
    // reached after signature and key binding, so its fields are facts.
    SignedJCustosEventEnvelope acme = fx.publishPipeline().toEnvelope(new LoginSucceededEvent(
        EventMetadata.create(TenantId.of("acme"), SubjectId.of("alice"), BusFixtures.T0,
            JCustosEventSeverity.INFO), "password"));
    Instant late = BusFixtures.T0.plus(Duration.ofMinutes(6));
    JCustosEventVerificationResult expired = consumer.verify(acme, late);
    assertInstanceOf(JCustosEventVerificationResult.Expired.class, expired);
    handler.handle(acme, expired);

    assertEquals(afterFlood + 1, chained.size());
    EnvelopeRejectedEvent event =
        assertInstanceOf(EnvelopeRejectedEvent.class, chained.get(afterFlood));
    assertEquals(TenantId.of("acme"), event.tenantId());
    assertEquals(acme.envelopeId().value(), event.rejectedEnvelopeId());
  }

  /** Real resolver over real keys that binds the key to no producer of the fixtures. */
  private record UnboundResolver(InMemoryKeyManagement delegate)
      implements JCustosEventVerificationKeyResolver {
    @Override
    public Optional<PublicKey> resolveVerificationKey(KeyId keyId) {
      return delegate.resolveVerificationKey(keyId);
    }

    @Override
    public KeyStatus keyStatus(KeyId keyId) {
      return delegate.keyStatus(keyId);
    }

    @Override
    public boolean mayVerify(KeyId keyId, EventProducerId producerId, TenantId tenantId) {
      return false;
    }
  }

  @Test
  @DisplayName("a key holder's impersonation attempt is reported with its key after any amount of junk")
  void keyNotAuthorizedHasABudgetOfItsOwn() {
    ConsumeFailureHandler handler = new ConsumeFailureHandler(
        ConsumeFailurePolicy.strict(), null, bus, now::get);
    ConsumePipeline consumer = fx.consumePipeline();
    for (int i = 0; i < 100; i++) {
      SignedJCustosEventEnvelope junk = junk(i);
      handler.handle(junk, consumer.verify(junk, now.get()));
    }
    int limit = ConsumeFailureHandler.DEFAULT_UNAUTHENTICATED_EVENT_LIMIT;
    assertEquals(limit, chained.size(), "the keyless budget is spent");
    assertTrue(chained.stream()
        .allMatch(event -> ((EnvelopeRejectedEvent) event).keyId() == null));

    // The holder of key eventbus-1 signs in the name of a producer the key is not bound to.
    ConsumePipeline bound = new ConsumePipeline(new UnboundResolver(fx.keyManagement),
        SignatureAlgorithms.defaults(), fx.consumeReplay, fx.consumeSequence,
        new SequenceValidator(), SequenceViolationStrategy.REJECT, fx.allowAll);
    JCustosEventVerificationResult impersonation = bound.verify(genuine, now.get());
    assertInstanceOf(JCustosEventVerificationResult.KeyNotAuthorizedForProducer.class,
        impersonation);
    handler.handle(genuine, impersonation);

    assertEquals(limit + 1, chained.size(), "the attempt is reported despite the junk");
    EnvelopeRejectedEvent reported =
        assertInstanceOf(EnvelopeRejectedEvent.class, chained.get(limit));
    assertEquals(SelfObservabilityEvents.REASON_KEY_NOT_AUTHORIZED, reported.reason());
    assertEquals(BusFixtures.KEY.value(), reported.keyId(), "the verified key is named");
    assertEquals(SelfObservabilityEvents.UNAUTHENTICATED_TENANT, reported.tenantId(),
        "the claimed tenant is still not adopted");
    assertFalse(SelfObservabilityEvents.isUnauthenticatedRejection(reported),
        "a key holder's impersonation is no keyless noise; an audit chain records it");

    // Its own budget is bounded too, and independent of the keyless one.
    int keyLimit = ConsumeFailureHandler.DEFAULT_KEY_NOT_AUTHORIZED_EVENT_LIMIT;
    for (int i = 1; i < keyLimit + 5; i++) {
      handler.handle(genuine, impersonation);
    }
    assertEquals(limit + keyLimit, chained.size());
    assertEquals(5L, handler.suppressedKeyNotAuthorizedCount());
    assertEquals(100L - limit, handler.suppressedUnauthenticatedCount());
  }

  @Test
  @DisplayName("a policy that dead-letters keyless rejections keeps every record but not every event")
  void deadLetteredEventsFollowTheThrottle() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    ConsumeFailureHandler handler = new ConsumeFailureHandler(ConsumeFailurePolicy.custom()
        .with(ConsumeFailurePolicy.FailureKind.UNKNOWN_KEY,
            ConsumeFailureAction.REJECT_AND_DEAD_LETTER)
        .build(), store, bus, now::get);
    ConsumePipeline consumer = fx.consumePipeline();

    for (int i = 0; i < 100; i++) {
      SignedJCustosEventEnvelope junk = junk(i);
      assertEquals(ConsumeFailureAction.REJECT_AND_DEAD_LETTER,
          handler.handle(junk, consumer.verify(junk, now.get())));
    }

    int limit = ConsumeFailureHandler.DEFAULT_UNAUTHENTICATED_EVENT_LIMIT;
    assertEquals(100, store.findOpen(Integer.MAX_VALUE).size(),
        "every rejection is kept for forensics");
    assertEquals(limit, chained.stream().filter(DeadLetteredEvent.class::isInstance).count(),
        "a DeadLettered event only for a rejection that was reported");
    assertEquals(limit, chained.stream().filter(EnvelopeRejectedEvent.class::isInstance).count());
    assertEquals(2 * limit, alerts.size(), "the alert stream stays bounded");
  }

  @Test
  @DisplayName("the budget is per window and both limit and window are configurable")
  void budgetIsPerWindowAndConfigurable() {
    ConsumePipeline consumer = fx.consumePipeline();
    ConsumeFailureHandler handler = new ConsumeFailureHandler(
        ConsumeFailurePolicy.strict(), null, bus, now::get, 3, Duration.ofSeconds(10));

    for (int i = 0; i < 10; i++) {
      SignedJCustosEventEnvelope junk = junk(i);
      handler.handle(junk, consumer.verify(junk, now.get()));
    }
    assertEquals(3, chained.size());
    assertEquals(7L, handler.suppressedUnauthenticatedCount());

    now.set(BusFixtures.T0.plusSeconds(10));
    for (int i = 10; i < 20; i++) {
      SignedJCustosEventEnvelope junk = junk(i);
      handler.handle(junk, consumer.verify(junk, now.get()));
    }
    assertEquals(6, chained.size(), "a new window grants the budget again");
    assertEquals(14L, handler.suppressedUnauthenticatedCount());

    assertThrows(IllegalArgumentException.class, () -> new ConsumeFailureHandler(
        ConsumeFailurePolicy.strict(), null, bus, now::get, -1, Duration.ofSeconds(10)));
    assertThrows(IllegalArgumentException.class, () -> new ConsumeFailureHandler(
        ConsumeFailurePolicy.strict(), null, bus, now::get, 3, Duration.ZERO));
  }
}
