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
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.codec.CanonicalJsonPayloadCodec;
import eu.jsentinel.jcustos.events.codec.RecordReflectionCanonicalizer;
import eu.jsentinel.jcustos.events.keys.InMemoryKeyManagement;
import eu.jsentinel.jcustos.events.keys.JCustosEventSigningKeyProvider;
import eu.jsentinel.jcustos.events.keys.JCustosEventVerificationKeyResolver;
import eu.jsentinel.jcustos.events.keys.JdkKeyStoreKeyManagement;
import eu.jsentinel.jcustos.events.keys.KeyStatus;
import eu.jsentinel.jcustos.events.producer.AllowListProducerPolicy;
import eu.jsentinel.jcustos.events.producer.JCustosEventProducerPolicy;
import eu.jsentinel.jcustos.events.replay.InMemoryReplayStore;
import eu.jsentinel.jcustos.events.sequence.InMemorySequenceStore;
import eu.jsentinel.jcustos.events.sequence.SequenceValidator;
import eu.jsentinel.jcustos.events.sequence.SequenceViolationStrategy;
import eu.jsentinel.jcustos.events.signature.Ed25519SignatureAlgorithm;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithm;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithms;
import eu.jsentinel.jcustos.events.types.LoginSucceededEvent;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-101: a trusted key must only vouch for its own producer. Runs against
 * a real, keytool-built PKCS12 store with the two synthetic Ed25519 aliases
 * {@code rest-primary} and {@code vaadin-client}
 * ({@code src/test/resources/test-eventbus-two-producers.p12}). No mocks.
 */
@DisplayName("ConsumePipeline — key-to-producer binding (JS-SEC-101)")
class ProducerKeyBindingTest {

  private static final Instant T0 = Instant.parse("2026-11-11T10:00:00Z");
  private static final EventProducerId REST = EventProducerId.of("rest-primary");
  private static final EventProducerId VAADIN = EventProducerId.of("vaadin-client");
  private static final KeyId REST_KEY = KeyId.of("rest-primary");
  private static final KeyId VAADIN_KEY = KeyId.of("vaadin-client");
  private static final TenantId ACME = TenantId.of("acme");
  private static final TenantId GLOBEX = TenantId.of("globex");

  /** The consumer's policy: the REST service everywhere, the UI process for acme only. */
  private static final JCustosEventProducerPolicy CONSUMER_POLICY =
      AllowListProducerPolicy.builder()
          .allow(REST, LoginSucceededEvent.TYPE)
          .allowForTenant(VAADIN, LoginSucceededEvent.TYPE, ACME)
          .build();

  private final InMemoryReplayStore consumeReplay = new InMemoryReplayStore();
  private final InMemorySequenceStore consumeSequence = new InMemorySequenceStore();

  private static JdkKeyStoreKeyManagement keyStore(KeyId currentAlias) {
    try {
      Path p12 = Path.of(ProducerKeyBindingTest.class
          .getResource("/test-eventbus-two-producers.p12").toURI());
      return JdkKeyStoreKeyManagement.loadPkcs12(p12, "changeit".toCharArray(),
          "changeit".toCharArray(), currentAlias, new Ed25519SignatureAlgorithm());
    } catch (java.net.URISyntaxException e) {
      throw new IllegalStateException(e);
    }
  }

  /** A process signs with the key it holds and names itself whatever it likes. */
  private static SignedJCustosEventEnvelope publish(KeyId heldKey, EventProducerId claimed,
      TenantId tenant) {
    PublishPipeline pipeline = new PublishPipeline(keyStore(heldKey),
        new RecordReflectionCanonicalizer(), new CanonicalJsonPayloadCodec(),
        PayloadHashAlgorithm.SHA_256, claimed, new InMemorySequenceStore(),
        new InMemoryReplayStore(),
        AllowListProducerPolicy.builder().allow(claimed, LoginSucceededEvent.TYPE).build(),
        Duration.ofMinutes(5), () -> T0);
    return pipeline.toEnvelope(new LoginSucceededEvent(
        EventMetadata.create(tenant, SubjectId.of("alice"), T0, JCustosEventSeverity.INFO),
        "password"));
  }

  private ConsumePipeline consumer(JCustosEventVerificationKeyResolver resolver) {
    return new ConsumePipeline(resolver, SignatureAlgorithms.defaults(), consumeReplay,
        consumeSequence, new SequenceValidator(), SequenceViolationStrategy.REJECT,
        CONSUMER_POLICY);
  }

  @Test
  @DisplayName("an envelope signed with key B in the name of producer A is rejected")
  void foreignKeyCannotSignForAnotherProducer() {
    // The UI process holds only its own key, but claims to be the REST service
    // and publishes for a tenant it has no grant for.
    SignedJCustosEventEnvelope forged = publish(VAADIN_KEY, REST, GLOBEX);
    assertEquals(VAADIN_KEY, forged.keyId());
    assertEquals(REST, forged.producerId());

    JCustosEventVerificationResult result = consumer(keyStore(REST_KEY)).verify(forged, T0);

    JCustosEventVerificationResult.KeyNotAuthorizedForProducer rejected = assertInstanceOf(
        JCustosEventVerificationResult.KeyNotAuthorizedForProducer.class, result);
    assertEquals(VAADIN_KEY, rejected.keyId());
    assertEquals(REST, rejected.producerId());
    assertEquals(GLOBEX, rejected.tenantId());
    assertFalse(result.envelopeAuthenticated());
    assertFalse(consumeReplay.hasSeen(forged.envelopeId()),
        "a rejected envelope must not be recorded in the replay store");
    assertTrue(consumeSequence.lastSequence(GLOBEX, REST).isEmpty(),
        "a rejected envelope must not start the sequence of the impersonated producer");
  }

  @Test
  @DisplayName("the same envelope signed with producer A's own key is Valid")
  void ownKeySignsForItsProducer() {
    SignedJCustosEventEnvelope genuine = publish(REST_KEY, REST, GLOBEX);

    assertTrue(consumer(keyStore(REST_KEY)).verify(genuine, T0).isValid());
  }

  @Test
  @DisplayName("a bound key is still subject to the producer policy")
  void boundKeyStillPassesThroughPolicy() {
    ConsumePipeline consumer = consumer(keyStore(REST_KEY));

    assertTrue(consumer.verify(publish(VAADIN_KEY, VAADIN, ACME), T0).isValid());
    assertInstanceOf(JCustosEventVerificationResult.ProducerNotAllowed.class,
        consumer.verify(publish(VAADIN_KEY, VAADIN, GLOBEX), T0));
  }

  @Test
  @DisplayName("an explicit binding replaces the alias convention for that key only")
  void explicitBindingReplacesAliasConvention() {
    EventProducerId renamed = EventProducerId.of("rest-primary-eu");
    JdkKeyStoreKeyManagement rebound = keyStore(REST_KEY)
        .withProducerBinding(REST_KEY, Set.of(renamed));

    assertTrue(rebound.mayVerify(REST_KEY, renamed, ACME));
    assertFalse(rebound.mayVerify(REST_KEY, REST, ACME),
        "the explicit binding replaces the alias convention");
    assertTrue(rebound.mayVerify(VAADIN_KEY, VAADIN, ACME),
        "other keys keep the alias convention");
    assertFalse(rebound.mayVerify(VAADIN_KEY, renamed, ACME));
    assertFalse(keyStore(REST_KEY).withProducerBinding(REST_KEY, Set.of())
        .mayVerify(REST_KEY, REST, ACME), "an empty binding binds the key to nobody");
  }

  @Test
  @DisplayName("a resolver that states no binding fails closed for a differently named producer")
  void resolverWithoutBindingFailsClosed() {
    BusFixtures fx = new BusFixtures();
    SignedJCustosEventEnvelope envelope = fx.publishPipeline().toEnvelope(BusFixtures.event());
    // A third-party resolver written before 00.84.00: it resolves and reports
    // status, and inherits the default binding (key id equals producer id).
    ConsumePipeline consumer = new ConsumePipeline(new LegacyResolver(fx.keyManagement),
        SignatureAlgorithms.defaults(), fx.consumeReplay, fx.consumeSequence,
        new SequenceValidator(), SequenceViolationStrategy.REJECT, fx.allowAll);

    assertInstanceOf(JCustosEventVerificationResult.KeyNotAuthorizedForProducer.class,
        consumer.verify(envelope, BusFixtures.T0));
    // The in-memory manager itself is a single-party key holder and accepts it.
    assertTrue(fx.consumePipeline().verify(envelope, BusFixtures.T0).isValid());
  }

  /** Signs with the private key of {@code heldKey} but stamps {@code stamped} as key id. */
  private static SignedJCustosEventEnvelope publishStamped(KeyId heldKey, KeyId stamped,
      EventProducerId claimed, TenantId tenant) {
    PrivateKey held = keyStore(heldKey).currentSigningKey();
    JCustosEventSigningKeyProvider respelled = new JCustosEventSigningKeyProvider() {
      @Override
      public KeyId currentKeyId() {
        return stamped;
      }

      @Override
      public PrivateKey currentSigningKey() {
        return held;
      }

      @Override
      public SignatureAlgorithm currentAlgorithm() {
        return new Ed25519SignatureAlgorithm();
      }
    };
    PublishPipeline pipeline = new PublishPipeline(respelled,
        new RecordReflectionCanonicalizer(), new CanonicalJsonPayloadCodec(),
        PayloadHashAlgorithm.SHA_256, claimed, new InMemorySequenceStore(),
        new InMemoryReplayStore(),
        AllowListProducerPolicy.builder().allow(claimed, LoginSucceededEvent.TYPE).build(),
        Duration.ofMinutes(5), () -> T0);
    return pipeline.toEnvelope(new LoginSucceededEvent(
        EventMetadata.create(tenant, SubjectId.of("alice"), T0, JCustosEventSeverity.INFO),
        "password"));
  }

  @Test
  @DisplayName("a key id that differs from the store alias in case alone is an unknown key")
  void keyIdMustMatchTheAliasExactly() {
    KeyId shouted = KeyId.of("VAADIN-CLIENT");
    EventProducerId shoutedProducer = EventProducerId.of("VAADIN-CLIENT");
    // The operator retired the UI key: it is bound to no producer any more.
    JdkKeyStoreKeyManagement retired = keyStore(REST_KEY)
        .withProducerBinding(VAADIN_KEY, Set.of());

    assertTrue(retired.resolveVerificationKey(VAADIN_KEY).isPresent());
    assertTrue(retired.resolveVerificationKey(shouted).isEmpty(),
        "the PKCS12 store would find vaadin-client under VAADIN-CLIENT");
    assertEquals(KeyStatus.UNKNOWN, retired.keyStatus(shouted));
    assertFalse(retired.mayVerify(shouted, shoutedProducer, ACME),
        "a respelled key id must not escape the binding stated for the alias");

    // The holder of the retired key signs under the respelled id, for a producer
    // id spelled the same way, which a consumer has allow-listed.
    SignedJCustosEventEnvelope respelled = publishStamped(VAADIN_KEY, shouted,
        shoutedProducer, ACME);
    ConsumePipeline consumer = new ConsumePipeline(retired, SignatureAlgorithms.defaults(),
        consumeReplay, consumeSequence, new SequenceValidator(), SequenceViolationStrategy.REJECT,
        AllowListProducerPolicy.builder().allow(shoutedProducer, LoginSucceededEvent.TYPE).build());

    assertInstanceOf(JCustosEventVerificationResult.UnknownKey.class,
        consumer.verify(respelled, T0));
  }

  @Test
  @DisplayName("an in-memory manager confined to producers rejects every other producer id")
  void confinedInMemoryManager() {
    InMemoryKeyManagement confined = new InMemoryKeyManagement(
        new Ed25519SignatureAlgorithm(), KeyId.of("k1"), Set.of(REST));
    confined.rotate(KeyId.of("k2"));

    assertTrue(confined.mayVerify(KeyId.of("k1"), REST, ACME));
    assertTrue(confined.mayVerify(KeyId.of("k2"), REST, ACME), "a rotated key keeps the binding");
    assertFalse(confined.mayVerify(KeyId.of("k1"), VAADIN, ACME));
    assertFalse(confined.mayVerify(KeyId.of("unknown"), REST, ACME));
  }

  /** Real resolver over real keys that predates the binding method — no mock. */
  private record LegacyResolver(InMemoryKeyManagement delegate)
      implements JCustosEventVerificationKeyResolver {
    @Override
    public Optional<PublicKey> resolveVerificationKey(KeyId keyId) {
      return delegate.resolveVerificationKey(keyId);
    }

    @Override
    public KeyStatus keyStatus(KeyId keyId) {
      return delegate.keyStatus(keyId);
    }
  }
}
