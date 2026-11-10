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

import eu.jsentinel.jcustos.events.api.PayloadContentType;
import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelopeBuilder;
import eu.jsentinel.jcustos.events.codec.CanonicalJCustosEventPayload;
import eu.jsentinel.jcustos.events.codec.CanonicalJsonPayloadCodec;
import eu.jsentinel.jcustos.events.keys.JCustosEventSigningKeyProvider;

/**
 * Signs hand-built envelopes with real key material — for the tests that need
 * an envelope the publish pipeline itself would never produce (a payload that
 * contradicts its envelope, a poisoned sequence). No mocks: the signature base
 * and the signature are the production ones.
 */
final class SignedEnvelopes {

  private SignedEnvelopes() {
  }

  /** Stamps key id and algorithm of the provider's current key and signs. */
  static SignedJCustosEventEnvelope sign(SignedJCustosEventEnvelopeBuilder builder,
      JCustosEventSigningKeyProvider keys) {
    builder.keyId(keys.currentKeyId())
        .signatureAlgorithm(keys.currentAlgorithm().id())
        .signature(new byte[]{0});
    byte[] base = EnvelopeSignatureBase.compute(builder.build());
    return builder
        .signature(keys.currentAlgorithm().sign(base, keys.currentSigningKey()))
        .build();
  }

  /** Sets the canonical-JSON encoding of {@code payload} and its hash on the builder. */
  static SignedJCustosEventEnvelopeBuilder withPayload(
      SignedJCustosEventEnvelopeBuilder builder, CanonicalJCustosEventPayload payload) {
    return withPayloadBytes(builder, new CanonicalJsonPayloadCodec().encode(payload));
  }

  /** Sets raw payload bytes and their hash on the builder. */
  static SignedJCustosEventEnvelopeBuilder withPayloadBytes(
      SignedJCustosEventEnvelopeBuilder builder, byte[] payload) {
    return builder
        .payloadContentType(PayloadContentType.CANONICAL_JSON)
        .payloadHashAlgorithm(PayloadHashAlgorithm.SHA_256)
        .canonicalPayloadHash(PayloadDigest.hash(PayloadHashAlgorithm.SHA_256, payload))
        .canonicalPayload(payload);
  }
}
