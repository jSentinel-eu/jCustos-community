package eu.jsentinel.jcustos.events.codec;

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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.PayloadContentType;

/**
 * SPI for serializing a {@link CanonicalJCustosEventPayload} to and from the
 * deterministic byte form that gets hashed and signed (Konzept §536).
 *
 * <p>The codec id ({@link #contentType()}) is recorded on the envelope so a
 * consumer can pick the matching decoder. Every codec MUST produce
 * deterministic bytes for a given payload — the signature is bound to exactly
 * those bytes — and is verified by the testkit contract.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public interface PayloadCodec {

  /**
   * @return the media type identifying this codec, stored on the envelope
   */
  PayloadContentType contentType();

  /**
   * @param payload the canonical payload
   * @return deterministic encoded bytes
   */
  byte[] encode(CanonicalJCustosEventPayload payload);

  /**
   * Decodes bytes this codec encoded. The consume pipeline re-encodes the
   * result and rejects the envelope unless {@link #encode} reproduces
   * {@code bytes} exactly (JS-SEC-107), so a codec must decode its own output
   * into a payload that encodes back to the same bytes; an encoding with more
   * than one spelling for the same payload is rejected on the consume side.
   *
   * @param bytes encoded bytes produced by this codec
   * @return the decoded canonical payload
   * @throws PayloadCodecException if the bytes are not valid for this codec
   */
  CanonicalJCustosEventPayload decode(byte[] bytes);
}
