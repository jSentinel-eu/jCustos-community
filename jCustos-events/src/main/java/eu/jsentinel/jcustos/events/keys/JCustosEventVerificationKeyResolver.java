package eu.jsentinel.jcustos.events.keys;

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
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.KeyId;

import java.security.PublicKey;
import java.util.Objects;
import java.util.Optional;

/**
 * Verifier-side key SPI (Konzept §583): resolves a public key and its status
 * for a given {@link KeyId}, so the consume pipeline can verify a signature
 * and reject envelopes signed under an unknown or revoked key.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public interface JCustosEventVerificationKeyResolver {

  /**
   * @param keyId the key referenced by the envelope
   * @return the public key, if one is known for the id
   */
  Optional<PublicKey> resolveVerificationKey(KeyId keyId);

  /**
   * @param keyId the key referenced by the envelope
   * @return the lifecycle status; {@link KeyStatus#UNKNOWN} if no key is known
   */
  KeyStatus keyStatus(KeyId keyId);

  /**
   * Decides whether a key may vouch for envelopes of a producer — the binding
   * between key and producer identity (JS-SEC-101, CWE-290). The consume
   * pipeline asks after the signature verified and rejects the envelope when
   * the answer is {@code false}: a valid signature only proves that
   * <em>some</em> trusted key signed, and the {@code producerId} in the
   * envelope is written by the signer itself. Without the binding every
   * trusted key could sign for every producer and every tenant, and the
   * producer policy would be decided on a self-declared name.
   *
   * <p>The {@code default} implementation is the naming convention <em>a key
   * signs only for the producer of the same name</em>: it returns {@code true}
   * iff {@code keyId} and {@code producerId} carry the same value, for every
   * tenant. It fails closed for an implementation that predates this method
   * and names its keys differently — such an implementation has to state its
   * binding by overriding the method.
   *
   * @param keyId the key the envelope was verified under
   * @param producerId the producer the envelope claims
   * @param tenantId the tenant the envelope claims; lets an implementation
   *     confine a key to tenants, the shipped implementations ignore it
   * @return {@code true} if the key may sign for this producer and tenant
   * @since 00.84.00
   */
  default boolean mayVerify(KeyId keyId, EventProducerId producerId, TenantId tenantId) {
    Objects.requireNonNull(keyId, "keyId");
    Objects.requireNonNull(producerId, "producerId");
    Objects.requireNonNull(tenantId, "tenantId");
    return keyId.value().equals(producerId.value());
  }
}
