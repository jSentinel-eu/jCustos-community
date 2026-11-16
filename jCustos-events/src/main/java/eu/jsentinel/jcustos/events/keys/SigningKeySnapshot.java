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
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithm;

import java.security.PrivateKey;
import java.util.Objects;

/**
 * Immutable, self-consistent view of the current signing key (R00): the
 * {@code keyId} stamped onto an envelope plus the algorithm and private key the
 * envelope is signed with, captured together at one point in time. The publish
 * pipeline takes exactly one snapshot per publish and uses it for both the
 * {@code keyId} stamp and the signing operation, so a concurrent key rotation
 * between those two steps can never produce an envelope stamped with one key id
 * but signed with another key's private material.
 *
 * @param keyId the id of the signing key, stamped onto the envelope
 * @param algorithm the signature algorithm bound to the key
 * @param privateKey the private signing key matching {@code keyId}
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public record SigningKeySnapshot(KeyId keyId, SignatureAlgorithm algorithm,
    PrivateKey privateKey) {

  public SigningKeySnapshot {
    Objects.requireNonNull(keyId, "keyId");
    Objects.requireNonNull(algorithm, "algorithm");
    Objects.requireNonNull(privateKey, "privateKey");
  }

  /**
   * Masks the private key (JS-SEC-127, CWE-532): the generated {@code toString()} delegated
   * to the key's own, which for some providers prints key material.
   *
   * @return a description with key id, algorithm and the key's algorithm name only
   */
  @Override
  public String toString() {
    return "SigningKeySnapshot[keyId=" + keyId + ", algorithm=" + algorithm
        + ", privateKey=*** (" + privateKey.getAlgorithm() + ")]";
  }
}
