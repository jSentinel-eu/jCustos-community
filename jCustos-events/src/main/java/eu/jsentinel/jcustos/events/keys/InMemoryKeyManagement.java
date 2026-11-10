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
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithm;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link JCustosEventSigningKeyProvider} +
 * {@link JCustosEventVerificationKeyResolver} (Konzept §98). The default
 * key-management implementation for local setups and tests: it generates the
 * current key pair with the configured {@link SignatureAlgorithm} and supports
 * rotation and revocation without an API break.
 *
 * <p>Rotated-out keys stay {@link KeyStatus#ACCEPTED_FOR_VERIFICATION} so
 * in-flight envelopes still verify during the grace window.
 *
 * <p>Key-to-producer binding (JS-SEC-101): this manager generates every key
 * it trusts itself and cannot import a foreign public key, so all of its keys
 * belong to one party — the process that owns the instance. The two-argument
 * constructor therefore lets its keys vouch for any producer id. Pass the
 * producer ids to the three-argument constructor to confine the keys to them.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class InMemoryKeyManagement
    implements JCustosEventSigningKeyProvider, JCustosEventVerificationKeyResolver {

  // R00: id and key pair live in ONE immutable holder behind a single volatile
  // reference, so a reader can never observe the new id paired with the old key
  // material (or vice versa) — the previous two separate volatile stores made
  // exactly that interleaving possible during rotate().
  private record CurrentKey(KeyId keyId, KeyPair keyPair) {
  }

  private final SignatureAlgorithm algorithm;
  private final Map<KeyId, PublicKey> verificationKeys = new ConcurrentHashMap<>();
  private final Set<KeyId> revoked = ConcurrentHashMap.newKeySet();

  // null = not confined: every key of this single-party manager vouches for
  // any producer id (see the class Javadoc).
  private final Set<EventProducerId> boundProducers;
  private volatile CurrentKey current;

  /**
   * Creates a manager with a freshly generated initial key pair.
   *
   * @param algorithm the signature algorithm
   * @param initialKeyId the id of the initial signing key
   */
  public InMemoryKeyManagement(SignatureAlgorithm algorithm, KeyId initialKeyId) {
    this(algorithm, initialKeyId, null, false);
  }

  /**
   * Creates a manager with a freshly generated initial key pair whose keys —
   * the initial one and every rotated one — may only vouch for the given
   * producers.
   *
   * @param algorithm the signature algorithm
   * @param initialKeyId the id of the initial signing key
   * @param boundProducers the producer ids the keys sign for; an empty set
   *     binds the keys to no producer, so every envelope is rejected
   * @since 00.84.00
   */
  public InMemoryKeyManagement(SignatureAlgorithm algorithm, KeyId initialKeyId,
      Set<EventProducerId> boundProducers) {
    this(algorithm, initialKeyId,
        Set.copyOf(Objects.requireNonNull(boundProducers, "boundProducers")), true);
  }

  private InMemoryKeyManagement(SignatureAlgorithm algorithm, KeyId initialKeyId,
      Set<EventProducerId> boundProducers, boolean confined) {
    this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
    Objects.requireNonNull(initialKeyId, "initialKeyId");
    this.boundProducers = confined ? boundProducers : null;
    KeyPair pair = algorithm.generateKeyPair();
    verificationKeys.put(initialKeyId, pair.getPublic());
    this.current = new CurrentKey(initialKeyId, pair);
  }

  @Override
  public KeyId currentKeyId() {
    return current.keyId();
  }

  @Override
  public PrivateKey currentSigningKey() {
    return current.keyPair().getPrivate();
  }

  @Override
  public SignatureAlgorithm currentAlgorithm() {
    return algorithm;
  }

  @Override
  public SigningKeySnapshot signingSnapshot() {
    // One volatile read — keyId and private key are guaranteed to belong to
    // the same key generation even while rotate() runs concurrently (R00).
    CurrentKey snapshot = current;
    return new SigningKeySnapshot(snapshot.keyId(), algorithm, snapshot.keyPair().getPrivate());
  }

  @Override
  public Optional<PublicKey> resolveVerificationKey(KeyId keyId) {
    return Optional.ofNullable(verificationKeys.get(Objects.requireNonNull(keyId, "keyId")));
  }

  @Override
  public KeyStatus keyStatus(KeyId keyId) {
    Objects.requireNonNull(keyId, "keyId");
    if (revoked.contains(keyId)) {
      return KeyStatus.REVOKED;
    }
    if (!verificationKeys.containsKey(keyId)) {
      return KeyStatus.UNKNOWN;
    }
    return keyId.equals(current.keyId())
        ? KeyStatus.ACTIVE
        : KeyStatus.ACCEPTED_FOR_VERIFICATION;
  }

  @Override
  public boolean mayVerify(KeyId keyId, EventProducerId producerId, TenantId tenantId) {
    Objects.requireNonNull(keyId, "keyId");
    Objects.requireNonNull(producerId, "producerId");
    Objects.requireNonNull(tenantId, "tenantId");
    if (!verificationKeys.containsKey(keyId)) {
      return false;
    }
    return boundProducers == null || boundProducers.contains(producerId);
  }

  /**
   * Rotates to a freshly generated key. The previous key stays valid for
   * verification.
   *
   * @param newKeyId the id of the new signing key
   */
  public synchronized void rotate(KeyId newKeyId) {
    Objects.requireNonNull(newKeyId, "newKeyId");
    KeyPair pair = algorithm.generateKeyPair();
    // Publish the verification key BEFORE swapping the holder, so any reader
    // that already sees the new current key can also resolve it (R00). The
    // holder itself is swapped in a single volatile store.
    verificationKeys.put(newKeyId, pair.getPublic());
    this.current = new CurrentKey(newKeyId, pair);
  }

  /**
   * Revokes a key; subsequent {@link #keyStatus(KeyId)} reports
   * {@link KeyStatus#REVOKED}.
   *
   * @param keyId the key to revoke
   */
  public void revoke(KeyId keyId) {
    revoked.add(Objects.requireNonNull(keyId, "keyId"));
  }
}
