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

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * JDK {@code KeyStore}-backed key management (Konzept §599). The simple
 * reference implementation: private keys load from a PKCS12 store, public keys
 * come from the stored certificates, {@code keyId} maps to a store alias, and a
 * designated current alias is used for signing. Rotation is achieved by
 * pointing a new instance at a new current alias — no API break.
 *
 * <p>Key-to-producer binding (JS-SEC-101): a key store usually holds the keys
 * of several producers, so a key must not vouch for a producer other than its
 * own. Without further configuration the alias <em>is</em> the binding — the
 * key under alias {@code rest-primary} signs for the producer id
 * {@code rest-primary} and for no other (exact, case-sensitive comparison).
 * Where alias and producer id differ, for instance after a rotation to
 * {@code rest-primary-2027}, state the binding with
 * {@link #withProducerBinding(KeyId, Set)}; an explicit binding replaces the
 * alias convention for that key.
 *
 * <p>Key ids are matched exactly, too (JS-SEC-101). A JDK key store looks
 * aliases up case-insensitively — PKCS12 stores them in lower case and finds
 * {@code VAADIN-CLIENT} under {@code vaadin-client} — so a key id that
 * differed from the alias in case alone resolved the key, escaped an explicit
 * binding stated for the alias and was compared with the producer id it
 * spelled. A key id is therefore accepted only if it equals, character for
 * character, an alias {@link KeyStore#aliases()} lists; any other spelling is
 * an unknown key, may not vouch for a producer and cannot sign. Key stores
 * keep their aliases in lower case, so key ids and current alias should be
 * lower case as well.
 *
 * <p>Non-goals (Konzept §609): full secret management, HSM, Cloud-KMS. Those
 * can follow later behind the same SPI.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class JdkKeyStoreKeyManagement
    implements JCustosEventSigningKeyProvider, JCustosEventVerificationKeyResolver {

  private final KeyStore keyStore;
  private final char[] keyPassword;
  private final KeyId currentAlias;
  private final SignatureAlgorithm algorithm;
  private final Map<KeyId, Set<EventProducerId>> producerBindings;

  /**
   * @param keyStore an already-loaded key store
   * @param keyPassword the password protecting private-key entries
   * @param currentAlias the alias used as the current signing key
   * @param algorithm the signature algorithm bound to the keys
   */
  public JdkKeyStoreKeyManagement(KeyStore keyStore, char[] keyPassword,
      KeyId currentAlias, SignatureAlgorithm algorithm) {
    this.keyStore = Objects.requireNonNull(keyStore, "keyStore");
    this.keyPassword = Objects.requireNonNull(keyPassword, "keyPassword").clone();
    this.currentAlias = Objects.requireNonNull(currentAlias, "currentAlias");
    this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
    this.producerBindings = Map.of();
  }

  private JdkKeyStoreKeyManagement(JdkKeyStoreKeyManagement source,
      Map<KeyId, Set<EventProducerId>> producerBindings) {
    this.keyStore = source.keyStore;
    this.keyPassword = source.keyPassword;
    this.currentAlias = source.currentAlias;
    this.algorithm = source.algorithm;
    this.producerBindings = Map.copyOf(producerBindings);
  }

  /**
   * Returns a copy of this key management in which {@code keyId} vouches for
   * exactly the given producers instead of the producer named like its alias
   * (JS-SEC-101). Bindings of other keys are kept; calling it again for the
   * same key replaces that key's binding.
   *
   * @param keyId the key (store alias) to bind
   * @param producers the producer ids the key may sign for; an empty set
   *     binds the key to no producer
   * @return a new instance over the same key store with the added binding
   * @since 00.84.00
   */
  public JdkKeyStoreKeyManagement withProducerBinding(KeyId keyId,
      Set<EventProducerId> producers) {
    Objects.requireNonNull(keyId, "keyId");
    Objects.requireNonNull(producers, "producers");
    Map<KeyId, Set<EventProducerId>> bindings = new HashMap<>(producerBindings);
    bindings.put(keyId, Set.copyOf(producers));
    return new JdkKeyStoreKeyManagement(this, bindings);
  }

  /**
   * Loads a PKCS12 key store from a path. The store password may, in
   * production, be sourced from {@code app.eventbus.keystore.password}.
   *
   * @param path the {@code .p12} file
   * @param storePassword the store password
   * @param keyPassword the private-key password
   * @param currentAlias the current signing alias
   * @param algorithm the signature algorithm
   * @return a configured key-management instance
   */
  public static JdkKeyStoreKeyManagement loadPkcs12(Path path, char[] storePassword,
      char[] keyPassword, KeyId currentAlias, SignatureAlgorithm algorithm) {
    try (InputStream in = Files.newInputStream(path)) {
      KeyStore store = KeyStore.getInstance("PKCS12");
      store.load(in, storePassword);
      return new JdkKeyStoreKeyManagement(store, keyPassword, currentAlias, algorithm);
    } catch (IOException | GeneralSecurityException e) {
      throw new KeyAccessException("Cannot load PKCS12 key store from " + path, e);
    }
  }

  @Override
  public KeyId currentKeyId() {
    return currentAlias;
  }

  // JS-SEC-101: the alias exactly as the store lists it, or empty. KeyStore's
  // own lookups (getKey, getCertificate, containsAlias) ignore case.
  private Optional<String> exactAlias(KeyId keyId) throws KeyStoreException {
    String wanted = keyId.value();
    Enumeration<String> aliases = keyStore.aliases();
    while (aliases.hasMoreElements()) {
      if (aliases.nextElement().equals(wanted)) {
        return Optional.of(wanted);
      }
    }
    return Optional.empty();
  }

  @Override
  public PrivateKey currentSigningKey() {
    try {
      if (exactAlias(currentAlias).isEmpty()) {
        throw new KeyAccessException("Alias " + currentAlias.value()
            + " is not in the key store with exactly this spelling", null);
      }
      java.security.Key key = keyStore.getKey(currentAlias.value(), keyPassword);
      if (!(key instanceof PrivateKey privateKey)) {
        throw new KeyAccessException(
            "Alias " + currentAlias.value() + " is not a private-key entry", null);
      }
      return privateKey;
    } catch (GeneralSecurityException e) {
      throw new KeyAccessException("Cannot read signing key " + currentAlias.value(), e);
    }
  }

  @Override
  public SignatureAlgorithm currentAlgorithm() {
    return algorithm;
  }

  @Override
  public Optional<PublicKey> resolveVerificationKey(KeyId keyId) {
    Objects.requireNonNull(keyId, "keyId");
    try {
      if (exactAlias(keyId).isEmpty()) {
        return Optional.empty();
      }
      Certificate certificate = keyStore.getCertificate(keyId.value());
      return Optional.ofNullable(certificate).map(Certificate::getPublicKey);
    } catch (GeneralSecurityException e) {
      throw new KeyAccessException("Cannot read verification key " + keyId.value(), e);
    }
  }

  @Override
  public boolean mayVerify(KeyId keyId, EventProducerId producerId, TenantId tenantId) {
    Objects.requireNonNull(keyId, "keyId");
    Objects.requireNonNull(producerId, "producerId");
    Objects.requireNonNull(tenantId, "tenantId");
    try {
      if (exactAlias(keyId).isEmpty()) {
        return false;
      }
    } catch (KeyStoreException e) {
      throw new KeyAccessException("Cannot read the aliases of the key store", e);
    }
    Set<EventProducerId> bound = producerBindings.get(keyId);
    if (bound != null) {
      return bound.contains(producerId);
    }
    // No explicit binding: the alias names the one producer the key signs for.
    return keyId.value().equals(producerId.value());
  }

  @Override
  public KeyStatus keyStatus(KeyId keyId) {
    Objects.requireNonNull(keyId, "keyId");
    try {
      if (exactAlias(keyId).isEmpty()) {
        return KeyStatus.UNKNOWN;
      }
      Certificate certificate = keyStore.getCertificate(keyId.value());
      if (certificate instanceof X509Certificate x509) {
        try {
          x509.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
          return KeyStatus.EXPIRED;
        }
      }
      return keyId.equals(currentAlias)
          ? KeyStatus.ACTIVE
          : KeyStatus.ACCEPTED_FOR_VERIFICATION;
    } catch (GeneralSecurityException e) {
      throw new KeyAccessException("Cannot read key status " + keyId.value(), e);
    }
  }
}
