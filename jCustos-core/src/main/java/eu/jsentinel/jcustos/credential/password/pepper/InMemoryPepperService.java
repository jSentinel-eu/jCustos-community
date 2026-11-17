/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
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
package eu.jsentinel.jcustos.credential.password.pepper;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * In-process pepper key store for tests, demos and small single-node
 * deployments.
 *
 * <p>Keys are kept on the heap; the service holds defensive copies so
 * the caller can zero the original bytes. This is <strong>not</strong>
 * an HSM (see CWE-321 / CWE-798) — the operator must still keep the
 * pepper material out of source control, off the password database and
 * out of audit logs.</p>
 *
 * <p>For a production deployment, load the keys from where they are kept
 * instead: {@link KeyStorePepperService} (PKCS12 file, PKCS#11 token) or
 * {@link FilePepperService} (container secrets), or plug in a
 * {@link PepperService} backed by a secret manager.</p>
 */
public final class InMemoryPepperService implements PepperService {

  private final Map<String, byte[]> keysById;
  private final Optional<String> activeKeyId;

  private InMemoryPepperService(
      Map<String, byte[]> keysById, Optional<String> activeKeyId) {
    this.keysById = keysById;
    this.activeKeyId = activeKeyId;
  }

  /**
   * Convenience: build a service from a single active key.
   */
  public static InMemoryPepperService withActiveKey(String keyId, byte[] key) {
    Objects.requireNonNull(keyId, "keyId");
    Objects.requireNonNull(key, "key");
    if (key.length < PepperReference.MIN_KEY_BYTES) {
      throw new IllegalArgumentException(
          "pepper key must be at least "
              + PepperReference.MIN_KEY_BYTES + " bytes");
    }
    Map<String, byte[]> map = new LinkedHashMap<>();
    map.put(keyId, key.clone());
    return new InMemoryPepperService(map, Optional.of(keyId));
  }

  /**
   * Builder for multi-key configurations (one active + zero or more
   * retired, used by Phase-3 pepper rotation).
   */
  public static Builder builder() {
    return new Builder();
  }

  @Override
  public Optional<String> activeKeyId() {
    return activeKeyId;
  }

  // R013: resolve()/wipe()/knownKeyCount() are synchronized on this — wipe()
  // zeroes the key bytes in place and then clears the map, so an unsynchronized
  // concurrent resolve() could clone a half-zeroed key or hit the map mid-clear.
  @Override
  public synchronized Optional<byte[]> resolve(String keyId) {
    Objects.requireNonNull(keyId, "keyId");
    byte[] key = keysById.get(keyId);
    return Optional.ofNullable(key == null ? null : key.clone());
  }

  /**
   * Zeroes every held key and forgets all key ids. After this call the
   * service has no active key and {@link #resolve(String)} returns
   * {@link Optional#empty()} for every input.
   */
  public synchronized void wipe() {
    for (byte[] key : keysById.values()) {
      Arrays.fill(key, (byte) 0);
    }
    keysById.clear();
  }

  /**
   * Convenience for tests: returns the number of known key ids.
   */
  public synchronized int knownKeyCount() {
    return keysById.size();
  }

  public static final class Builder {

    private final Map<String, byte[]> keys = new LinkedHashMap<>();
    private String activeKeyId;

    private Builder() {
    }

    public Builder addKey(String keyId, byte[] key) {
      Objects.requireNonNull(keyId, "keyId");
      Objects.requireNonNull(key, "key");
      if (key.length < PepperReference.MIN_KEY_BYTES) {
        throw new IllegalArgumentException(
            "pepper key must be at least "
                + PepperReference.MIN_KEY_BYTES + " bytes");
      }
      if (keys.put(keyId, key.clone()) != null) {
        throw new IllegalArgumentException("duplicate pepper key id");
      }
      return this;
    }

    public Builder activeKeyId(String keyId) {
      this.activeKeyId = Objects.requireNonNull(keyId, "keyId");
      return this;
    }

    /**
     * Zeroes every key copy this builder holds and forgets them - for a key source whose load
     * failed after some keys were copied in (since 00.84.00). A service built from this builder
     * shares the copies, so this is called instead of {@link #build()}, never after it.
     */
    void wipe() {
      for (byte[] key : keys.values()) {
        Arrays.fill(key, (byte) 0);
      }
      keys.clear();
    }

    /** Package-visible for tests: the key copies this builder holds, not copies of them. */
    List<byte[]> heldCopies() {
      return List.copyOf(keys.values());
    }

    public InMemoryPepperService build() {
      if (activeKeyId == null) {
        throw new IllegalStateException("activeKeyId must be set");
      }
      if (!keys.containsKey(activeKeyId)) {
        throw new IllegalStateException(
            "activeKeyId must reference an added key");
      }
      return new InMemoryPepperService(
          new LinkedHashMap<>(keys), Optional.of(activeKeyId));
    }
  }
}
