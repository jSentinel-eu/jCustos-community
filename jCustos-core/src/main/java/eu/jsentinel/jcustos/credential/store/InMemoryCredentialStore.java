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
package eu.jsentinel.jcustos.credential.store;

import eu.jsentinel.jcustos.util.SubjectKeyCanonicalizer;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link CredentialStore} backed by
 * {@link ConcurrentHashMap}, suitable for tests, demos and small
 * single-node deployments.
 *
 * <p>The CAS is implemented through
 * {@link ConcurrentHashMap#replace(Object, Object, Object)} which uses
 * the record's identity comparison — record equality is value-based,
 * so two records with the same field values are considered equal.
 * That means concurrent updates pinning the same witness deterministically
 * resolve to a single winner (CWE-362).</p>
 *
 * <p>JS-SEC-123 (CWE-178): the map key is the user name after the
 * {@link SubjectKeyCanonicalizer} - by default NFKC, lower-case, trimmed -
 * so {@code alice} and {@code ALICE} are one account here, exactly as they
 * are one counter in the login throttle. Until 00.83.00 the store compared
 * exactly while the throttle folded case: two accounts shared one failure
 * counter, and the owner of one could reset the counter of the other. The
 * record keeps the spelling it was registered with. A deployment whose
 * names are case-sensitive passes {@link SubjectKeyCanonicalizer#exact()}
 * here <em>and</em> to its login policy.</p>
 */
public final class InMemoryCredentialStore implements CredentialStore {

  private final ConcurrentHashMap<String, CredentialRecord> records =
      new ConcurrentHashMap<>();
  private final SubjectKeyCanonicalizer canonicalizer;

  /** Uses {@link SubjectKeyCanonicalizer#defaults()}. */
  public InMemoryCredentialStore() {
    this(SubjectKeyCanonicalizer.defaults());
  }

  /**
   * @param canonicalizer decides which spellings of a user name are the same
   *                      account; use the instance the login policy uses
   * @since 00.84.00
   */
  public InMemoryCredentialStore(SubjectKeyCanonicalizer canonicalizer) {
    this.canonicalizer = Objects.requireNonNull(canonicalizer, "canonicalizer");
  }

  private String key(String username) {
    return canonicalizer.canonicalize(username);
  }

  /**
   * Inserts a new record. Throws when a record under the same username
   * already exists - including a name that differs only in a spelling the
   * canonicaliser folds (JS-SEC-123); the test fixtures expect callers to
   * be explicit.
   */
  public CredentialRecord register(CredentialRecord record) {
    Objects.requireNonNull(record, "record");
    CredentialRecord prior = records.putIfAbsent(key(record.username()), record);
    if (prior != null) {
      throw new IllegalStateException(
          "credential already exists for username: " + record.username());
    }
    return record;
  }

  @Override
  public Optional<CredentialRecord> findByUsername(String username) {
    Objects.requireNonNull(username, "username");
    return Optional.ofNullable(records.get(key(username)));
  }

  @Override
  public CredentialUpdateResult updateHashIfCurrent(
      String username,
      String expectedEncodedHash,
      String newEncodedHash,
      Instant when) {
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(expectedEncodedHash, "expectedEncodedHash");
    Objects.requireNonNull(newEncodedHash, "newEncodedHash");
    Objects.requireNonNull(when, "when");

    String key = key(username);
    CredentialRecord current = records.get(key);
    if (current == null) {
      return CredentialUpdateResult.NotFound.INSTANCE;
    }
    if (!current.encodedHash().equals(expectedEncodedHash)) {
      return CredentialUpdateResult.Stale.INSTANCE;
    }
    CredentialRecord updated = current.withHash(newEncodedHash, when);
    if (!records.replace(key, current, updated)) {
      return CredentialUpdateResult.Stale.INSTANCE;
    }
    return new CredentialUpdateResult.Updated(updated);
  }

  @Override
  public CredentialUpdateResult updateStatusIfCurrent(
      String username,
      CredentialStatus expectedStatus,
      CredentialStatus newStatus,
      Instant when) {
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(expectedStatus, "expectedStatus");
    Objects.requireNonNull(newStatus, "newStatus");
    Objects.requireNonNull(when, "when");

    String key = key(username);
    CredentialRecord current = records.get(key);
    if (current == null) {
      return CredentialUpdateResult.NotFound.INSTANCE;
    }
    if (current.status() != expectedStatus) {
      return CredentialUpdateResult.Stale.INSTANCE;
    }
    CredentialRecord updated = current.withStatus(newStatus, when);
    if (!records.replace(key, current, updated)) {
      return CredentialUpdateResult.Stale.INSTANCE;
    }
    return new CredentialUpdateResult.Updated(updated);
  }

  /**
   * Test/demo helper: number of records currently held.
   */
  public int size() {
    return records.size();
  }
}
