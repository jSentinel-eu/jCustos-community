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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.time.Instant;
import java.util.Objects;

/**
 * Persisted credential row, returned by {@link CredentialStore} reads
 * and used as the compare-and-swap witness on writes.
 *
 * <p>The {@code version} field is a monotonically increasing
 * optimistic-lock counter: every successful update returns a new record
 * with {@code version + 1}. CAS callers normally hand back the
 * {@code encodedHash} as the witness, but the version field is exposed
 * for adapters that prefer numeric optimistic-lock comparisons.</p>
 *
 * <h2>Rotation proof (JS-SEC-161, CWE-284, CWE-620)</h2>
 * <p>A credential that was declared {@link CredentialStatus#COMPROMISED}
 * must not be accepted again with the same secret. Since 00.84.00 the
 * record carries the proof of a rotation itself:</p>
 * <ul>
 *   <li>{@link #compromisedSince()} is set when the credential enters
 *       {@code COMPROMISED} and stays set - through {@code DISABLED},
 *       {@code MUST_CHANGE}, {@code RESET_PENDING} or {@code LOCKED} - until
 *       a new secret is written with {@link #withNewSecret};</li>
 *   <li>{@link #secretChangedAt()} is the instant of the last such write.
 *       A rehash of the same password ({@link #withHash}) is not a change
 *       and touches neither component.</li>
 * </ul>
 * <p>{@link #secretRotationRequired()} combines both with the status, and
 * {@code CredentialLifecycleService} refuses every transition to
 * {@link CredentialStatus#ACTIVE} while it is {@code true}. Until 00.84.00
 * a compromised credential that an administrator moved to {@code DISABLED}
 * or {@code MUST_CHANGE} could be switched back to {@code ACTIVE} with the
 * compromised secret still in place.</p>
 *
 * <p>Both components are {@code null} in a record built with the
 * six-argument constructor - the shape of the releases before 00.84.00,
 * still used by stores that do not persist them - and in a record that
 * Eclipse Store loads from a storage written before. Such a record counts
 * as compromised for as long as its status is {@code COMPROMISED};
 * {@link #withStatus} sets the marker when it moves the credential out of
 * {@code COMPROMISED} and finds none, so the proof is required from then
 * on (fail-closed).</p>
 *
 * <p>{@link #toString()} never exposes {@link #encodedHash()} (CWE-522 /
 * CWE-209).</p>
 *
 * @param username         case-sensitive identifier; never {@code null} or blank
 * @param encodedHash      full Phase-1a envelope as stored
 * @param status           current lifecycle status
 * @param version          optimistic-lock counter, starts at 1
 * @param createdAt        when the record was first written
 * @param updatedAt        when the record was last written
 * @param secretChangedAt  when the secret was last replaced by a new one, or
 *                         {@code null} when unknown; since 00.84.00
 * @param compromisedSince when the secret now stored was declared
 *                         compromised, or {@code null} while it is not; a
 *                         {@code COMPROMISED} record without one receives
 *                         {@code updatedAt}; since 00.84.00
 */
public record CredentialRecord(
    String username,
    String encodedHash,
    CredentialStatus status,
    long version,
    Instant createdAt,
    Instant updatedAt,
    Instant secretChangedAt,
    Instant compromisedSince
) {

  public CredentialRecord {
    Objects.requireNonNull(username, "username");
    if (username.isBlank()) {
      throw new IllegalArgumentException("username must not be blank");
    }
    Objects.requireNonNull(encodedHash, "encodedHash");
    if (encodedHash.isBlank()) {
      throw new IllegalArgumentException("encodedHash must not be blank");
    }
    Objects.requireNonNull(status, "status");
    if (version < 1L) {
      throw new IllegalArgumentException("version must be >= 1");
    }
    Objects.requireNonNull(createdAt, "createdAt");
    Objects.requireNonNull(updatedAt, "updatedAt");
    // JS-SEC-161: a COMPROMISED record always names when it was compromised,
    // so that the marker outlives the status.
    if (status == CredentialStatus.COMPROMISED && compromisedSince == null) {
      compromisedSince = updatedAt;
    }
  }

  /**
   * The record shape before 00.84.00: no rotation proof. A
   * {@code COMPROMISED} record receives {@code updatedAt} as
   * {@link #compromisedSince()}; every other record carries neither
   * component.
   *
   * @param username    case-sensitive identifier; never {@code null} or blank
   * @param encodedHash full Phase-1a envelope as stored
   * @param status      current lifecycle status
   * @param version     optimistic-lock counter, starts at 1
   * @param createdAt   when the record was first written
   * @param updatedAt   when the record was last written
   */
  public CredentialRecord(
      String username,
      String encodedHash,
      CredentialStatus status,
      long version,
      Instant createdAt,
      Instant updatedAt) {
    this(username, encodedHash, status, version, createdAt, updatedAt, null, null);
  }

  /**
   * Convenience: build a fresh record at version 1 with timestamps
   * equal to {@code now}. The secret counts as set at {@code now}.
   */
  public static CredentialRecord initial(
      String username, String encodedHash,
      CredentialStatus status, Instant now) {
    return new CredentialRecord(username, encodedHash, status, 1L, now, now, now, null);
  }

  /**
   * Returns a new record with the supplied hash and timestamp, version
   * bumped by one. For a new encoding of the <em>same</em> secret - a
   * rehash: {@link #secretChangedAt()} and {@link #compromisedSince()}
   * are kept. A changed password goes through {@link #withNewSecret}.
   */
  public CredentialRecord withHash(String newEncodedHash, Instant when) {
    return new CredentialRecord(username, newEncodedHash, status, version + 1, createdAt, when,
        secretChangedAt, compromisedSince);
  }

  /**
   * Returns a new record that holds a <em>new</em> secret - a password
   * change or a consumed reset (JS-SEC-161): the hash is replaced,
   * {@link #secretChangedAt()} becomes {@code when} and the compromise
   * marker is cleared, version bumped by one. While the status is still
   * {@code COMPROMISED} the marker stays: that status declares the stored
   * secret compromised, whichever it is.
   *
   * @param newEncodedHash envelope of the new secret
   * @param when           instant of the change
   * @return the changed record
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public CredentialRecord withNewSecret(String newEncodedHash, Instant when) {
    return new CredentialRecord(username, newEncodedHash, status, version + 1, createdAt, when,
        when, null);
  }

  /**
   * Returns a new record with the supplied status and timestamp,
   * version bumped by one. Entering {@code COMPROMISED} sets
   * {@link #compromisedSince()} unless it is set already; leaving it keeps
   * the marker, and sets it to {@code when} for a record that has none -
   * one written before 00.84.00 (JS-SEC-161).
   */
  public CredentialRecord withStatus(CredentialStatus newStatus, Instant when) {
    Instant since = compromisedSince;
    if (since == null
        && (status == CredentialStatus.COMPROMISED || newStatus == CredentialStatus.COMPROMISED)) {
      since = when;
    }
    return new CredentialRecord(username, encodedHash, newStatus, version + 1, createdAt, when,
        secretChangedAt, since);
  }

  /**
   * Whether the secret stored in this record is one that was declared
   * compromised and has not been replaced since (JS-SEC-161): the status is
   * {@code COMPROMISED}, or {@link #compromisedSince()} is set.
   *
   * @return {@code true} while only a new secret may return the credential
   *     to {@link CredentialStatus#ACTIVE}
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public boolean secretRotationRequired() {
    return status == CredentialStatus.COMPROMISED || compromisedSince != null;
  }

  @Override
  public String toString() {
    return "CredentialRecord["
        + "username=" + username
        + ", status=" + status
        + ", version=" + version
        + ", createdAt=" + createdAt
        + ", updatedAt=" + updatedAt
        + ", secretChangedAt=" + secretChangedAt
        + ", compromisedSince=" + compromisedSince
        + ", encodedHash=<redacted>"
        + "]";
  }
}
