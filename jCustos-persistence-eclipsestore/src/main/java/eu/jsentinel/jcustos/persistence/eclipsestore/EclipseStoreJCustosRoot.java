/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.jsentinel.jcustos.persistence.eclipsestore;

import eu.jsentinel.jcustos.accountlifecycle.EmailVerificationTokenRecord;
import eu.jsentinel.jcustos.accountlifecycle.PasswordResetTokenRecord;
import eu.jsentinel.jcustos.audit.AuditEnvelope;
import eu.jsentinel.jcustos.authentication.ApiKeyRecord;
import eu.jsentinel.jcustos.authentication.RefreshTokenRecord;
import eu.jsentinel.jcustos.authentication.RememberMeTokenRecord;
import eu.jsentinel.jcustos.authentication.RememberMeTokenStore;
import eu.jsentinel.jcustos.authorization.api.roles.RoleAssignmentKey;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bootstrap.BootstrapState;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptKey;
import eu.jsentinel.jcustos.ratelimiting.RateLimitKey;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;

import java.time.DateTimeException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;

/**
 * Package-private container for everything an Eclipse-Store-backed
 * persistence layer needs to keep around.
 * <p>
 * Eclipse Store reaches the entire object graph from a single root
 * reference; the {@link EclipseStoreJCustosStorage} lifecycle owns
 * the one and only instance of this class and hands it out to the
 * individual {@code EclipseStore*Store} adapters. Nothing outside
 * this module touches the root — the public API surface of the
 * module is the {@link EclipseStoreJCustosStorage} facade plus the
 * Phase-2 store SPIs.
 *
 * <p>Plan exit criterion: <em>no public API type called
 * {@code JCustosRoot}</em>. This class is package-private; its name
 * carries a precise prefix and the module suffix.
 *
 * <h2>Stored layout (JS-SEC-125)</h2>
 * <p>Since 00.84.00 the data lives in {@link #tables}: one
 * {@link StoredTable} per store and a {@link StoredLog} for the audit
 * events, so that a mutation writes the changed part and not a whole
 * map. The {@link java.util.Map} fields below are the layout of the
 * releases up to 00.83.x and of 00.84.00 before this change. They stay
 * declared, with their names and types, because Eclipse Store maps a
 * stored root to this class field by field; a root that was written in
 * the old layout is loaded into them, has no {@link #tables}, and is
 * moved over by {@link EclipseStoreJCustosStorage} when it is opened.
 * Afterwards the maps are empty and nothing reads or writes them.</p>
 */
final class EclipseStoreJCustosRoot {

  // ── layout up to 00.83.x: read once by the migration, empty afterwards ──

  /** id → envelope (audit events). */
  final Map<String, AuditEnvelope> auditEnvelopes = new LinkedHashMap<>();

  /** session id → session record. */
  final Map<SessionId, SessionRecord> sessions = new LinkedHashMap<>();

  /** login attempt key → (failureCount, lastFailureAt). */
  final Map<LoginAttemptKey, LoginAttemptLedger> loginAttempts = new LinkedHashMap<>();

  /** role assignment key → role set. */
  final Map<RoleAssignmentKey, LinkedHashSet<RoleName>> roleAssignments = new LinkedHashMap<>();

  /** tenant → bootstrap state. */
  final Map<TenantId, BootstrapState> bootstrapStates = new LinkedHashMap<>();

  /** token hash → remember-me record. */
  final Map<String, RememberMeTokenRecord> rememberMeTokens = new LinkedHashMap<>();

  /** token hash → password-reset record. */
  final Map<String, PasswordResetTokenRecord> passwordResetTokens = new LinkedHashMap<>();

  /** token hash → email-verification record. */
  final Map<String, EmailVerificationTokenRecord> emailVerificationTokens = new LinkedHashMap<>();

  /** key hash → api-key record. */
  final Map<String, ApiKeyRecord> apiKeys = new LinkedHashMap<>();

  /** token hash → refresh-token record. */
  final Map<String, RefreshTokenRecord> refreshTokens = new LinkedHashMap<>();

  /**
   * (tenant, subject) → instant before which the subject's refresh tokens are
   * invalid (JS-SEC-129, CWE-613). Added in 00.84.00 before the layout
   * changed: {@code null} in a root stored by 00.83.x, a map in a root stored
   * by an early 00.84.00 build.
   */
  Map<RefreshTokenScope, Instant> refreshTokenInvalidBefore = new LinkedHashMap<>();

  /** rate-limit key → event instants; a set, which lost events with equal instants (JS-SEC-118). */
  final Map<RateLimitKey, LinkedHashSet<Instant>> rateLimitEvents = new LinkedHashMap<>();

  /** (tenant, subject) → current security version. */
  final Map<JCustosVersionKey, JCustosVersion> securityVersions = new LinkedHashMap<>();

  // ── layout since 00.84.00 ──────────────────────────────────────────

  /**
   * Everything the stores keep (JS-SEC-125). {@code null} only in a root that
   * was written in the earlier layout and has not been opened by this version
   * yet — field initialisers do not run for instances the storage
   * reconstructs. {@link EclipseStoreJCustosStorage} sets it before any store
   * is handed out.
   */
  Tables tables = new Tables();

  /**
   * JS-SEC-122 / JS-SEC-123: the login-attempt store's working state - attempts in flight, the
   * expiry index, which entries are live lockouts. {@code transient}: Eclipse Store does not
   * persist it; after a restart it is {@code null} and {@code EclipseStoreLoginAttemptStore}
   * rebuilds it from {@link Tables#loginAttempts}. Guarded by the storage's write lock.
   */
  transient EclipseStoreLoginAttemptStore.WorkingState loginAttemptRuntime;

  /**
   * Working state of the rate-limit store: the instant, in the callers' time, before which it
   * does not look for dead buckets again. {@code transient}; guarded by the storage's write lock.
   */
  transient Instant rateLimitNextSweep;

  EclipseStoreJCustosRoot() {
  }

  /**
   * The stores' data in the layout that writes the changed part only. One
   * object under the root, so that "this root is in the old layout" is a
   * single {@code null} check. A stored type: a field added later is
   * {@code null} in a storage written before and has to be created on first
   * use, as {@link #tables} is.
   */
  static final class Tables {

    /** Audit events in append order. */
    final StoredLog<AuditEnvelope> auditEnvelopes = new StoredLog<>();

    /** session id → session record. */
    final StoredTable<SessionId, SessionRecord> sessions = new StoredTable<>();

    /** login attempt key → (failureCount, lastFailureAt). */
    final StoredTable<LoginAttemptKey, LoginAttemptLedger> loginAttempts = new StoredTable<>();

    /** role assignment key → role set; the set is changed in place and stored by its adapter. */
    final StoredTable<RoleAssignmentKey, LinkedHashSet<RoleName>> roleAssignments =
        new StoredTable<>();

    /** tenant → bootstrap state. */
    final StoredTable<TenantId, BootstrapState> bootstrapStates = new StoredTable<>();

    /** token hash → live remember-me record. */
    final StoredTable<String, RememberMeTokenRecord> rememberMeTokens = new StoredTable<>();

    /**
     * token hash → trail of a remember-me token that was consumed by a rotation
     * (JS-SEC-128): what makes a replayed token recognisable after a restart.
     */
    final StoredTable<String, RememberMeTokenStore.RotatedToken> rememberMeRotated =
        new StoredTable<>();

    /** token hash → password-reset record. */
    final StoredTable<String, PasswordResetTokenRecord> passwordResetTokens = new StoredTable<>();

    /** token hash → email-verification record. */
    final StoredTable<String, EmailVerificationTokenRecord> emailVerificationTokens =
        new StoredTable<>();

    /** key hash → api-key record. */
    final StoredTable<String, ApiKeyRecord> apiKeys = new StoredTable<>();

    /** token hash → refresh-token record. */
    final StoredTable<String, RefreshTokenRecord> refreshTokens = new StoredTable<>();

    /**
     * (tenant, subject) → instant before which the subject's refresh tokens are
     * invalid (JS-SEC-129, CWE-613), written by a subject-wide revocation.
     */
    final StoredTable<RefreshTokenScope, Instant> refreshTokenInvalidBefore = new StoredTable<>();

    /**
     * (tenant, subject) → instant before which the subject's remember-me tokens
     * are invalid (JS-SEC-129, CWE-613), written by a subject-wide revocation.
     * Added after the layout of 00.84.00 was first written: {@code null} in a
     * storage written by such a build, created by {@link EclipseStoreJCustosStorage}
     * when it opens one - hence not {@code final}.
     */
    StoredTable<RememberMeTokenScope, Instant> rememberMeInvalidBefore = new StoredTable<>();

    /** rate-limit key → the key's events; the bucket is changed in place and stored by its adapter. */
    final StoredTable<RateLimitKey, RateLimitBucket> rateLimitBuckets = new StoredTable<>();

    /** (tenant, subject) → current security version. */
    final StoredTable<JCustosVersionKey, JCustosVersion> securityVersions = new StoredTable<>();

    Tables() {
    }
  }

  /**
   * Tiny package-private record that holds the
   * {@code LoginAttemptStore}'s per-key state. Kept here (alongside
   * the root) rather than in {@code security-core} because it is an
   * implementation detail of how this module stores the data;
   * {@code LoginAttemptStore} itself exposes only counter +
   * timestamp through behavioural API.
   *
   * @param count          accumulated failure count
   * @param lastFailureAt  most recent failure instant
   */
  record LoginAttemptLedger(int count, Instant lastFailureAt) {
  }

  /**
   * Key of {@link Tables#refreshTokenInvalidBefore}: the subject within a tenant
   * whose refresh tokens were revoked wholesale. Kept here because it is an
   * implementation detail of how this module stores the mark.
   *
   * @param tenant    tenant scope
   * @param subjectId subject identifier value
   */
  record RefreshTokenScope(String tenant, String subjectId) {
  }

  /**
   * Key of {@link Tables#rememberMeInvalidBefore}: the subject within a tenant
   * whose remember-me tokens were revoked wholesale (JS-SEC-129).
   *
   * @param tenant    tenant scope
   * @param subjectId subject identifier value
   */
  record RememberMeTokenScope(String tenant, String subjectId) {
  }

  /**
   * The events of one rate-limit key (JS-SEC-118) and, since 00.84.00, its block.
   * A list in ascending order, not a set: two requests in the same clock tick are
   * two events.
   */
  static final class RateLimitBucket {

    /** Event instants, ascending; equal instants are kept. */
    final ArrayList<Instant> events = new ArrayList<>(4);

    /**
     * The widest window, in milliseconds, a policy has applied to this key
     * through {@code tryAdmit}; {@code 0} while none has. Once the newest event
     * is older than this, no admission can count the bucket any more and the
     * store drops it.
     */
    long retentionMillis;

    /**
     * End of the key's block, exclusive; {@code null} while the key has none. Added in
     * 00.84.00 after the layout of JS-SEC-125: a bucket stored before has none.
     */
    Instant blockedUntil;

    RateLimitBucket() {
    }

    /**
     * @return the instant from which this bucket can no longer influence a decision: its
     *     events are out of every window applied to it and its block has ended
     */
    Instant deadAt() {
      Instant eventsDeadAt = eventsDeadAt();
      return blockedUntil != null && blockedUntil.isAfter(eventsDeadAt)
          ? blockedUntil
          : eventsDeadAt;
    }

    private Instant eventsDeadAt() {
      if (events.isEmpty()) {
        return Instant.MIN;
      }
      if (retentionMillis <= 0) {
        return Instant.MAX; // only recordEvent has touched it: the window is unknown
      }
      try {
        // one millisecond of slack: an event exactly at the window start still counts
        return events.get(events.size() - 1).plusMillis(retentionMillis).plusMillis(1);
      } catch (DateTimeException | ArithmeticException beyondTheTimeline) {
        return Instant.MAX;
      }
    }
  }
}
