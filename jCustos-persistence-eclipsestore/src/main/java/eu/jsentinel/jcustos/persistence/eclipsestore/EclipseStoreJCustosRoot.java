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

import java.time.Instant;
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
 * <p>The fields are mutable {@link LinkedHashMap}/{@link
 * LinkedHashSet} instances so Eclipse Store can persist them in
 * place — the store adapters mutate them under the lifecycle's
 * write lock and call {@code manager.store(field)} after each
 * mutation.
 */
final class EclipseStoreJCustosRoot {

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
   * invalid (JS-SEC-129, CWE-613), written by a subject-wide revocation.
   *
   * <p>Not {@code final} and possibly {@code null}: the field was added in
   * 00.84.00, and a root that was stored by an earlier version is loaded
   * without it — field initialisers do not run for instances the storage
   * reconstructs. {@link EclipseStoreRefreshTokenStore} creates the map on
   * first use under the write lock; nothing else may touch this field.</p>
   */
  Map<RefreshTokenScope, Instant> refreshTokenInvalidBefore = new LinkedHashMap<>();

  /** rate-limit key → ordered list of event instants. */
  final Map<RateLimitKey, LinkedHashSet<Instant>> rateLimitEvents = new LinkedHashMap<>();

  /** (tenant, subject) → current security version. */
  final Map<JCustosVersionKey, JCustosVersion> securityVersions = new LinkedHashMap<>();

  EclipseStoreJCustosRoot() {
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
   * Key of {@link #refreshTokenInvalidBefore}: the subject within a tenant
   * whose refresh tokens were revoked wholesale. Kept here because it is an
   * implementation detail of how this module stores the mark.
   *
   * @param tenant    tenant scope
   * @param subjectId subject identifier value
   */
  record RefreshTokenScope(String tenant, String subjectId) {
  }
}
