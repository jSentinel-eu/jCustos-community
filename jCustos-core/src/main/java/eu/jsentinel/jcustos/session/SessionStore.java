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
package eu.jsentinel.jcustos.session;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Store for {@link SessionRecord}s, keyed on {@link SessionId}.
 * <p>
 * Distinct from the existing
 * {@link eu.jsentinel.jcustos.logout.SubjectSessionRegistry}
 * which only maps a subject to its set of <em>active</em> session
 * ids (an index used by multi-session logout). {@code SessionStore}
 * owns the canonical, queryable representation of every session —
 * including expired and revoked ones, until they age out via
 * retention. Since V00.81 the retention (and the lazy
 * ACTIVE→EXPIRED transition) is implemented by wrapping the
 * concrete store in a {@link SweepingSessionStore}.
 *
 * <p>Mutation pattern: load a record, copy-with via the {@code with…}
 * methods on {@link SessionRecord}, save the new value. Stores upsert
 * on {@link #save(SessionRecord)} — there is no separate update call.
 *
 * <p>Implementations must be thread-safe.
 */
@ExperimentalJCustosApi
public interface SessionStore {

  /**
   * Persists or replaces the supplied session record. Keyed on
   * {@link SessionRecord#sessionId()}.
   *
   * @param session record to persist; must not be {@code null}
   */
  void save(SessionRecord session);

  /**
   * Looks up the record for a session id.
   *
   * @param sessionId session identifier; must not be {@code null}
   * @return the record, if present
   */
  Optional<SessionRecord> findById(SessionId sessionId);

  /**
   * Returns every record (in any {@link SessionStatus}) belonging to
   * {@code subjectId} within {@code tenant}, in insertion order
   * (oldest first).
   *
   * @param tenant    tenant scope; must not be {@code null}
   * @param subjectId subject; must not be {@code null}
   * @return immutable list of records; empty when none exist
   */
  List<SessionRecord> findBySubject(TenantId tenant, SubjectId subjectId);

  /**
   * Removes the record for {@code sessionId}.
   *
   * @param sessionId session identifier; must not be {@code null}
   * @return {@code true} if a record was removed,
   *         {@code false} when no such session existed
   */
  boolean delete(SessionId sessionId);

  /**
   * Returns every record currently persisted, in insertion order.
   * Used by admin tooling — e.g. the Phase-8a
   * {@code SessionManagementView} — that needs the full session
   * inventory across all subjects.
   * <p>
   * Default returns an empty list so pre-existing implementations
   * keep compiling; concrete stores override.
   *
   * @return immutable list of records, possibly empty; never {@code null}
   */
  /**
   * Moves the record stored under {@code from} to {@code to} (JS-SEC-060,
   * CWE-384). A record created during login must follow the HTTP session id
   * once the adapter rotates it; otherwise revocation by id misses the live
   * session. The default is find, save under the new id, delete the old id;
   * stores with an atomic primitive may override it.
   *
   * @param from the id the record is currently stored under; non-null
   * @param to   the surviving session id; non-null
   * @return {@code true} when a record was moved (or already lives under
   *         {@code to} because both ids are equal), {@code false} when no
   *         record exists under {@code from}
   * @since 00.84.00
   */
  default boolean rekey(SessionId from, SessionId to) {
    Objects.requireNonNull(from, "from must not be null");
    Objects.requireNonNull(to, "to must not be null");
    Optional<SessionRecord> existing = findById(from);
    if (existing.isEmpty()) {
      return false;
    }
    if (from.equals(to)) {
      return true;
    }
    save(existing.get().withSessionId(to));
    delete(from);
    return true;
  }

  default List<SessionRecord> findAll() {
    return List.of();
  }
}
