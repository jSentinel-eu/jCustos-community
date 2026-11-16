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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.SessionStore;
import eu.jsentinel.jcustos.session.SweepingSessionStore;
import eu.jsentinel.jcustos.util.CapacityBound;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Eclipse-Store-backed {@link SessionStore}.
 *
 * <p>JS-SEC-125 (CWE-770): a new session writes one segment of the table, an
 * update of a known session — the last-activity instant, a status change —
 * writes that session's slot. The store holds at most
 * {@link EclipseStoreJCustosStorage#maxEntries()} records.</p>
 *
 * <p>JS-SEC-131 (CWE-613): at the bound the records are not equally
 * expendable. A {@link SessionStatus#REVOKED} record is what tells every node
 * that the session is over; dropping it would bring the session back on every
 * node that has not seen the record before - after a restart, on a node
 * without the seen-memory of the adapter. A new session therefore makes room
 * in this order:</p>
 * <ol>
 *   <li>the oldest record that is {@link SessionStatus#EXPIRED}, or
 *       {@code REVOKED} for longer than {@link #REVOKED_RETENTION};</li>
 *   <li>the oldest {@link SessionStatus#ACTIVE} record - the adapters treat a
 *       record that disappeared as a revocation, so the oldest session ends;</li>
 *   <li>none: a store full of revoked records within their retention refuses
 *       the new session with {@code persistence/session-store-capacity-exceeded}
 *       instead of forgetting a revocation.</li>
 * </ol>
 *
 * <p>Records carry no expiry of their own — wrap the store in a
 * {@code SweepingSessionStore} to retire stale and terminal records by
 * policy.</p>
 */
final class EclipseStoreSessionStore implements SessionStore, HasLogger {

  /**
   * How long a {@link SessionStatus#REVOKED} record is kept at the bound, counted from its
   * {@link SessionRecord#lastActivityAt()}: 30 days, the default terminal retention of
   * {@link SweepingSessionStore}. Within it the record is never evicted for a new session.
   */
  static final Duration REVOKED_RETENTION = SweepingSessionStore.DEFAULT_TERMINAL_RETENTION;

  /** Capacity namespace of the refusal code {@code persistence/session-store-capacity-exceeded}. */
  static final String CAPACITY_NAMESPACE = "persistence/session-store";

  private final EclipseStoreJCustosStorage storage;

  EclipseStoreSessionStore(EclipseStoreJCustosStorage storage) {
    this.storage = storage;
  }

  @Override
  public void save(SessionRecord session) {
    requireNonNull(session, "session must not be null");
    storage.update(() -> {
      StoredTable<SessionId, SessionRecord> sessions = storage.tables().sessions;
      makeRoomFor(sessions, session.sessionId());
      sessions.put(session.sessionId(), session);
    });
  }

  /**
   * JS-SEC-131 (CWE-613): makes room for {@code incoming} without dropping a revocation; throws
   * when only revoked records within their retention are left. The caller holds the write lock.
   */
  private void makeRoomFor(StoredTable<SessionId, SessionRecord> sessions, SessionId incoming) {
    int maxEntries = storage.maxEntries();
    if (sessions.hasRoomFor(incoming, maxEntries)) {
      return;
    }
    Instant now = storage.now();
    int evicted = sessions.evictEldest(incoming, maxEntries, record -> isRetired(record, now));
    evicted += sessions.evictEldest(incoming, maxEntries, record -> record.status() == SessionStatus.ACTIVE);
    sessions.recordEvictions(evicted);
    if (evicted > 0 && sessions.evictionLogDue()) {
      logger().warn("persistence/session-store-capacity: the session store is at its bound of {}"
          + " records; for every new session the oldest expired record, or else the oldest active"
          + " record, is dropped - revoked records are kept", maxEntries);
    }
    if (!sessions.hasRoomFor(incoming, maxEntries)) {
      if (sessions.recordRefusal()) {
        logger().error("persistence/session-store-capacity: the session store is full of revoked"
            + " sessions within their retention of {} ({} records); new sessions are refused until"
            + " the retention ends or the bound is raised", REVOKED_RETENTION, maxEntries);
      }
      throw new IllegalStateException(
          CapacityBound.capacityExceededCode(CAPACITY_NAMESPACE) + ": " + maxEntries);
    }
  }

  /**
   * @return {@code true} for a record that may make room before any active one: expired, or
   *     revoked longer than {@link #REVOKED_RETENTION} ago
   */
  static boolean isRetired(SessionRecord record, Instant now) {
    return switch (record.status()) {
      case EXPIRED -> true;
      case REVOKED -> !now.isBefore(record.lastActivityAt().plus(REVOKED_RETENTION));
      case ACTIVE -> false;
    };
  }

  @Override
  public Optional<SessionRecord> findById(SessionId sessionId) {
    requireNonNull(sessionId, "sessionId must not be null");
    return storage.read(() -> Optional.ofNullable(storage.tables().sessions.get(sessionId)));
  }

  @Override
  public List<SessionRecord> findBySubject(TenantId tenant, SubjectId subjectId) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    return storage.read(() -> {
      List<SessionRecord> result = new ArrayList<>();
      for (SessionRecord record : storage.tables().sessions.values()) {
        if (record.tenant().equals(tenant) && record.subjectId().equals(subjectId)) {
          result.add(record);
        }
      }
      return List.copyOf(result);
    });
  }

  @Override
  public boolean delete(SessionId sessionId) {
    requireNonNull(sessionId, "sessionId must not be null");
    return storage.write(() -> storage.tables().sessions.remove(sessionId) != null);
  }

  @Override
  public List<SessionRecord> findAll() {
    return storage.read(() -> {
      List<SessionRecord> result = new ArrayList<>(storage.tables().sessions.size());
      storage.tables().sessions.values().forEach(result::add);
      return List.copyOf(result);
    });
  }
}
