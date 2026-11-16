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
import eu.jsentinel.jcustos.session.SessionStore;

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
 * {@link EclipseStoreJCustosStorage#maxEntries()} records; at the bound the
 * record that was stored first is dropped to make room. A session whose
 * record is gone is not listed any more and cannot be revoked by id; the
 * Vaadin adapter treats a record that disappeared as a revocation. Records
 * carry no expiry of their own — wrap the store in a
 * {@code SweepingSessionStore} to retire stale and terminal records by
 * policy.</p>
 */
final class EclipseStoreSessionStore implements SessionStore, HasLogger {

  private final EclipseStoreJCustosStorage storage;

  EclipseStoreSessionStore(EclipseStoreJCustosStorage storage) {
    this.storage = storage;
  }

  @Override
  public void save(SessionRecord session) {
    requireNonNull(session, "session must not be null");
    storage.update(() -> {
      StoredTable<SessionId, SessionRecord> sessions = storage.tables().sessions;
      int evicted = sessions.makeRoomFor(session.sessionId(), storage.maxEntries(), storage.now());
      if (evicted > 0 && sessions.evictionLogDue()) {
        logger().warn("persistence/session-store-capacity: the session store is at its bound of {}"
            + " records; the oldest record is dropped for every new session", storage.maxEntries());
      }
      sessions.put(session.sessionId(), session);
    });
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
