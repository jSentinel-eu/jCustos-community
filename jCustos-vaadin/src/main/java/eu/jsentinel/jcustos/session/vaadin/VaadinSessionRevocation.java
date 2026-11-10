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
package eu.jsentinel.jcustos.session.vaadin;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.SessionStore;
import com.vaadin.flow.internal.CurrentInstance;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.VaadinSessionState;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.atomic.AtomicReference;

import static java.util.Objects.requireNonNull;

/**
 * Ends Vaadin sessions that were revoked (JS-SEC-131, CWE-613).
 *
 * <p>Until 00.84.00 a revoke only changed the {@link SessionStore}: nothing on the request
 * path read the record, so the revoked user kept working until the idle timeout or the
 * absolute lifetime ended the session. This class closes that gap in two ways.
 *
 * <ul>
 *   <li><strong>On this node, at once.</strong> {@link SessionLifetimeListener} tracks the
 *       live {@link VaadinSession}s of the service. {@link #terminate(SessionId, String)}
 *       finds the session that currently carries the given HTTP session id and ends it
 *       through {@link VaadinSession#access}: the subject, the security-version snapshot and
 *       a bound token credential are cleared, {@code SessionInvalidated} is audited, the
 *       Vaadin session is closed and the HTTP session invalidated. A session that is busy
 *       with a request is ended as soon as that request releases the session lock.</li>
 *   <li><strong>On every other node, on the next request.</strong> When a store is
 *       registered through {@link #useSessionStore(SessionStore)}, the listener looks up the
 *       record of the current session on every client message and navigation. A record with
 *       the status {@link SessionStatus#REVOKED}, or a record that was there on an earlier
 *       request and is gone now, ends the session in the same way and the request is
 *       answered with Vaadin's session-expired message.</li>
 * </ul>
 *
 * <p>A record with the status {@link SessionStatus#EXPIRED} does <em>not</em> end the session.
 * That status is derived from the lifetime policy; the listener evaluates the same policy
 * against the live session immediately beforehand and is the authority for it. A
 * {@code SweepingSessionStore} marks a record {@code EXPIRED} from the record's own
 * {@code lastActivityAt}, which no adapter advances, so treating it as a revocation would
 * end every session one idle timeout after the login.
 *
 * <p>Sessions the application never recorded are not affected: without a record under the
 * current session id there is nothing to revoke. The check only reads the store. It never
 * writes a record - not even the last-activity instant - because {@link SessionStore} offers
 * no atomic update, and a read-modify-write on the request path could bring back a record an
 * administrator removed in the same moment.
 *
 * <p>The holder is process-wide. {@code VaadinSecurity.bootstrap()} publishes the configured
 * store when the session-management route is activated; applications that wire the pieces
 * by hand call {@link #useSessionStore(SessionStore)} themselves.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class VaadinSessionRevocation {

  /** Audit reason of a session that was ended because it was revoked. */
  public static final String REASON_REVOKED = "Revoked";

  /**
   * Session attribute that remembers under which HTTP session id the record of this session
   * was last found in the store. A record missing under that very id was removed, which is
   * how the default revoke of the session-management route works.
   */
  static final String RECORD_SEEN_ATTRIBUTE = "eu.jsentinel.jcustos.session.recordSeenUnder";

  private static final AtomicReference<SessionStore> STORE = new AtomicReference<>();

  /** Live sessions of this node; weak so a session the container dropped is not kept alive. */
  private static final Set<VaadinSession> LIVE =
      Collections.synchronizedSet(Collections.newSetFromMap(new WeakHashMap<>()));

  private VaadinSessionRevocation() {
    throw new AssertionError("no instances");
  }

  /**
   * Registers the store the per-request check consults. Passing {@code null} switches the
   * check off again.
   *
   * @param store the store that holds the session records, or {@code null}
   */
  public static void useSessionStore(SessionStore store) {
    STORE.set(store);
  }

  /** @return the store the per-request check consults, if one was registered */
  public static Optional<SessionStore> findSessionStore() {
    return Optional.ofNullable(STORE.get());
  }

  /** Test helper: forgets the registered store and every tracked session. */
  public static void reset() {
    STORE.set(null);
    LIVE.clear();
  }

  /**
   * Revokes the session a record describes: removes the record from the registered store, so
   * other nodes refuse the session on its next request, and ends the live session on this
   * node. This is the default revoke of the session-management route.
   *
   * @param record the session to revoke; non-null
   * @return {@code true} when a live session on this node was found and its termination
   *     scheduled
   */
  public static boolean revoke(SessionRecord record) {
    requireNonNull(record, "record must not be null");
    findSessionStore().ifPresent(store -> store.delete(record.sessionId()));
    return terminate(record.sessionId(), record.subjectId().value());
  }

  /**
   * Ends the live session on this node that currently carries {@code sessionId}. The session
   * id is compared with the id the HTTP session has now, so a session whose id was rotated
   * after login is found under the rotated id.
   *
   * @param sessionId         the HTTP session id; non-null
   * @param fallbackSubjectId subject id to audit when the session no longer exposes one;
   *                          may be {@code null}
   * @return {@code true} when a live session was found and its termination scheduled
   */
  public static boolean terminate(SessionId sessionId, String fallbackSubjectId) {
    requireNonNull(sessionId, "sessionId must not be null");
    boolean found = false;
    for (VaadinSession session : liveSessions()) {
      if (sessionId.value().equals(SessionTermination.sessionIdOf(session))) {
        found = true;
        // JS-SEC-131 (CWE-613): access() runs the command under the lock of the TARGET
        // session - at once when the session is idle, otherwise when its request ends.
        session.access(() -> terminateLocked(session, sessionId.value(), fallbackSubjectId));
      }
    }
    return found;
  }

  /**
   * Ends the session bound to the current thread from inside one of its own requests - for a
   * login that must not stand, such as an OAuth2 callback whose session id could not be
   * rotated (JS-SEC-146, CWE-384). The subject, the security-version snapshot and a bound
   * token credential are cleared, {@code SessionInvalidated} is audited with {@code reason},
   * the Vaadin session is closed and the HTTP session invalidated. The surrounding request
   * still renders its response; Vaadin destroys the session when that request ends. The
   * caller holds the session lock, as every navigation listener and RPC handler does.
   *
   * @param reason the audit reason; non-null
   * @return {@code false} when no session is bound to the thread
   */
  public static boolean endCurrentSession(String reason) {
    requireNonNull(reason, "reason must not be null");
    VaadinSession session = VaadinSession.getCurrent();
    if (session == null) {
      return false;
    }
    SubjectStore store = SubjectStores.findSubjectStore().orElse(null);
    String subjectId = currentSubjectId(store).orElse("");
    String sessionId = SessionTermination.sessionIdOf(session);
    SessionTermination.clearIdentity(session, store);
    audit(subjectId, sessionId, reason);
    SessionTermination.closeAndInvalidate(session);
    return true;
  }

  /** Called by {@link SessionLifetimeListener} for every session the service starts. */
  static void track(VaadinSession session) {
    if (session != null) {
      LIVE.add(session);
    }
  }

  /** Called by {@link SessionLifetimeListener} for every session the service destroys. */
  static void untrack(VaadinSession session) {
    if (session != null) {
      LIVE.remove(session);
    }
  }

  private static List<VaadinSession> liveSessions() {
    synchronized (LIVE) {
      return new ArrayList<>(LIVE);
    }
  }

  private static void terminateLocked(VaadinSession session, String sessionId, String fallbackSubjectId) {
    if (session.getState() != VaadinSessionState.OPEN) {
      return;
    }
    // The command may run on the thread of the administrator's request. Bind only the
    // target session, so nothing below reads the administrator's request or UI.
    CurrentInstance.clearAll();
    VaadinSession.setCurrent(session);
    SubjectStore store = SubjectStores.findSubjectStore().orElse(null);
    String subjectId = currentSubjectId(store).orElse(fallbackSubjectId);
    SessionTermination.clearIdentity(session, store);
    auditRevoked(subjectId, sessionId);
    SessionTermination.closeInvalidateAndDestroy(session);
  }

  /**
   * JS-SEC-131 (CWE-613): the store side of the revocation, evaluated for the session bound
   * to the current thread with its lock held.
   *
   * @return {@code true} when the record of the session says it was revoked
   */
  static boolean isRevoked(VaadinSession session) {
    SessionStore store = STORE.get();
    if (store == null) {
      return false;
    }
    String sessionId = SessionTermination.sessionIdOf(session);
    if (sessionId == null || sessionId.isBlank()) {
      return false;
    }
    Optional<SessionRecord> record;
    try {
      record = store.findById(SessionId.of(sessionId));
    } catch (RuntimeException storeFailure) {
      // An unreachable store must not log every user out; lifetime and drift checks still run.
      HasLogger.staticLogger().warn("Session revocation check skipped, the SessionStore failed: {}",
          storeFailure.toString());
      return false;
    }
    if (record.isPresent()) {
      session.setAttribute(RECORD_SEEN_ATTRIBUTE, sessionId);
      return record.get().status() == SessionStatus.REVOKED;
    }
    return sessionId.equals(session.getAttribute(RECORD_SEEN_ATTRIBUTE));
  }

  static void auditRevoked(String subjectId, String sessionId) {
    audit(subjectId, sessionId, REASON_REVOKED);
  }

  private static void audit(String subjectId, String sessionId, String reason) {
    try {
      JCustosAuditService sink = JCustosServiceResolver.securityAuditService();
      sink.publish(new SessionInvalidated(
          Instant.now(), subjectId == null ? "" : subjectId, sessionId, reason));
    } catch (RuntimeException auditFailure) {
      // never keep a session alive because the audit sink failed
    }
  }

  /** Resolves the audit id of the subject bound to the current session; never the raw subject. */
  static Optional<String> currentSubjectId(SubjectStore store) {
    try {
      Class<?> subjectType = SessionTermination.resolveSubjectType();
      if (store == null || subjectType == null) {
        return Optional.empty();
      }
      Optional<?> subject = store.currentSubject(subjectType);
      if (subject.isEmpty()) {
        return Optional.empty();
      }
      Optional<SubjectIdResolver<Object>> resolver = JCustosServiceResolver.findSubjectIdResolver();
      if (resolver.isEmpty()) {
        return Optional.empty();
      }
      String resolved = resolver.get().resolve(subject.get()).value();
      return resolved == null || resolved.isBlank() ? Optional.empty() : Optional.of(resolved);
    } catch (RuntimeException ignored) {
      return Optional.empty();
    }
  }
}
