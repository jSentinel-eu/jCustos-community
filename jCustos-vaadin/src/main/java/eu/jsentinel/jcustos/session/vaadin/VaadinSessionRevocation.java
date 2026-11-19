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
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.authorization.api.CurrentSubject;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
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
 *       finds the session that currently carries the given HTTP session id - or whose id has
 *       the given {@link SessionRef reference} - and ends it through
 *       {@link VaadinSession#access}: the subject, the security-version snapshot and
 *       a bound token credential are cleared, {@code SessionInvalidated} is audited, the
 *       Vaadin session is closed and the HTTP session invalidated. A session that is busy
 *       with a request is ended as soon as that request releases the session lock.</li>
 *   <li><strong>On every other node, on the next request.</strong> When a store is
 *       registered through {@link #useSessionStore(SessionStore)}, the listener looks up the
 *       record of the current session on every client message, download, upload and
 *       navigation. A record with the status {@link SessionStatus#REVOKED}, or a record that
 *       was there on an earlier request and is gone now, ends the session in the same way and
 *       the request is answered with Vaadin's session-expired message.</li>
 * </ul>
 *
 * <p><strong>A revocation is a record, not a deletion (JS-SEC-131, CWE-613).</strong>
 * {@link #revoke(SessionRecord)} marks the record {@link SessionStatus#REVOKED} and keeps it.
 * Until the exit review of 00.84.00 it deleted the record, and a missing record ends a session
 * only on a node that saw the record on an earlier request: a session revoked before its first
 * request on another node, or after that node restarted, lived on. The {@link SessionStore}
 * contract keeps terminal records until their retention ends, and the stores of this release
 * do not evict a revoked record to make room for a new session.
 *
 * <p><strong>Records under a reference (JS-SEC-117, CWE-522).</strong> The HTTP session id is
 * the session cookie; a store should not hold it. Record sessions under
 * {@code SessionId.of(SessionRef.of(id))}. The per-request check looks the current session up
 * under its reference first and under the live id second, so stores of either kind keep
 * working, and {@link #revoke(SessionRecord)} of a record keyed by the reference ends the live
 * session on this node at once. No decorating store is needed for that.
 *
 * <p>A record with the status {@link SessionStatus#EXPIRED} does <em>not</em> end the session.
 * That status is derived from the lifetime policy; the listener evaluates the same policy
 * against the live session immediately beforehand and is the authority for it. A
 * {@code SweepingSessionStore} marks a record {@code EXPIRED} from the record's own
 * {@code lastActivityAt}, which no adapter advances, so treating it as a revocation would
 * end every session one idle timeout after the login.
 *
 * <p>Sessions the application never recorded are not affected: without a record under the
 * current session id or its reference there is nothing to revoke. The check only reads the
 * store. It never writes a record - not even the last-activity instant - because
 * {@link SessionStore} offers no atomic update, and a read-modify-write on the request path
 * could bring back a record an administrator removed in the same moment.
 *
 * <p>The audit events of this class carry the {@link SessionRef reference} of the session id,
 * never the id itself (JS-SEC-117).
 *
 * <p><strong>The subject id of a revocation (ER30 follow-up, decision F21, JS-SEC-097).</strong>
 * {@code SessionInvalidated} names the subject bound to the session through the value of the
 * registered {@link SubjectIdResolver}; without one - or when it fails or yields a blank
 * value - through the subject id of the session record that is revoked, so the audit trail
 * names the session under the id the session inventory shows; without a record through the
 * identity handle of {@link CurrentSubject#subjectIdOf(Object)}. It is never the subject's
 * {@code toString()}. Only a session without a bound subject and without a record id is
 * audited with an empty subject id: there is nobody to name. Until this follow-up a session
 * ended without a resolver and without a record was audited with an empty id.
 *
 * <p>The holder is process-wide. {@code VaadinSecurity.bootstrap()} publishes the store
 * whenever store-backed sessions are configured ({@code .sessions(s -> s.storeBacked(...))});
 * applications that wire the pieces by hand call {@link #useSessionStore(SessionStore)}
 * themselves.
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

  /**
   * Test helper of this package: forgets the registered store and every tracked session.
   * Package-private since the exit review of 00.84.00 (XR09-5) - as a public method it let
   * any code switch the check off for the whole process. Tests elsewhere call
   * {@link #useSessionStore(SessionStore) useSessionStore(null)}.
   */
  static void reset() {
    STORE.set(null);
    LIVE.clear();
  }

  /**
   * Revokes the session a record describes: marks the record {@link SessionStatus#REVOKED} in
   * the registered store, so every other node refuses the session on its next request - also
   * on its first - and ends the live session on this node. The record that is kept is the one
   * the store holds under the id, or {@code record} when the store holds none; its
   * {@link SessionRecord#lastActivityAt() last activity} becomes the instant of the
   * revocation, which anchors the retention of the terminal record. The live session on this
   * node is ended even when the store fails; the store's exception is rethrown afterwards.
   *
   * @param record the session to revoke; non-null
   * @return {@code true} when a live session on this node was found and its termination
   *     scheduled
   * @throws RuntimeException the exception of the store, after the live session was ended
   */
  public static boolean revoke(SessionRecord record) {
    requireNonNull(record, "record must not be null");
    RuntimeException storeFailure = null;
    try {
      findSessionStore().ifPresent(store -> markRevoked(store, record));
    } catch (RuntimeException failure) {
      storeFailure = failure;
    }
    boolean live = terminate(record.sessionId(), record.subjectId().value());
    if (storeFailure != null) {
      // JS-SEC-117 (CWE-532): the message of a store exception can name the key it was asked for
      HasLogger.staticLogger().warn("Session revocation: the SessionStore could not mark session {}"
          + " as revoked ({}); other nodes keep serving it until it ends", SessionRef.of(
          record.sessionId().value()), storeFailure.getClass().getName());
      throw storeFailure;
    }
    return live;
  }

  /** JS-SEC-131 (CWE-613): the store side of a revocation - a REVOKED record, never a gap. */
  private static void markRevoked(SessionStore store, SessionRecord record) {
    SessionRecord current = store.findById(record.sessionId()).orElse(record);
    Instant now = Instant.now();
    SessionRecord revoked = current.withStatus(SessionStatus.REVOKED);
    if (now.isAfter(revoked.lastActivityAt())) {
      revoked = revoked.withLastActivityAt(now);
    }
    store.save(revoked);
  }

  /**
   * Ends the live session on this node that currently carries {@code sessionId}. The session
   * id is compared with the id the HTTP session has now, so a session whose id was rotated
   * after login is found under the rotated id. The comparison is made on the
   * {@link SessionRef reference}: {@code sessionId} may be the live id or its reference, as a
   * session inventory keyed by references holds it.
   *
   * <p>The audit names the subject by the rule of the class comment: the registered
   * {@link SubjectIdResolver}'s value, else {@code recordSubjectId}, else the identity handle
   * of the bound subject (decision F21).
   *
   * @param sessionId       the HTTP session id or its reference; non-null
   * @param recordSubjectId the subject id of the session record, as the session inventory
   *                        shows it; audited when no resolver yields an id. May be
   *                        {@code null} or blank when there is no record: the identity
   *                        handle of the bound subject is audited then
   * @return {@code true} when a live session was found and its termination scheduled
   */
  public static boolean terminate(SessionId sessionId, String recordSubjectId) {
    requireNonNull(sessionId, "sessionId must not be null");
    String wanted = SessionRef.of(sessionId.value());
    boolean found = false;
    for (VaadinSession session : liveSessions()) {
      String liveId = SessionTermination.sessionIdOf(session);
      // JS-SEC-117 / JS-SEC-131: SessionRef.of is idempotent, so a live id and a reference
      // name the same session.
      if (liveId != null && !liveId.isBlank() && wanted.equals(SessionRef.of(liveId))) {
        found = true;
        // JS-SEC-131 (CWE-613): access() runs the command under the lock of the TARGET
        // session - at once when the session is idle, otherwise when its request ends.
        session.access(() -> terminateLocked(session, sessionId.value(), recordSubjectId));
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
   * <p>No session record is consulted, so the audit names the subject through the registered
   * {@link SubjectIdResolver} or, without one, through its identity handle (decision F21);
   * until then it carried an empty subject id without a resolver.
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
    String subjectId = auditSubjectId(null);
    String sessionId = SessionTermination.sessionIdOf(session);
    SessionTermination.clearIdentity(session);
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

  private static void terminateLocked(VaadinSession session, String sessionId, String recordSubjectId) {
    if (session.getState() != VaadinSessionState.OPEN) {
      return;
    }
    // The command may run on the thread of the administrator's request. Bind only the
    // target session, so nothing below reads the administrator's request or UI.
    CurrentInstance.clearAll();
    VaadinSession.setCurrent(session);
    String subjectId = auditSubjectId(recordSubjectId);
    SessionTermination.clearIdentity(session);
    auditRevoked(subjectId, sessionId);
    SessionTermination.closeInvalidateAndDestroy(session);
  }

  /**
   * JS-SEC-131 (CWE-613): the store side of the revocation, evaluated for the session bound
   * to the current thread with its lock held.
   *
   * @return the revocation when the record of the session says it was revoked - or when the
   *     record this session was seen with has gone; empty otherwise
   */
  static Optional<Revoked> revocationOf(VaadinSession session) {
    SessionStore store = STORE.get();
    if (store == null) {
      return Optional.empty();
    }
    String sessionId = SessionTermination.sessionIdOf(session);
    if (sessionId == null || sessionId.isBlank()) {
      return Optional.empty();
    }
    Optional<SessionRecord> record;
    try {
      // JS-SEC-117 / JS-SEC-131: a store keyed by the reference first, one keyed by the live
      // id second - both kinds are in use.
      record = store.findById(SessionId.of(SessionRef.of(sessionId)));
      if (record.isEmpty()) {
        record = store.findById(SessionId.of(sessionId));
      }
    } catch (RuntimeException storeFailure) {
      // An unreachable store must not log every user out; lifetime and drift checks still run.
      // JS-SEC-117 (CWE-532): the class only - the message can name the id the store was asked for.
      HasLogger.staticLogger().warn("Session revocation check skipped, the SessionStore failed: {}",
          storeFailure.getClass().getName());
      return Optional.empty();
    }
    if (record.isPresent()) {
      session.setAttribute(RECORD_SEEN_ATTRIBUTE, sessionId);
      return record.get().status() == SessionStatus.REVOKED
          ? Optional.of(new Revoked(record.get().subjectId().value()))
          : Optional.empty();
    }
    return sessionId.equals(session.getAttribute(RECORD_SEEN_ATTRIBUTE))
        ? Optional.of(new Revoked(null))
        : Optional.empty();
  }

  /**
   * A revocation found by {@link #revocationOf(VaadinSession)}.
   *
   * @param recordSubjectId the subject id of the revoked session record; {@code null} when the
   *                        record has gone since the session was seen with it
   */
  record Revoked(String recordSubjectId) {
  }

  static void auditRevoked(String subjectId, String sessionId) {
    audit(subjectId, sessionId, REASON_REVOKED);
  }

  private static void audit(String subjectId, String sessionId, String reason) {
    try {
      JCustosAuditService sink = JCustosServiceResolver.securityAuditService();
      // JS-SEC-117 (CWE-532, CWE-522): the event carries the reference, never the cookie.
      sink.publish(new SessionInvalidated(Instant.now(), subjectId == null ? "" : subjectId,
          SessionRef.ofNullable(sessionId), reason));
    } catch (RuntimeException auditFailure) {
      // never keep a session alive because the audit sink failed
    }
  }

  /**
   * ER30 follow-up, decision F21 (JS-SEC-097, CWE-1041, CWE-778): the subject id a revocation
   * audits for the subject bound to the current session - the registered
   * {@link SubjectIdResolver}'s value, else {@code recordSubjectId}, else the identity handle
   * of {@link CurrentSubject#subjectIdOf(Object)}. The subject is read through
   * {@link CurrentSubject#current()}, which reads a failing lookup as "no subject".
   *
   * @param recordSubjectId the subject id of the session record that is revoked; {@code null}
   *                        or blank when no record is bound
   * @return the subject id; empty only when no subject is bound and no record id is given
   */
  static String auditSubjectId(String recordSubjectId) {
    boolean recordNamesSubject = recordSubjectId != null && !recordSubjectId.isBlank();
    Optional<Object> subject = CurrentSubject.current();
    if (subject.isEmpty()) {
      return recordNamesSubject ? recordSubjectId : "";
    }
    if (!recordNamesSubject) {
      // the resolver, else the identity handle - CurrentSubject's own rule
      return CurrentSubject.subjectIdOf(subject.get());
    }
    return CurrentSubject.resolvedSubjectIdOf(subject.get()).orElse(recordSubjectId);
  }
}
