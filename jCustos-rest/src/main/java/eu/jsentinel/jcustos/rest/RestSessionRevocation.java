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
package eu.jsentinel.jcustos.rest;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.SessionStore;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static java.util.Objects.requireNonNull;

/**
 * Refuses REST requests of sessions that were revoked (JS-SEC-131, CWE-613).
 *
 * <p>Until 00.84.00 nothing on the REST request path read the {@link SessionStore}: a
 * session whose record an administrator had set to {@link SessionStatus#REVOKED}, or
 * removed, kept being served until its token expired. With a store registered through
 * {@link #useSessionStore(SessionStore)}, {@link RestAuthenticationFilter},
 * {@link RestAuthorizationFilter} and {@link RestJCustosVersionFilter} look up the record
 * of the request's session before the handler runs; request paths that use none of the
 * three call {@link #allow(RestSubjectResolver, RestRequest, RestResponse)} themselves.
 *
 * <p><strong>Opt-in, in two steps.</strong> The check needs the store and the key of the
 * request's record: {@link RestSubjectResolver#resolveSessionId(RestRequest)}. Without a
 * registered store the resolver is not even asked; with a store but without a session id
 * the request passes. An application that does neither sees no change.
 *
 * <p><strong>What counts as revoked.</strong>
 * <ul>
 *   <li>A record with the status {@link SessionStatus#REVOKED}.</li>
 *   <li>A record that was found on an earlier request and is gone now - a revocation by
 *       {@link SessionStore#delete(SessionId)}, which is how the session-management route
 *       revokes. "Earlier" is remembered per node, for the
 *       {@value #SEEN_CAPACITY} sessions seen most recently (see below).</li>
 *   <li>With {@link #requireRecord(boolean) requireRecord(true)}: any session id without
 *       a record.</li>
 * </ul>
 * A record with the status {@link SessionStatus#EXPIRED} is <em>not</em> a revocation.
 * That status is derived from the lifetime policy, and both filters evaluate the policy
 * against {@link RestSubjectResolver#resolveSessionMetadata(RestRequest)} themselves; a
 * {@code SweepingSessionStore} marks a record {@code EXPIRED} from the record's own
 * {@code lastActivityAt}, which no adapter advances, so treating it as a revocation would
 * end every session one idle timeout after the login. A session the application never
 * recorded is not affected either, unless a record is required.
 *
 * <p><strong>What a refusal looks like.</strong> The request is answered as any other
 * unauthenticated request - through the decision mapper a bootstrap published to
 * {@link RestDecisionContext}, so {@code 401}, the {@code WWW-Authenticate} challenge and
 * the configured error-body strategy apply - and one {@link SessionInvalidated} event with
 * the reason {@value #REASON_REVOKED} is published, the event the Vaadin adapter publishes
 * for a revoked session. The event carries the {@link SessionRef} of the session id, never
 * the id. The handler does not run, whatever the mapper returns.
 *
 * <p><strong>Failure and side effects.</strong> A store that throws must not log every
 * user out: the failure is logged - at most once per {@link #FAILURE_LOG_INTERVAL}, the
 * rest counted - and the request proceeds to the lifetime and authorisation checks. The check only reads. It never writes a record - not even the
 * last-activity instant - because {@link SessionStore} offers no atomic update, and a
 * read-modify-write on the request path could bring back a record an administrator
 * removed in the same moment.
 *
 * <p><strong>Limits of the memory.</strong> REST has no server-side session to hang the
 * "record was seen" mark on, so it is kept in this class: per JVM, and bounded to
 * {@value #SEEN_CAPACITY} sessions, the least recently seen one making room. A removed
 * record is therefore not recognised as a revocation on a node the session never reached,
 * nor for a session that fell out of the memory. Deployments with several nodes, or with
 * more concurrent sessions than the bound, revoke by status ({@code REVOKED} is kept until
 * the retention sweep) or switch on {@link #requireRecord(boolean)}, which needs no
 * memory at all.
 *
 * <p>The holder is process-wide and the most recent caller owns it, as with
 * {@link RestDecisionContext}. {@code RestSecurity.bootstrap()} publishes the store
 * configured through {@code .sessions(s -> s.storeBacked(...))}.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class RestSessionRevocation {

  /** Audit reason of a request that was refused because its session was revoked. */
  public static final String REASON_REVOKED = "Revoked";

  /** Reason of the {@code Unauthenticated} decision handed to the decision mapper. */
  public static final String DECISION_REASON = "session-revoked";

  /**
   * Number of sessions for which this node remembers that their record was seen. The
   * entries hold a {@link SessionRef}, not the session id; 10 000 of them take about two
   * megabytes.
   */
  public static final int SEEN_CAPACITY = 10_000;

  /**
   * Minimum time between two WARN lines about the same failure of the REST filters: a
   * session store that cannot be read, an audit sink that refuses an event. The filters go
   * on without them, and one line per request would bury the log during an outage; the
   * occurrences in between are counted and named in the next line.
   *
   * @since 00.84.00
   */
  public static final Duration FAILURE_LOG_INTERVAL = Duration.ofMinutes(1);

  /** WARN code: the session store failed, the revocation check was skipped. */
  static final String CODE_STORE_FAILED = "rest/session-revocation-store-failed";

  /** WARN code: the audit sink refused an event of a REST filter. */
  static final String CODE_AUDIT_FAILED = "rest/audit-failed";

  static final RateLimitedWarning STORE_FAILURES = new RateLimitedWarning(
      CODE_STORE_FAILED, FAILURE_LOG_INTERVAL, HasLogger.staticLogger());

  static final RateLimitedWarning AUDIT_FAILURES = new RateLimitedWarning(
      CODE_AUDIT_FAILED, FAILURE_LOG_INTERVAL, HasLogger.staticLogger());

  private static final AtomicReference<SessionStore> STORE = new AtomicReference<>();

  private static final AtomicBoolean RECORD_REQUIRED = new AtomicBoolean();

  /** References of the sessions whose record was found, least recently seen first. */
  private static final Map<String, Boolean> SEEN = new LinkedHashMap<>(256, 0.75f, true) {
    @Override
    protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
      return size() > SEEN_CAPACITY;
    }
  };

  private RestSessionRevocation() {
    throw new AssertionError("no instances");
  }

  /**
   * Registers the store the REST filters consult, replacing any store registered before.
   * Passing {@code null} switches the check off again. The memory of seen records belongs
   * to the store and is forgotten with it.
   *
   * @param store the store that holds the session records, or {@code null}
   */
  public static void useSessionStore(SessionStore store) {
    SessionStore previous = STORE.getAndSet(store);
    if (previous != store) {
      forgetSeen();
    }
  }

  /** @return the store the REST filters consult, if one was registered */
  public static Optional<SessionStore> findSessionStore() {
    return Optional.ofNullable(STORE.get());
  }

  /**
   * Decides what a session id without a record means. {@code false} (the default): the
   * application never recorded that session, the request passes - unless the record was
   * seen before. {@code true}: every session id the resolver reports must have a record;
   * a missing one is a revocation. The strict mode recognises a removed record on every
   * node and for any number of sessions, and it requires the application to save the
   * record before it hands out the token.
   *
   * @param required whether a session id without a record is refused
   */
  public static void requireRecord(boolean required) {
    RECORD_REQUIRED.set(required);
  }

  /** @return whether a session id without a record is refused */
  public static boolean isRecordRequired() {
    return RECORD_REQUIRED.get();
  }

  /** Clears the holder: no store, no required record, no memory. Intended for tests and redeploys. */
  public static void reset() {
    STORE.set(null);
    RECORD_REQUIRED.set(false);
    forgetSeen();
  }

  /**
   * Runs the revocation check for request paths that use none of
   * {@link RestAuthenticationFilter}, {@link RestAuthorizationFilter} and
   * {@link RestJCustosVersionFilter}. Returns
   * {@code true} when the request may proceed. Returns {@code false} when its session was
   * revoked; the response is then written and the audit event published, and the caller
   * must not invoke the handler.
   *
   * @param resolver resolver that knows the session id of the request; non-null
   * @param request  current request; non-null
   * @param response response to populate on a refusal; non-null
   * @return {@code true} when the request passes
   */
  public static boolean allow(RestSubjectResolver resolver, RestRequest request, RestResponse response) {
    requireNonNull(resolver, "resolver must not be null");
    requireNonNull(request, "request must not be null");
    requireNonNull(response, "response must not be null");
    // R5 (JS-SEC-066): called outside the filters, so the SessionInvalidated it may publish
    // needs a correlation scope of its own; inside an open scope that scope's id is kept.
    return RestAuditCorrelation.call(request,
        () -> !refuseIfRevoked(resolver, request, response, null, null, null));
  }

  /**
   * The check as the filters run it, after they resolved the subject.
   *
   * @param subject      the resolved subject, or {@code null} to resolve it only when the
   *                     audit event needs it
   * @param mapper       the mapper to render the refusal through, or {@code null} for the
   *                     published one
   * @param auditService the audit service to publish to, or {@code null} for the
   *                     registered one
   * @return {@code true} when the request was refused - the response is written, the event
   *         published and the handler must not run
   */
  static boolean refuseIfRevoked(RestSubjectResolver resolver,
                                 RestRequest request,
                                 RestResponse response,
                                 JCustosSubject subject,
                                 RestDecisionMapping mapper,
                                 JCustosAuditService auditService) {
    SessionStore store = STORE.get();
    if (store == null) {
      // Not configured: the resolver is not asked, nothing changes for the application.
      return false;
    }
    Optional<SessionId> sessionId = resolver.resolveSessionId(request);
    if (sessionId == null || sessionId.isEmpty()) {
      return false;
    }
    Optional<String> revokedSubject = revokedSubjectId(store, sessionId.get());
    if (revokedSubject.isEmpty()) {
      return false;
    }
    String subjectId = subject != null
        ? subject.subjectId()
        : resolver.resolveSubject(request).map(JCustosSubject::subjectId).orElse(revokedSubject.get());
    audit(auditService, subjectId, sessionId.get());
    // The mapper renders the refusal, it does not decide it: the caller stops in any case.
    (mapper != null ? mapper : RestDecisionContext.mapperOrDefault())
        .apply(AuthorizationDecision.unauthenticated(DECISION_REASON), response);
    return true;
  }

  /**
   * @return empty when the session is not revoked; otherwise the subject id of its record,
   *         or an empty string when the record is gone
   */
  private static Optional<String> revokedSubjectId(SessionStore store, SessionId sessionId) {
    Optional<SessionRecord> record;
    try {
      record = store.findById(sessionId);
    } catch (RuntimeException storeFailure) {
      // An unreachable store must not refuse every request; lifetime and drift checks still run.
      // The type only: the message of a store failure may quote the session key.
      STORE_FAILURES.warn("the SessionStore failed (" + storeFailure.getClass().getName()
          + "), the revocation check was skipped and the request proceeds. A revoked session "
          + "is not recognised until the store answers again.");
      return Optional.empty();
    }
    String reference = SessionRef.of(sessionId.value());
    if (record != null && record.isPresent()) {
      rememberSeen(reference);
      return record.get().status() == SessionStatus.REVOKED
          ? Optional.of(record.get().subjectId().value())
          : Optional.empty();
    }
    return RECORD_REQUIRED.get() || wasSeen(reference) ? Optional.of("") : Optional.empty();
  }

  private static void audit(JCustosAuditService auditService, String subjectId, SessionId sessionId) {
    try {
      JCustosAuditService sink = auditService != null
          ? auditService
          : JCustosServiceResolver.securityAuditService();
      // JS-SEC-117: in a REST integration the session id tends to be derived from the bearer
      // token. The event carries the reference, never the id.
      sink.publish(new SessionInvalidated(
          Instant.now(Clock.systemUTC()),
          subjectId == null ? "" : subjectId,
          SessionRef.of(sessionId.value()),
          REASON_REVOKED));
    } catch (RuntimeException auditFailure) {
      // never serve a revoked session because the audit sink failed - but say so
      auditFailed(SessionInvalidated.class, auditFailure);
    }
  }

  /**
   * Announces an audit event a REST filter could not publish (ER13, CWE-778): the request
   * decision stands, the event is lost. Rate-limited, see {@link #FAILURE_LOG_INTERVAL}.
   */
  static void auditFailed(Class<?> eventType, RuntimeException auditFailure) {
    AUDIT_FAILURES.warn("the audit sink failed (" + auditFailure.getClass().getName()
        + ") to publish " + eventType.getSimpleName() + "; the event is lost, the request "
        + "decision stands. Check the configured JCustosAuditService.");
  }

  private static void rememberSeen(String reference) {
    synchronized (SEEN) {
      SEEN.put(reference, Boolean.TRUE);
    }
  }

  private static boolean wasSeen(String reference) {
    synchronized (SEEN) {
      return SEEN.get(reference) != null;
    }
  }

  private static void forgetSeen() {
    synchronized (SEEN) {
      SEEN.clear();
    }
  }
}
