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
package eu.jsentinel.jcustos.logout;

import eu.jsentinel.jcustos.audit.LogoutPerformed;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Adapter-neutral default {@link LogoutService} implementation.
 * <p>
 * Clears the current subject from the {@link SubjectStore} (when the
 * scope is {@link LogoutScope#CurrentSession}), enumerates active
 * sessions via the {@link SubjectSessionRegistry}, fans the
 * notification out to every registered {@link LogoutListener}, and
 * emits a {@link LogoutPerformed} audit event per logged-out session.
 * <p>
 * Listener exceptions are swallowed — a misbehaving listener cannot
 * block the logout flow.
 *
 * @param <U> subject type (only used when scope is CurrentSession,
 *            for the SubjectStore wipe)
 */
public final class SubjectClearingLogoutService<U> implements LogoutService {

  private final SubjectStore subjectStore;
  private final Class<U> subjectType;
  private final SubjectSessionRegistry registry;
  private final JCustosAuditService auditService;
  private final List<LogoutListener> listeners = new CopyOnWriteArrayList<>();

  /**
   * Constructs a logout service that only clears the subject store;
   * uses {@link SubjectSessionRegistry} no-op behaviour. Suitable for
   * applications that don't need multi-session logout.
   *
   * @param subjectStore subject store to clear on CurrentSession scope
   * @param subjectType  subject type token
   */
  public SubjectClearingLogoutService(SubjectStore subjectStore, Class<U> subjectType) {
    this(subjectStore, subjectType, new InMemorySubjectSessionRegistry(), null);
  }

  /**
   * @param subjectStore subject store to clear on CurrentSession scope
   * @param subjectType  subject type token
   * @param registry     session registry consulted for
   *                     {@link LogoutScope#AllSessionsOfSubject}
   * @param auditService audit sink, or {@code null} to resolve from
   *                     {@link JCustosServiceResolver#securityAuditService()}
   *                     at logout time
   */
  public SubjectClearingLogoutService(
      SubjectStore subjectStore,
      Class<U> subjectType,
      SubjectSessionRegistry registry,
      JCustosAuditService auditService) {
    this.subjectStore = Objects.requireNonNull(subjectStore, "subjectStore");
    this.subjectType = Objects.requireNonNull(subjectType, "subjectType");
    this.registry = Objects.requireNonNull(registry, "registry");
    this.auditService = auditService;
  }

  @Override
  public void logout(SubjectId subjectId, LogoutScope scope) {
    Objects.requireNonNull(subjectId, "subjectId");
    Objects.requireNonNull(scope, "scope");

    Collection<String> targetedSessions = switch (scope) {
      case CurrentSession -> currentSession();
      case AllSessionsOfSubject -> registry.clearAll(subjectId);
    };

    // Clear the subject from the local SubjectStore — only meaningful
    // when we're logging out the current thread's session.
    if (scope == LogoutScope.CurrentSession) {
      subjectStore.deleteCurrentSubject(subjectType);
    }

    // Fan-out and audit one event per session. For CurrentSession
    // without a known session id, fire once with null.
    if (targetedSessions.isEmpty()) {
      fanOut(subjectId, null, scope);
    } else {
      for (String sessionId : targetedSessions) {
        fanOut(subjectId, sessionId, scope);
      }
    }
  }

  private static Collection<String> currentSession() {
    // The adapter-neutral default doesn't have a notion of "the current
    // session id" — that's adapter-specific (Vaadin session id, bearer
    // token, etc.). Return an empty collection so fanOut fires once
    // with null.
    return new ArrayList<>();
  }

  private void fanOut(SubjectId subjectId, String sessionId, LogoutScope scope) {
    for (LogoutListener listener : listeners) {
      try {
        listener.onLogout(subjectId, sessionId, scope);
      } catch (RuntimeException listenerFailure) {
        // never block the logout because a listener threw
      }
    }
    audit(subjectId, sessionId, scope);
  }

  private void audit(SubjectId subjectId, String sessionId, LogoutScope scope) {
    JCustosAuditService sink = auditService != null
        ? auditService
        : JCustosServiceResolver.securityAuditService();
    try {
      // JS-SEC-117 (CWE-532): listeners need the session id to end the session; the audit
      // event gets its reference only.
      sink.publish(new LogoutPerformed(
          Instant.now(Clock.systemUTC()), subjectId.value(), SessionRef.ofNullable(sessionId), scope));
    } catch (RuntimeException auditFailure) {
      // never block the logout because the audit sink failed
    }
  }

  @Override
  public void addListener(LogoutListener listener) {
    Objects.requireNonNull(listener, "listener");
    if (!listeners.contains(listener)) {
      listeners.add(listener);
    }
  }

  @Override
  public void removeListener(LogoutListener listener) {
    listeners.remove(listener);
  }
}
