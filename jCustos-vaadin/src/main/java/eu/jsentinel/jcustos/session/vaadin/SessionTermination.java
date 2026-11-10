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

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore;
import com.vaadin.flow.internal.CurrentInstance;
import com.vaadin.flow.server.HandlerHelper;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinResponse;
import com.vaadin.flow.server.VaadinService;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.VaadinSessionState;
import com.vaadin.flow.server.WrappedSession;
import com.vaadin.flow.shared.JsonConstants;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/**
 * Shared mechanics of the per-request session checks (JS-SEC-155, JS-SEC-131): finding and
 * locking the session of a request, telling a client message from the other request types,
 * tearing a session down and answering the request that triggered the teardown.
 *
 * <p>Package-private on purpose: the public entry points are {@link SessionLifetimeListener},
 * {@link JCustosVersionEnforcerListener} and {@link VaadinSessionRevocation}.
 */
final class SessionTermination {

  private static final String HTTP_POST = "POST";

  private SessionTermination() {
    // utility
  }

  /** @return {@code true} for a UIDL round-trip sent over XHR */
  static boolean isUidlRequest(VaadinRequest request) {
    return HandlerHelper.isRequestType(request, HandlerHelper.RequestType.UIDL);
  }

  /**
   * JS-SEC-155 (CWE-613): with {@code Transport.WEBSOCKET} the client sends its RPC messages
   * through the push channel. Atmosphere dispatches each of them as a {@code POST} on the
   * push request, while the handshake and the long-polling connect are {@code GET}s. Only the
   * former carries a client message.
   *
   * @return {@code true} for a client-to-server message that travels through the push channel
   */
  static boolean isPushMessage(VaadinRequest request) {
    return HandlerHelper.isRequestType(request, HandlerHelper.RequestType.PUSH)
        && HTTP_POST.equalsIgnoreCase(request.getMethod());
  }

  /**
   * Resolves the {@link VaadinSession} a request belongs to without creating one. A
   * {@code VaadinRequestInterceptor} runs before the framework looked the session up, so
   * {@link VaadinSession#getCurrent()} is still empty there.
   */
  static Optional<VaadinSession> sessionOf(VaadinRequest request) {
    try {
      WrappedSession wrapped = request.getWrappedSession(false);
      VaadinService service = request.getService();
      if (wrapped == null || service == null) {
        return Optional.empty();
      }
      Object candidate = wrapped.getAttribute(
          VaadinSession.class.getName() + "." + service.getServiceName());
      return candidate instanceof VaadinSession session ? Optional.of(session) : Optional.empty();
    } catch (RuntimeException invalidatedOrUnavailable) {
      return Optional.empty();
    }
  }

  /**
   * JS-SEC-155 (CWE-667, CWE-362): runs {@code check} with the session locked and bound as the
   * current session. Neither {@code VaadinService.handleRequest} nor
   * {@code VaadinService.requestStart} holds the session lock when it calls a plain
   * {@code RequestHandler} or a {@code VaadinRequestInterceptor}; every read and write of
   * session state has to take it itself.
   *
   * @return the result of {@code check}, or {@code fallback} when the session is not open
   */
  static <T> T underLock(VaadinSession session, T fallback, Function<VaadinSession, T> check) {
    session.lock();
    try {
      if (session.getState() != VaadinSessionState.OPEN) {
        return fallback;
      }
      Map<Class<?>, CurrentInstance> previous = CurrentInstance.setCurrent(session);
      try {
        return check.apply(session);
      } finally {
        CurrentInstance.restoreInstances(previous);
      }
    } finally {
      session.unlock();
    }
  }

  /**
   * Best-effort removal of everything that authenticates the session bound to the current
   * thread: the subject, the security-version snapshot and a bound token credential. Never
   * throws.
   */
  static void clearIdentity(VaadinSession session, SubjectStore store) {
    try {
      Class<?> subjectType = resolveSubjectType();
      SubjectStore effective = store != null ? store : SubjectStores.findSubjectStore().orElse(null);
      if (subjectType != null && effective != null) {
        removeSubjectUnchecked(effective, subjectType);
      }
    } catch (RuntimeException ignored) {
      // the session is closed regardless
    }
    try {
      VaadinJCustosVersionContext.clear(session);
    } catch (RuntimeException ignored) {
      // the session is closed regardless
    }
    try {
      JCustosServiceResolver.findTokenCredentialStore().ifPresent(TokenCredentialStore::clear);
    } catch (RuntimeException ignored) {
      // the session is closed regardless
    }
  }

  /**
   * Closes the Vaadin session and invalidates the HTTP session behind it. The caller holds
   * the session lock. Meant for a navigation listener: the surrounding request still renders
   * its response, and Vaadin destroys the session when that request ends.
   */
  static void closeAndInvalidate(VaadinSession session) {
    WrappedSession wrapped = session.getSession();
    try {
      session.close();
    } catch (RuntimeException ignored) {
      // continue with the HTTP session
    }
    if (wrapped != null) {
      try {
        wrapped.invalidate();
      } catch (RuntimeException alreadyInvalidated) {
        // nothing left to invalidate
      }
    }
  }

  /**
   * As {@link #closeAndInvalidate(VaadinSession)}, and requests the destroy event - UI
   * detach, session-destroy listeners, state {@code CLOSED} - explicitly; it runs as soon as
   * the session lock is released. Needed wherever the framework does not clean up by itself:
   * a request interceptor ends the session before the framework resolved it, so the request
   * ends without one, and a revocation runs outside any request of the session. The request
   * handlers use it as well, so the outcome does not depend on the order in which a servlet
   * container unbinds session attributes. A second destroy request for a session that is
   * already closed is a no-op in Vaadin.
   */
  static void closeInvalidateAndDestroy(VaadinSession session) {
    VaadinService service = session.getService();
    closeAndInvalidate(session);
    if (service != null) {
      try {
        service.fireSessionDestroy(session);
      } catch (RuntimeException ignored) {
        // the container's session listener is the last resort
      }
    }
  }

  /**
   * JS-SEC-155 (CWE-613): answers the request that triggered the teardown with Vaadin's
   * session-expired message, so the client reloads instead of the UIDL handler executing
   * the RPC invocations the request carries.
   */
  static void writeSessionExpired(VaadinRequest request, VaadinResponse response) throws IOException {
    VaadinService service = request.getService();
    service.writeUncachedStringResponse(response, JsonConstants.JSON_CONTENT_TYPE,
        VaadinService.createSessionExpiredJSON(false));
  }

  static Class<?> resolveSubjectType() {
    try {
      return JCustosServiceResolver.<Object, Object>authenticationService().subjectType();
    } catch (RuntimeException ignored) {
      return null;
    }
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  static void removeSubjectUnchecked(SubjectStore store, Class<?> subjectType) {
    Class raw = subjectType;
    store.deleteCurrentSubject(raw);
  }

  /** @return the id of the HTTP session behind {@code session}, or {@code null} */
  static String sessionIdOf(VaadinSession session) {
    try {
      WrappedSession wrapped = session.getSession();
      return wrapped == null ? null : wrapped.getId();
    } catch (RuntimeException invalidated) {
      return null;
    }
  }
}
