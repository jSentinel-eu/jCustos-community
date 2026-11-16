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
import com.svenruppert.dependencies.core.net.HttpStatus;
import com.svenruppert.dependencies.core.net.MediaType;
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
import com.vaadin.flow.server.communication.StreamRequestHandler;
import com.vaadin.flow.shared.ApplicationConstants;
import com.vaadin.flow.shared.JsonConstants;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/**
 * Shared mechanics of the per-request session checks (JS-SEC-155, JS-SEC-131): finding and
 * locking the session of a request, telling the requests that are checked from the others,
 * tearing a session down and answering the request that triggered the teardown.
 *
 * <p>Package-private on purpose: the public entry points are {@link SessionLifetimeListener},
 * {@link JCustosVersionEnforcerListener} and {@link VaadinSessionRevocation}.
 */
final class SessionTermination {

  private static final String HTTP_POST = "POST";

  /**
   * Values of the request-type parameter {@code v-r} the request handlers of the checks leave
   * alone (exit review XR03): the heartbeat carries no user action and is no activity; the
   * bootstrap request ({@code init}) performs a navigation, which the navigation listeners
   * check; a push request is checked by the request interceptor; the translation file and
   * the page for an outdated browser are static.
   */
  private static final Set<String> UNCHECKED_REQUEST_TYPES = Set.of(
      HandlerHelper.RequestType.HEARTBEAT.getIdentifier(),
      HandlerHelper.RequestType.INIT.getIdentifier(),
      HandlerHelper.RequestType.PUSH.getIdentifier(),
      HandlerHelper.RequestType.TRANSLATION_FILE.getIdentifier(),
      HandlerHelper.RequestType.BROWSER_TOO_OLD.getIdentifier());

  /** Body of the answer to a download or upload of an ended session - Vaadin's own wording. */
  static final String SESSION_EXPIRED_MESSAGE = "Session expired";

  private static final String CACHE_CONTROL_HEADER = "Cache-Control";
  private static final String NO_CACHE = "no-cache";

  private SessionTermination() {
    // utility
  }

  /**
   * Exit review XR03 (CWE-613): tells whether the per-request checks of the request handlers
   * apply. Until then only UIDL requests were checked, and a download, an upload or a
   * {@code StreamResource} of an expired, revoked or drifted session was served. Checked are:
   * <ul>
   *   <li>every request for a path of Vaadin's {@link StreamRequestHandler} -
   *       {@code DownloadHandler}, {@code UploadHandler}, {@code StreamResource},
   *       {@code StreamReceiver} - whatever request-type parameter it carries, because that
   *       handler runs before the heartbeat and UIDL handlers and does not look at it;</li>
   *   <li>every other request that carries a request type, except the
   *       {@linkplain #UNCHECKED_REQUEST_TYPES unchecked ones} - UIDL above all.</li>
   * </ul>
   * A request without a request type outside the stream paths is a page load or a static
   * resource and is not checked here; the navigation it leads to is.
   *
   * @return {@code true} when the request has to pass the checks before it is served
   */
  static boolean isCheckedRequest(VaadinRequest request) {
    if (isStreamRequest(request)) {
      return true;
    }
    String type = request.getParameter(ApplicationConstants.REQUEST_TYPE_PARAMETER);
    return type != null && !UNCHECKED_REQUEST_TYPES.contains(type);
  }

  /**
   * @return {@code true} for a request Vaadin's {@link StreamRequestHandler} serves - the
   *     same test that handler applies: the path info without its leading separator starts
   *     with {@code VAADIN/dynamic/resource/} ({@link StreamRequestHandler#DYN_RES_PREFIX})
   */
  static boolean isStreamRequest(VaadinRequest request) {
    String pathInfo = request.getPathInfo();
    return pathInfo != null && !pathInfo.isEmpty()
        && pathInfo.substring(1).startsWith(StreamRequestHandler.DYN_RES_PREFIX);
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
   * JS-SEC-155 / XR03 (CWE-613): answers the request that triggered the teardown instead of
   * the handler it was meant for. A client message receives Vaadin's session-expired message,
   * so the client reloads instead of the UIDL handler executing the RPC invocations the
   * request carries. A download or upload receives {@code 403} with
   * {@value #SESSION_EXPIRED_MESSAGE}, uncached - the answer Vaadin gives itself to a plain
   * HTTP request of an expired session; the stream handler never runs.
   */
  static void answerEnded(VaadinRequest request, VaadinResponse response) throws IOException {
    if (isStreamRequest(request)) {
      response.setHeader(CACHE_CONTROL_HEADER, NO_CACHE);
      response.setContentType(MediaType.TEXT_PLAIN.mime());
      response.sendError(HttpStatus.FORBIDDEN.code(), SESSION_EXPIRED_MESSAGE);
      return;
    }
    writeSessionExpired(request, response);
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

  /**
   * Exit review XR05 (CWE-636): ends a session whose per-request check failed with an
   * exception on the push channel. There the check runs in a request interceptor, and the
   * push handler executes the message once the interceptor returns - a check that throws
   * would let the message through, while on the XHR path the exception stops the request.
   * The identity is cleared and the session closed, invalidated and destroyed under its lock,
   * so the push handler finds no session and drops the message. Should that fail as well,
   * the HTTP session is invalidated without the lock. Never throws.
   */
  static void endAfterFailedCheck(VaadinSession session) {
    try {
      underLock(session, Boolean.FALSE, locked -> {
        clearIdentity(locked, null);
        closeInvalidateAndDestroy(locked);
        return Boolean.TRUE;
      });
    } catch (RuntimeException teardownFailure) {
      HasLogger.staticLogger().error("A session whose check failed could not be ended under its "
          + "lock ({}); its HTTP session is invalidated", teardownFailure.getClass().getName());
      try {
        WrappedSession wrapped = session.getSession();
        if (wrapped != null) {
          wrapped.invalidate();
        }
      } catch (RuntimeException alreadyInvalidated) {
        // nothing left to invalidate
      }
    }
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
