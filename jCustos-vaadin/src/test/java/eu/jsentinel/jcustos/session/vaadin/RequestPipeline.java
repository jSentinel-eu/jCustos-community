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

import com.vaadin.browserless.internal.MockVaadin;
import com.vaadin.browserless.internal.Routes;
import com.vaadin.browserless.internal.SessionObjects;
import com.vaadin.browserless.mocks.MockRequest;
import com.vaadin.browserless.mocks.MockResponse;
import com.vaadin.browserless.mocks.MockService;
import com.vaadin.browserless.mocks.MockVaadinServlet;
import com.vaadin.browserless.mocks.MockedUI;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.di.Instantiator;
import com.vaadin.flow.function.DeploymentConfiguration;
import com.vaadin.flow.internal.CurrentInstance;
import com.vaadin.flow.server.ServiceException;
import com.vaadin.flow.server.SessionExpiredException;
import com.vaadin.flow.server.SessionLockCheckStrategy;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinService;
import com.vaadin.flow.server.VaadinServiceInitListener;
import com.vaadin.flow.server.VaadinServletContext;
import com.vaadin.flow.server.VaadinServletRequest;
import com.vaadin.flow.server.VaadinServletResponse;
import com.vaadin.flow.server.VaadinServletService;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.WrappedHttpSession;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpSession;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Stream;

/**
 * Test support for JS-SEC-155 / JS-SEC-131: a real {@code VaadinServletService} whose
 * requests run through {@code VaadinService.handleRequest} on a thread that does
 * <em>not</em> hold the session lock - exactly how the servlet container calls it.
 *
 * <p>The earlier tests called {@code handleRequest} of the listener on the test thread,
 * which holds the session lock in a browserless test, and therefore never noticed that
 * Vaadin calls a request handler without it. Here the session is a plain
 * {@link VaadinSession} with the strict lock check Vaadin applies outside production mode
 * ({@link SessionLockCheckStrategy#THROW}), and it is not the browserless session that
 * re-creates itself on {@code close()}.
 *
 * <p>No mocking framework: the servlet, the service, the router, the UIDL handler and the
 * RPC handler are Vaadin's own; only the servlet request and response are the browserless
 * stand-ins, extended with a body.
 */
final class RequestPipeline implements AutoCloseable {

  private final VaadinServletService service;
  private final VaadinSession session;
  private final UI ui;
  private final HttpSession httpSession;
  private boolean lockReleased;

  private RequestPipeline(VaadinServletService service) {
    this.service = service;
    this.session = VaadinSession.getCurrent();
    this.ui = UI.getCurrent();
    this.httpSession = ((WrappedHttpSession) session.getSession()).getHttpSession();
  }

  /**
   * Starts a service with the given routes. The {@link SessionLifetimeListener} the service
   * loader would register is replaced by one that reads {@code clock}, so tests can move the
   * time.
   */
  @SafeVarargs
  static RequestPipeline start(Clock clock, Class<? extends Component>... routes) {
    return start(clock, List.of(), routes);
  }

  /**
   * As {@link #start(Clock, Class[])}, with additional service-init listeners - the place
   * where an application registers its own request handlers and interceptors.
   */
  @SafeVarargs
  static RequestPipeline start(Clock clock, List<VaadinServiceInitListener> extraListeners,
                               Class<? extends Component>... routes) {
    Routes routeSet = new Routes();
    routeSet.getRoutes().addAll(List.of(routes));
    StrictServlet servlet = new StrictServlet(routeSet, clock, extraListeners);
    MockVaadin.setup(MockedUI::new, servlet);
    return new RequestPipeline((VaadinServletService) VaadinService.getCurrent());
  }

  VaadinServletService service() {
    return service;
  }

  /** The session of the pipeline's browser; keep the reference, Vaadin holds it weakly. */
  VaadinSession session() {
    return session;
  }

  UI ui() {
    return ui;
  }

  String httpSessionId() {
    return httpSession.getId();
  }

  /** Navigates on the test thread, which holds the session lock like a UIDL handler would. */
  <T extends Component> T navigate(Class<T> view) {
    ui.navigate(view);
    return view.cast(ui.getInternals().getActiveRouterTargetsChain().get(0));
  }

  /** A second, independent session of the same service - "another browser". */
  SessionObjects newSession() {
    SessionObjects objects = MockVaadin.createSessionObjects(service);
    MockVaadin.fireSessionInit(service, objects.getSession(), objects.getRequest());
    return objects;
  }

  /**
   * Gives up the session lock the browserless set-up took for the test thread. From here on
   * the session is in the state a servlet container leaves it in between two requests.
   */
  void releaseLock() {
    if (!lockReleased) {
      ((ReentrantLock) session.getLockInstance()).unlock();
      lockReleased = true;
    }
  }

  void reacquireLock() {
    if (lockReleased) {
      session.getLockInstance().lock();
      lockReleased = false;
    }
  }

  /** Sends a DOM event for {@code component} as a UIDL request through the real pipeline. */
  Exchange fire(Component component, String eventName) {
    reacquireLock();
    int node = component.getElement().getNode().getId();
    return uidl("{\"type\":\"event\",\"node\":" + node + ",\"event\":\"" + eventName + "\",\"data\":{}}");
  }

  /** Sends the message the client's poll timer sends: the {@code ui-poll} event on the UI. */
  Exchange poll() {
    return fire(ui, "ui-poll");
  }

  /** Sends one UIDL request with the given RPC invocation through {@code handleRequest}. */
  Exchange uidl(String rpcJson) {
    reacquireLock();
    String body = "{\"csrfToken\":\"" + ui.getCsrfToken() + "\",\"rpc\":[" + rpcJson + "],\"syncId\":"
        + ui.getInternals().getServerSyncId() + ",\"clientId\":"
        + (ui.getInternals().getLastProcessedClientToServerId() + 1) + "}";
    BodyRequest raw = new BodyRequest(httpSession, "POST", body);
    raw.setParameter("v-r", "uidl");
    raw.setParameter("v-uiId", String.valueOf(ui.getUIId()));
    return send(raw, true);
  }

  /** Sends the keep-alive request the client sends while a tab is open. */
  Exchange heartbeat() {
    reacquireLock();
    BodyRequest raw = new BodyRequest(httpSession, "POST", "");
    raw.setParameter("v-r", "heartbeat");
    raw.setParameter("v-uiId", String.valueOf(ui.getUIId()));
    return send(raw, true);
  }

  /**
   * Replays what {@code PushHandler.callWithUi} does for a message that arrives over a
   * WebSocket: {@code VaadinService.requestStart} with a push request and no response, then
   * the session lookup. The RPC itself is not executed here; the result says whether the
   * push handler would still have found a session to execute it in.
   */
  PushOutcome pushMessage() {
    reacquireLock();
    BodyRequest raw = new BodyRequest(httpSession, "POST", "");
    raw.setParameter("v-r", "push");
    raw.setParameter("v-uiId", String.valueOf(ui.getUIId()));
    VaadinServletRequest request = new VaadinServletRequest(raw, service);
    AtomicReference<Throwable> failure = new AtomicReference<>();
    AtomicReference<Boolean> sessionFound = new AtomicReference<>(Boolean.FALSE);
    releaseLock();
    runOnRequestThread(() -> {
      VaadinSession found = null;
      try {
        service.requestStart(request, null);
        try {
          found = service.findVaadinSession(request);
        } catch (SessionExpiredException expired) {
          found = null;
        }
        sessionFound.set(found != null);
      } catch (Throwable t) {
        failure.set(t);
      } finally {
        try {
          service.requestEnd(request, null, found);
        } catch (Throwable t) {
          failure.compareAndSet(null, t);
        }
      }
    });
    reacquireLock();
    return new PushOutcome(sessionFound.get(), failure.get());
  }

  private Exchange send(BodyRequest raw, boolean keepLockAfterwards) {
    VaadinServletRequest request = new VaadinServletRequest(raw, service);
    CapturingResponse rawResponse = new CapturingResponse();
    VaadinServletResponse response = new VaadinServletResponse(rawResponse, service);
    AtomicReference<Throwable> failure = new AtomicReference<>();
    releaseLock();
    runOnRequestThread(() -> {
      try {
        service.handleRequest(request, response);
      } catch (ServiceException | RuntimeException | Error t) {
        failure.set(t);
      }
    });
    if (keepLockAfterwards) {
      reacquireLock();
    }
    return new Exchange(rawResponse.body(), failure.get());
  }

  private static void runOnRequestThread(Runnable request) {
    Thread thread = new Thread(() -> {
      try {
        request.run();
      } finally {
        CurrentInstance.clearAll();
      }
    }, "pipeline-request");
    thread.start();
    try {
      thread.join(30_000);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException(e);
    }
    if (thread.isAlive()) {
      thread.interrupt();
      throw new IllegalStateException("the request thread did not finish - is the session lock still held?");
    }
  }

  @Override
  public void close() {
    reacquireLock();
    // the request threads cleared their own instances; the test thread keeps its own
    VaadinSession.setCurrent(session);
    MockVaadin.tearDown();
  }

  /** What a request produced. */
  record Exchange(String body, Throwable failure) {
    boolean sessionExpired() {
      return body.contains("\"sessionExpired\":true");
    }

    boolean internalError() {
      return body.contains("\"appError\"");
    }
  }

  /** What the push handler would have found after {@code requestStart}. */
  record PushOutcome(boolean sessionFound, Throwable failure) { }

  // ── the real service on stand-in servlet objects ─────────────────

  /** A plain session with the lock check Vaadin applies in development mode. */
  private static final class StrictSession extends VaadinSession {
    StrictSession(VaadinService service) {
      super(service);
      applyLockStrategy(SessionLockCheckStrategy.THROW);
    }
  }

  private static final class StrictServlet extends MockVaadinServlet {
    private final transient Clock clock;
    private final transient List<VaadinServiceInitListener> extraListeners;

    StrictServlet(Routes routes, Clock clock, List<VaadinServiceInitListener> extraListeners) {
      super(routes, MockedUI::new);
      this.clock = clock;
      this.extraListeners = List.copyOf(extraListeners);
    }

    @Override
    protected VaadinServletService createServletService(DeploymentConfiguration configuration) {
      VaadinServletService service = new MockService(this, configuration, MockedUI::new) {
        @Override
        protected VaadinSession createVaadinSession(VaadinRequest request) {
          return new StrictSession(this);
        }

        @Override
        protected Instantiator createInstantiator() throws ServiceException {
          return withListeners(super.createInstantiator(), clock, extraListeners);
        }
      };
      try {
        service.init();
      } catch (ServiceException e) {
        throw new IllegalStateException(e);
      }
      getRoutes().register((VaadinServletContext) service.getContext());
      return service;
    }
  }

  /** Swaps the service-loaded lifetime listener for one that reads the test clock. */
  private static Instantiator withListeners(Instantiator delegate, Clock clock,
                                            List<VaadinServiceInitListener> extraListeners) {
    return (Instantiator) Proxy.newProxyInstance(
        Instantiator.class.getClassLoader(), new Class<?>[] {Instantiator.class},
        (proxy, method, args) -> {
          if ("getServiceInitListeners".equals(method.getName()) && method.getParameterCount() == 0) {
            Stream<VaadinServiceInitListener> others = delegate.getServiceInitListeners()
                .filter(listener -> !(listener instanceof SessionLifetimeListener));
            return Stream.concat(
                Stream.concat(others, Stream.of(new SessionLifetimeListener(clock))),
                extraListeners.stream());
          }
          try {
            return method.invoke(delegate, args);
          } catch (InvocationTargetException e) {
            throw e.getCause();
          }
        });
  }

  /** A servlet request with a method and a body. */
  private static final class BodyRequest extends MockRequest {
    private final String method;
    private final String body;

    BodyRequest(HttpSession session, String method, String body) {
      super(session);
      this.method = method;
      this.body = body;
    }

    @Override public String getMethod() {
      return method;
    }

    @Override public BufferedReader getReader() {
      return new BufferedReader(new StringReader(body));
    }

    @Override public String getContentType() {
      return "application/json; charset=UTF-8";
    }

    @Override public String getCharacterEncoding() {
      return StandardCharsets.UTF_8.name();
    }
  }

  /** A servlet response that keeps what was written. */
  private static final class CapturingResponse extends MockResponse {
    private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();

    @Override public ServletOutputStream getOutputStream() {
      return new ServletOutputStream() {
        @Override public boolean isReady() {
          return true;
        }

        @Override public void setWriteListener(WriteListener listener) {
          // synchronous
        }

        @Override public void write(int b) {
          bytes.write(b);
        }
      };
    }

    @Override public PrintWriter getWriter() {
      return new PrintWriter(bytes, true, StandardCharsets.UTF_8);
    }

    @Override public boolean isCommitted() {
      return false;
    }

    String body() {
      return bytes.toString(StandardCharsets.UTF_8);
    }
  }
}
