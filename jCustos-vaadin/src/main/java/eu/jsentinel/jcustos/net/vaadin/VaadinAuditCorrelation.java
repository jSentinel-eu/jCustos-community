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
package eu.jsentinel.jcustos.net.vaadin;

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinRequestInterceptor;
import com.vaadin.flow.server.VaadinResponse;
import com.vaadin.flow.server.VaadinServiceInitListener;
import com.vaadin.flow.server.VaadinSession;
import eu.jsentinel.jcustos.audit.AuditCorrelation;
import eu.jsentinel.jcustos.audit.CorrelationIdResolver;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.io.Serial;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Correlation scope of a Vaadin request (R5, JS-SEC-066, CWE-778): audit events
 * recorded while Vaadin handles a request — a page load, a UIDL request, a
 * client message over the push channel — carry the request's correlation id,
 * in the audit store and as {@code corr=} in the audit line.
 * <p>
 * A {@link VaadinRequestInterceptor}: {@link #requestStart} resolves the id
 * through the registered {@link CorrelationIdResolver}, from the same request
 * view as {@link VaadinClientAddress} — a proxy's {@code X-Request-ID} only
 * from a trusted proxy, otherwise a server-side UUID — and opens the scope;
 * {@link #requestEnd}, which Vaadin calls in a {@code finally} block, closes
 * it. Work outside a request — {@code UI.access} from a background thread, a
 * scheduler — runs without a correlation id.
 * <p>
 * Registered as a {@link VaadinServiceInitListener} through
 * {@code META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener} of
 * jCustos-vaadin, after the other listeners of that file. Vaadin runs the
 * interceptors in the reverse order of their registration, so this one opens
 * the scope before the session checks of {@code SessionLifetimeListener}
 * audit. An interceptor that an application registers from a service-init
 * listener loaded after this one runs earlier and audits without the id.
 * <p>
 * One scope per request: a second instance — the class registered twice —
 * finds the scope of the first in the request and leaves it alone.
 * <p>
 * <strong>A request whose end is never signalled</strong> (exit review RF01,
 * CWE-401, CWE-778): Vaadin calls {@code requestStart} outside the
 * {@code try}/{@code finally} that calls {@code requestEnd}. When an
 * interceptor that runs after this one throws in {@code requestStart} - an
 * application's maintenance or tenant check that refuses a request by
 * throwing - {@code requestEnd} never comes, and the scope stayed on the pooled
 * thread: later audit events on that thread carried the refused request's id,
 * and every further refusal stacked one more scope. The scope this interceptor
 * opened is therefore remembered for the thread; a scope still open when the
 * next request starts on the thread is closed first, and the first such case
 * per JVM is reported as {@code audit/correlation-scope-stale}.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class VaadinAuditCorrelation
    implements VaadinServiceInitListener, VaadinRequestInterceptor, HasLogger {

  @Serial
  private static final long serialVersionUID = 1L;

  /** Request attribute holding the scope opened for the request. */
  static final String SCOPE_ATTRIBUTE = VaadinAuditCorrelation.class.getName() + ".scope";

  /**
   * RF01: the scope this interceptor opened on the thread and has not closed yet. Set in
   * {@link #requestStart}, removed in {@link #requestEnd}; still set at the next
   * {@code requestStart} only when the request before never ended.
   */
  private static final ThreadLocal<AuditCorrelation.Scope> OPENED_ON_THREAD = new ThreadLocal<>();

  /** RF01: one warning per JVM for a scope left open by a request that never ended. */
  private static final AtomicBoolean STALE_SCOPE_WARNED = new AtomicBoolean(false);

  /** Public for {@code ServiceLoader}. */
  public VaadinAuditCorrelation() {
  }

  @Override
  public void serviceInit(ServiceInitEvent event) {
    event.addVaadinRequestInterceptor(this);
  }

  /**
   * Opens the correlation scope of the request, after closing a scope an earlier
   * request on this thread left open (RF01). Never throws: a request whose scope
   * cannot be opened is handled without a correlation id.
   */
  @Override
  public void requestStart(VaadinRequest request, VaadinResponse response) {
    if (request == null) {
      return;
    }
    AuditCorrelation.Scope scope = null;
    try {
      if (request.getAttribute(SCOPE_ATTRIBUTE) != null) {
        return;
      }
      closeStaleScope();
      scope = AuditCorrelation.openFor(VaadinClientAddress.view(request));
      request.setAttribute(SCOPE_ATTRIBUTE, scope);
      OPENED_ON_THREAD.set(scope);
    } catch (RuntimeException failure) {
      if (scope != null) {
        scope.close();
      }
      // the class only: the message may quote request data
      logger().warn("audit/correlation-scope-not-opened: the request is handled without a "
          + "correlation id ({})", failure.getClass().getName());
    }
  }

  @Override
  public void handleException(VaadinRequest request, VaadinResponse response,
                              VaadinSession vaadinSession, Exception t) {
    // nothing to add - the scope is closed in requestEnd, which follows
  }

  /** Closes the scope {@link #requestStart} opened for the request. */
  @Override
  public void requestEnd(VaadinRequest request, VaadinResponse response, VaadinSession session) {
    if (request == null) {
      return;
    }
    Object scope = request.getAttribute(SCOPE_ATTRIBUTE);
    if (scope instanceof AuditCorrelation.Scope open) {
      request.removeAttribute(SCOPE_ATTRIBUTE);
      open.close();
      if (OPENED_ON_THREAD.get() == open) {
        OPENED_ON_THREAD.remove();
      }
    }
  }

  /**
   * RF01: closes the scope an earlier request on this thread opened and never closed - its
   * {@code requestEnd} did not come. Closing it also ends every scope opened above it and
   * restores what was current before it.
   */
  private void closeStaleScope() {
    AuditCorrelation.Scope stale = OPENED_ON_THREAD.get();
    if (stale == null) {
      return;
    }
    OPENED_ON_THREAD.remove();
    if (!stale.isOpen()) {
      return; // already ended - by an enclosing scope or JCustosServiceResolver.resetAll()
    }
    stale.close();
    if (STALE_SCOPE_WARNED.compareAndSet(false, true)) {
      logger().warn("audit/correlation-scope-stale: a correlation scope of an earlier Vaadin "
          + "request was still open on this thread - a request interceptor that runs after "
          + "VaadinAuditCorrelation threw in requestStart, so requestEnd never came. The scope "
          + "is closed before the next request opens its own (reported once per JVM)");
    }
  }

  /** Re-arms the once-per-JVM warning; for the tests of this package only. */
  static void resetStaleScopeWarning() {
    STALE_SCOPE_WARNED.set(false);
  }
}
