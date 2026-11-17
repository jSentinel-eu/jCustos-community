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

  /** Public for {@code ServiceLoader}. */
  public VaadinAuditCorrelation() {
  }

  @Override
  public void serviceInit(ServiceInitEvent event) {
    event.addVaadinRequestInterceptor(this);
  }

  /**
   * Opens the correlation scope of the request. Never throws: a request whose
   * scope cannot be opened is handled without a correlation id.
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
      scope = AuditCorrelation.openFor(VaadinClientAddress.view(request));
      request.setAttribute(SCOPE_ATTRIBUTE, scope);
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
    }
  }
}
