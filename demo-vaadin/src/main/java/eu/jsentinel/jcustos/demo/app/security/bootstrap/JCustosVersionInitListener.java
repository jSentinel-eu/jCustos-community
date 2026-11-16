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
package eu.jsentinel.jcustos.demo.app.security.bootstrap;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.demo.app.views.MyLoginView;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer;
import eu.jsentinel.jcustos.session.JCustosVersionStore;
import eu.jsentinel.jcustos.session.vaadin.JCustosVersionEnforcerListener;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.VaadinServiceInitListener;

import java.util.Optional;

/**
 * Registers the framework's {@link JCustosVersionEnforcerListener}
 * with {@link JCustosVersionEnforcerListener#register(ServiceInitEvent)}
 * so drifted sessions reroute to {@link MyLoginView} - on navigation,
 * on every UIDL request and on push messages.
 * <p>
 * The listener only fires when the {@code LoginView} captured a
 * {@code JCustosVersion} snapshot at login time — which itself
 * requires both an SPI-registered {@link JCustosVersionStore} and
 * a {@code SubjectIdResolver}. This demo registers
 * {@link eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore}
 * and {@link eu.jsentinel.jcustos.demo.app.security.services.DemoSubjectIdResolver}
 * via {@code META-INF/services} so the loop is closed end-to-end.
 * <p>
 * Without an SPI-registered store this initialiser logs a warning
 * and skips registration — the demo still runs, but with drift
 * detection silently disabled.
 */
public class JCustosVersionInitListener
    implements VaadinServiceInitListener, HasLogger {

  /** Creates a new instance. */
  public JCustosVersionInitListener() {
  }

  @Override
  public void serviceInit(ServiceInitEvent event) {
    Optional<JCustosVersionStore> storeOpt =
        JCustosServiceResolver.findJCustosVersionStore();
    if (storeOpt.isEmpty()) {
      logger().warn("JCustosVersionStore SPI not registered — "
          + "Phase 4c drift detection disabled in demo-vaadin");
      return;
    }
    JCustosVersionEnforcer enforcer = new JCustosVersionEnforcer(
        storeOpt.get(), JCustosServiceResolver.securityAuditService());
    JCustosVersionEnforcerListener listener =
        new JCustosVersionEnforcerListener(enforcer, MyLoginView.class);
    // JS-SEC-082 / JS-SEC-155: register(...) wires all three entry points - the
    // navigation listener on every UI, the request handler for UIDL requests and the
    // request interceptor for messages that arrive over a WebSocket-only push channel.
    // A handler and a navigation listener registered by hand missed the push messages.
    listener.register(event);
  }
}
