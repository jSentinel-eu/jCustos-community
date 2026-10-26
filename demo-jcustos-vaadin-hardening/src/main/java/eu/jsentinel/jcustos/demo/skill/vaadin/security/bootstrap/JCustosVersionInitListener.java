package eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer;
import eu.jsentinel.jcustos.session.JCustosVersionStore;
import eu.jsentinel.jcustos.session.vaadin.JCustosVersionEnforcerListener;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.UIInitListener;
import com.vaadin.flow.server.VaadinServiceInitListener;
import com.vaadin.flow.shared.Registration;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.MyLoginView;

import java.util.Optional;

/**
 * Registers {@link JCustosVersionEnforcerListener} on every UI so
 * drifted sessions reroute to {@link MyLoginView}.
 *
 * <p>The listener only fires when the {@code LoginView} captured a
 * {@link eu.jsentinel.jcustos.session.JCustosVersion} snapshot
 * at login time — which itself requires both an SPI-registered
 * {@link JCustosVersionStore} and a
 * {@link eu.jsentinel.jcustos.authorization.api.SubjectIdResolver}.
 * Both are registered alongside this listener by the hardening skill.
 *
 * <p>Without an SPI-registered store this initialiser logs a warning
 * and skips registration — the app still runs, but with drift
 * detection silently disabled.
 *
 * <p>Registered via
 * {@code META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener}.
 */
public class JCustosVersionInitListener
    implements VaadinServiceInitListener, HasLogger {

  @Override
  public void serviceInit(ServiceInitEvent event) {
    Optional<JCustosVersionStore> storeOpt =
        JCustosServiceResolver.findJCustosVersionStore();
    if (storeOpt.isEmpty()) {
      logger().warn("JCustosVersionStore SPI not registered — "
          + "Phase 4c drift detection disabled");
      return;
    }
    JCustosVersionEnforcer enforcer = new JCustosVersionEnforcer(
        storeOpt.get(), JCustosServiceResolver.securityAuditService());
    JCustosVersionEnforcerListener listener =
        new JCustosVersionEnforcerListener(enforcer, MyLoginView.class);
    // JS-SEC-082: drift is enforced on every UIDL request, not only on navigation.
    event.addRequestHandler(listener);
    event.getSource().addUIInitListener((UIInitListener) uiInitEvent -> {
      Registration reg = uiInitEvent.getUI().addBeforeEnterListener(listener);
      uiInitEvent.getUI().addDetachListener(detach -> reg.remove());
    });
  }
}
