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
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.authorization.api.CurrentSubject;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.components.SecuredVisibility;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionChangeListener;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer.EnforcementOutcome;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.ObservableJCustosVersionStore;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.HasElement;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.UIDetachedException;
import com.vaadin.flow.internal.CurrentInstance;
import com.vaadin.flow.router.RouteConfiguration;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.UIInitListener;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.VaadinSessionState;
import com.vaadin.flow.shared.Registration;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.WeakHashMap;

import static java.util.Objects.requireNonNull;

/**
 * Brings a change of a subject's security version to the open Vaadin UIs of that subject at
 * once, instead of at their next request (R8, JS-SEC-167, CWE-613).
 * <p>
 * {@link JCustosVersionEnforcerListener} refuses a session whose security version moved on,
 * on its next navigation, client message or download (JS-SEC-082, JS-SEC-155). Until then the
 * open page kept showing the controls of the withdrawn roles, and a page left open did not
 * notice the revocation at all. This bridge listens to an {@link ObservableJCustosVersionStore}
 * and acts on the open UIs of the subject whose version changed:
 * <ul>
 *   <li><strong>The session's own snapshot drifted</strong> - the subject the session was
 *       opened for: the session is ended as the per-request check ends it. The subject, the
 *       version snapshot and a bound token credential are dropped,
 *       {@link JCustosVersionEnforcer} audits {@code SessionStale} - with the class of the view
 *       the UI shows as its route, as the navigation check names it, never the URL with its
 *       route parameters - every UI of the session is
 *       sent to the reroute target - typically the login view - and the Vaadin session is
 *       closed, the HTTP session invalidated and destroyed.</li>
 *   <li><strong>No drift</strong> - a session without a snapshot whose subject resolves to the
 *       key, or a session that logged in again after the change: its secured components are
 *       evaluated again through {@link SecuredVisibility#refreshAll(UI)}.</li>
 * </ul>
 * Each reaction runs in {@link UI#access} under the lock of the target session: at once when
 * that session is idle, otherwise as soon as its current request releases the lock. A UI that
 * cannot be reached - its push channel fails, say - is logged and skipped; the other UIs are
 * still handled, and its session is checked again on its next request (exit review RF23).
 * <p>
 * <strong>Push.</strong> With {@code @Push} the browser receives the redirect without a click.
 * Without push the session is ended on the server all the same; the browser learns of it with
 * its next request - Vaadin answers with the session-expired message and the client reloads -
 * which is when the per-request check would have refused it anyway. The core has no push
 * dependency; only this adapter uses Vaadin's push channel.
 * <p>
 * <strong>Which UIs.</strong> The bridge remembers the subject key of every UI of the service
 * when the UI is created and after every navigation, from the session's version snapshot or,
 * without one, from the current subject and the registered {@link SubjectIdResolver}. A login
 * that does not navigate afterwards is picked up at the next navigation; until then the
 * per-request check covers the session. The key is a pre-selection only: the decision is taken
 * under the session lock, from the session's state at that moment.
 * <p>
 * <strong>Node-local.</strong> The bridge hears of the changes made through the observable
 * store of this JVM. Sessions on other nodes are refused by the per-request check on their next
 * request; see {@link ObservableJCustosVersionStore}.
 * <p>
 * <strong>Registration.</strong> {@link #register(ServiceInitEvent, ObservableJCustosVersionStore)}
 * from a {@code VaadinServiceInitListener}, next to {@link JCustosVersionEnforcerListener} with
 * the same enforcer and reroute target; the starter's {@code VaadinJCustosStarter.serviceInit(...)}
 * does both when the registered version store is observable.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class VaadinJCustosVersionChangeBridge implements JCustosVersionChangeListener, HasLogger {

  /** URL of the root route; an empty URL would open a blank page instead. */
  private static final String ROOT_LOCATION = "./";

  private final JCustosVersionEnforcer enforcer;
  private final Class<? extends Component> rerouteTarget;

  /** The UIs of the service and the subject key each showed last; weak, so no UI is kept alive. */
  private final Map<UI, JCustosVersionKey> keys = Collections.synchronizedMap(new WeakHashMap<>());

  /**
   * @param enforcer      the enforcer that decides drift and audits {@code SessionStale} - the
   *                      one {@link JCustosVersionEnforcerListener} uses; non-null
   * @param rerouteTarget where an ended session's browser is sent; non-null. Typically the
   *                      application's {@code LoginView} subclass. A target that has no URL of
   *                      its own - route parameters, not registered - reloads the page instead
   */
  public VaadinJCustosVersionChangeBridge(JCustosVersionEnforcer enforcer,
                                          Class<? extends Component> rerouteTarget) {
    this.enforcer = requireNonNull(enforcer, "enforcer must not be null");
    this.rerouteTarget = requireNonNull(rerouteTarget, "rerouteTarget must not be null");
  }

  /**
   * Subscribes the bridge to {@code store} and tracks every UI the service creates from now on.
   * The subscription ends when the service is destroyed, so a store that outlives the service
   * - it is usually process-wide - does not keep the bridge.
   *
   * @param event the service-init event of the application's {@code VaadinServiceInitListener}
   * @param store the store whose changes the bridge acts on; the instance every version change
   *              of the application goes through
   * @return removes the subscription and the UI tracking
   */
  public Registration register(ServiceInitEvent event, ObservableJCustosVersionStore store) {
    requireNonNull(event, "event must not be null");
    requireNonNull(store, "store must not be null");
    store.addListener(this);
    Registration uiInit = event.getSource().addUIInitListener((UIInitListener) init -> track(init.getUI()));
    Registration destroy = event.getSource().addServiceDestroyListener(destroyed -> store.removeListener(this));
    return () -> {
      store.removeListener(this);
      uiInit.remove();
      destroy.remove();
      keys.clear();
    };
  }

  /**
   * Starts tracking {@code ui}: its subject key now and after every navigation, until it is
   * detached. {@link #register} does this for every new UI; call it for a UI that existed
   * before. Needs the session lock of {@code ui}.
   *
   * @param ui the UI; non-null
   */
  public void track(UI ui) {
    requireNonNull(ui, "ui must not be null");
    remember(ui);
    Registration navigation = ui.addAfterNavigationListener(after -> remember(ui));
    ui.addDetachListener(detach -> {
      navigation.remove();
      keys.remove(ui);
    });
  }

  @Override
  public void onChange(JCustosVersionKey key, JCustosVersion version) {
    requireNonNull(key, "key must not be null");
    List<UI> affected = new ArrayList<>();
    synchronized (keys) {
      keys.forEach((ui, uiKey) -> {
        if (key.equals(uiKey)) {
          affected.add(ui);
        }
      });
    }
    for (UI ui : affected) {
      try {
        ui.access(() -> react(ui, key));
      } catch (UIDetachedException detached) {
        keys.remove(ui);
      } catch (RuntimeException accessFailure) {
        // RF23: one UI that cannot be reached - a failing push, for instance - must not keep
        // the others from being handled; the per-request check still covers its session
        logger().warn("Reaching a UI after a security-version change failed with {}; its session "
            + "is checked again on its next request", accessFailure.getClass().getName());
      }
    }
  }

  /** Runs under the lock of the UI's session, with the UI and its session current. */
  private void react(UI ui, JCustosVersionKey key) {
    VaadinSession session = ui.getSession();
    if (session == null || session.getState() != VaadinSessionState.OPEN) {
      return;
    }
    try {
      Optional<VaadinJCustosVersionContext.Snapshot> snapshot = VaadinJCustosVersionContext.current(session);
      if (snapshot.isPresent() && key.equals(keyOf(snapshot.get()))) {
        VaadinJCustosVersionContext.Snapshot recorded = snapshot.get();
        EnforcementOutcome outcome = enforcer.enforce(
            recorded.subjectId(),
            recorded.tenant(),
            recorded.snapshot(),
            // JS-SEC-117: the SessionStale event carries the reference, never the id
            SessionRef.ofNullable(recorded.sessionId()),
            routeOf(ui));
        if (outcome.isStale()) {
          endSession(session);
          return;
        }
      }
      if (keyOf(session).filter(key::equals).isPresent()) {
        SecuredVisibility.refreshAll(ui);
      }
      remember(ui);
    } catch (RuntimeException reactionFailure) {
      // the per-request check still refuses the session on its next request
      logger().warn("Reacting to a security-version change failed with {}; the session is checked "
          + "again on its next request", reactionFailure.getClass().getName());
    }
  }

  /**
   * JS-SEC-167 (CWE-613): ends the drifted session the way the per-request check ends it, and
   * sends each of its UIs to the reroute target - over push before the session is closed, so
   * the redirect still reaches the browser.
   */
  private void endSession(VaadinSession session) {
    SessionTermination.clearIdentity(session);
    String location = locationOfRerouteTarget();
    for (UI each : new ArrayList<>(session.getUIs())) {
      redirect(each, location);
      keys.remove(each);
    }
    SessionTermination.closeInvalidateAndDestroy(session);
  }

  private void redirect(UI ui, String location) {
    Map<Class<?>, CurrentInstance> previous = CurrentInstance.setCurrent(ui);
    try {
      if (location == null) {
        ui.getPage().reload();
      } else {
        ui.getPage().setLocation(location);
      }
      if (ui.getPushConfiguration().getPushMode().isEnabled()) {
        ui.push();
      }
    } catch (RuntimeException redirectFailure) {
      // the session is closed regardless; the browser learns of it with its next request
      logger().warn("The redirect of an ended session could not be sent ({})",
          redirectFailure.getClass().getName());
    } finally {
      CurrentInstance.restoreInstances(previous);
    }
  }

  /** @return the URL of the reroute target relative to the application root, or {@code null} */
  private String locationOfRerouteTarget() {
    try {
      String url = RouteConfiguration.forSessionScope().getUrl(rerouteTarget);
      return url.isEmpty() ? ROOT_LOCATION : url;
    } catch (RuntimeException noUrlOfItsOwn) {
      return null;
    }
  }

  /** Records the subject key the UI's session shows now; needs the session lock. */
  private void remember(UI ui) {
    VaadinSession session = ui.getSession();
    Optional<JCustosVersionKey> key = session == null ? Optional.empty() : keyOf(session);
    if (key.isEmpty()) {
      keys.remove(ui);
    } else {
      keys.put(ui, key.get());
    }
  }

  /**
   * The snapshot's key; without a snapshot the current subject's key.
   *
   * @return the key, or empty when there is no subject, no resolver, or the resolver fails
   */
  private static Optional<JCustosVersionKey> keyOf(VaadinSession session) {
    Optional<VaadinJCustosVersionContext.Snapshot> snapshot = VaadinJCustosVersionContext.current(session);
    if (snapshot.isPresent()) {
      return Optional.of(keyOf(snapshot.get()));
    }
    try {
      Optional<Object> subject = CurrentSubject.current();
      Optional<SubjectIdResolver<Object>> resolver = JCustosServiceResolver.findSubjectIdResolver();
      if (subject.isEmpty() || resolver.isEmpty()) {
        return Optional.empty();
      }
      return Optional.of(new JCustosVersionKey(resolver.get().tenantFor(subject.get()),
          resolver.get().resolve(subject.get())));
    } catch (RuntimeException unresolvable) {
      return Optional.empty();
    }
  }

  private static JCustosVersionKey keyOf(VaadinJCustosVersionContext.Snapshot snapshot) {
    return new JCustosVersionKey(snapshot.tenant(), snapshot.subjectId());
  }

  /**
   * RF16 (CWE-532, CWE-1041): the class of the view the UI shows - what
   * {@link JCustosVersionEnforcerListener} audits for a navigation - not the URL path, which
   * carries route parameter values ({@code customer/4711}, {@code search/<free text>}) into
   * the hash-chained audit trail.
   *
   * @return the binary name of the active route target, or {@code null} when there is none
   */
  private static String routeOf(UI ui) {
    try {
      List<HasElement> chain = ui.getInternals().getActiveRouterTargetsChain();
      return chain.isEmpty() ? null : chain.getFirst().getClass().getName();
    } catch (RuntimeException unavailable) {
      return null;
    }
  }
}
