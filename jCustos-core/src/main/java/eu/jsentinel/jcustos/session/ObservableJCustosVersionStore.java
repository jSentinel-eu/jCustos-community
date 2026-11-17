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
package eu.jsentinel.jcustos.session;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static java.util.Objects.requireNonNull;

/**
 * A {@link JCustosVersionStore} that reports every change to its
 * {@link JCustosVersionChangeListener}s (R8, JS-SEC-167, CWE-613).
 * <p>
 * The security-version check refuses a session whose subject's version moved on - but only
 * when that session sends its next request (JS-SEC-082, JS-SEC-155). An open page of a user
 * whose roles were just withdrawn keeps showing the controls of the old roles until then.
 * This decorator closes the gap between the change and the next request: it stores through the
 * wrapped store and then notifies its listeners, so an adapter can end the open sessions of the
 * subject at once - in Vaadin with {@code @Push}, through {@code VaadinJCustosVersionChangeBridge}.
 * <ul>
 *   <li>{@link #increment(JCustosVersionKey)} notifies with the version it returns,
 *       {@link #reset(JCustosVersionKey)} with {@link JCustosVersion#INITIAL}. The listeners run
 *       on the calling thread after the wrapped store returned; a change the wrapped store
 *       refuses with an exception is not reported.</li>
 *   <li>A listener that throws is logged with its class and the class of the exception and
 *       skipped; the change stands, the caller receives the result, and the remaining
 *       listeners are still notified. A misbehaving adapter cannot undo or hide a revocation.</li>
 *   <li>{@link #current(JCustosVersionKey)} reads through and notifies nothing.</li>
 * </ul>
 * <p>
 * <strong>Node-local.</strong> The listeners hear of the changes made through <em>this</em>
 * instance, in this JVM. When several nodes share one backing store - a database, a
 * replicated cache - a change made on one node is reported on that node only; the sessions on
 * the other nodes are refused by the per-request check on their next request, as without this
 * decorator. A cluster that needs the proactive reaction everywhere publishes the change to its
 * nodes itself (a message bus, a cache event) and calls its listeners there.
 * <p>
 * The decorator is opt-in: register it instead of the plain store - through
 * {@code .sessions(s -> s.securityVersion(new ObservableJCustosVersionStore(store)))} or
 * {@code JCustosServiceResolver.setJCustosVersionStore(...)} - and make every code path that
 * changes a version use the registered instance. A change made directly on the wrapped store
 * is stored but not reported.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class ObservableJCustosVersionStore implements JCustosVersionStore, HasLogger {

  private final JCustosVersionStore delegate;
  private final List<JCustosVersionChangeListener> listeners = new CopyOnWriteArrayList<>();

  /**
   * @param delegate the store that keeps the versions; non-null
   */
  public ObservableJCustosVersionStore(JCustosVersionStore delegate) {
    this.delegate = requireNonNull(delegate, "delegate must not be null");
  }

  /** @return the store this decorator writes through */
  public JCustosVersionStore delegate() {
    return delegate;
  }

  /**
   * Registers a listener. Registering the same instance twice keeps one registration.
   *
   * @param listener the listener; non-null
   */
  public void addListener(JCustosVersionChangeListener listener) {
    requireNonNull(listener, "listener must not be null");
    if (!listeners.contains(listener)) {
      listeners.add(listener);
    }
  }

  /**
   * Removes a listener; unknown or {@code null} listeners are ignored.
   *
   * @param listener the listener to remove
   */
  public void removeListener(JCustosVersionChangeListener listener) {
    listeners.remove(listener);
  }

  /** @return the number of registered listeners */
  public int listenerCount() {
    return listeners.size();
  }

  @Override
  public JCustosVersion current(JCustosVersionKey key) {
    requireNonNull(key, "key must not be null");
    return delegate.current(key);
  }

  @Override
  public JCustosVersion increment(JCustosVersionKey key) {
    requireNonNull(key, "key must not be null");
    JCustosVersion next = delegate.increment(key);
    notifyListeners(key, next);
    return next;
  }

  @Override
  public void reset(JCustosVersionKey key) {
    requireNonNull(key, "key must not be null");
    delegate.reset(key);
    notifyListeners(key, JCustosVersion.INITIAL);
  }

  private void notifyListeners(JCustosVersionKey key, JCustosVersion version) {
    for (JCustosVersionChangeListener listener : listeners) {
      try {
        listener.onChange(key, version);
      } catch (RuntimeException listenerFailure) {
        // R8 (CWE-613): the change is stored - a listener must not turn it into a failure of
        // the caller, nor keep the remaining listeners from hearing of it. The exception's
        // message is not logged: it may carry whatever the listener had at hand.
        logger().warn("JCustosVersionChangeListener {} failed with {}; the version change stands",
            listener.getClass().getName(), listenerFailure.getClass().getName());
      }
    }
  }
}
