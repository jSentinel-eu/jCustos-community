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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

/**
 * Callback of an {@link ObservableJCustosVersionStore}: the security version of a subject has
 * changed (R8, JS-SEC-167, CWE-613).
 * <p>
 * Until 00.84.00 a version change was only noticed when the subject's session sent its next
 * request; nothing could react in between. An adapter registers a listener to act on the open
 * sessions of the subject at once - the Vaadin adapter's
 * {@code VaadinJCustosVersionChangeBridge} ends them and refreshes their secured components.
 * <p>
 * <strong>Contract.</strong> The store calls the listener on the thread that changed the
 * version, after the change is stored, once per change. A listener must return quickly and
 * must not call back into the store for the same key; work that takes time belongs on another
 * thread or, in Vaadin, in {@code UI.access(...)}. An exception it throws is logged by the
 * store and never reaches the caller of {@code increment} or {@code reset}. Changes of the
 * same key that run concurrently may be reported in either order; compare
 * {@code version} with {@link JCustosVersionStore#current(JCustosVersionKey)} when the order
 * matters.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
@FunctionalInterface
public interface JCustosVersionChangeListener {

  /**
   * Reports a stored change.
   *
   * @param key     tenant and subject whose version changed; never {@code null}
   * @param version the version after the change - the value {@code increment} returned, or
   *                {@link JCustosVersion#INITIAL} after a {@code reset}; never {@code null}
   */
  void onChange(JCustosVersionKey key, JCustosVersion version);
}
