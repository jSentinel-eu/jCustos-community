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
package eu.jsentinel.jcustos.demo.app.security.services;

import eu.jsentinel.jcustos.session.InMemorySessionStore;
import eu.jsentinel.jcustos.session.SessionStore;

/**
 * Lazy singleton holder for the demo's {@link SessionStore}. Used by
 * {@code MyLoginView.checkCredentials} to record a {@code SessionRecord}
 * after a successful login and by {@code AdminSessionsView} to render
 * the inventory through the framework's
 * {@link eu.jsentinel.jcustos.components.SessionManagementView}.
 * <p>
 * Demo-only — backs an {@link InMemorySessionStore} (records live for
 * the lifetime of the JVM and are never persisted). A production
 * deployment would wire a persistent {@code SessionStore} (e.g. the
 * Eclipse-Store reference implementation).
 * <p>
 * The records are kept under the reference of the session id, never
 * under the session cookie itself: {@code MyLoginView} records each
 * login under {@code SessionRef.of(id)} (JS-SEC-117). The library
 * matches live sessions by that reference, so no decorating store is
 * needed. {@code BootstrapServiceInitListener} registers this store for
 * the per-request revocation check (JS-SEC-131).
 */
public final class DemoSessionStoreProvider {

  private static final SessionStore INSTANCE = new InMemorySessionStore();

  private DemoSessionStoreProvider() {
  }

  /**
   * Returns the shared {@link SessionStore} for the demo.
   *
   * @return non-null shared instance
   */
  public static SessionStore sessionStore() {
    return INSTANCE;
  }
}
