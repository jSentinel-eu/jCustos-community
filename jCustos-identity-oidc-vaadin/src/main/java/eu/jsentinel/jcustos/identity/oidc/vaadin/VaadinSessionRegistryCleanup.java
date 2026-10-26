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
package eu.jsentinel.jcustos.identity.oidc.vaadin;

import com.vaadin.flow.server.SessionDestroyEvent;
import com.vaadin.flow.server.SessionDestroyListener;
import com.vaadin.flow.server.WrappedSession;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.oidc.api.SessionRegistry;

import java.util.Objects;

/**
 * Forgets an RP session in the {@link SessionRegistry} when Vaadin destroys
 * the session (JS-SEC-078, CWE-770). Register it once per service:
 * {@code service.addSessionDestroyListener(new VaadinSessionRegistryCleanup(registry))},
 * typically from a {@code VaadinServiceInitListener}. Without it, every
 * registered session stays in the registry until a logout for its subject or
 * sid arrives.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class VaadinSessionRegistryCleanup implements SessionDestroyListener {

  private static final long serialVersionUID = 1L;

  private final transient SessionRegistry registry;

  /**
   * @param registry the registry the application registers RP sessions in
   */
  public VaadinSessionRegistryCleanup(SessionRegistry registry) {
    this.registry = Objects.requireNonNull(registry, "registry");
  }

  @Override
  public void sessionDestroy(SessionDestroyEvent event) {
    if (registry == null || event.getSession() == null) {
      return;
    }
    WrappedSession wrapped = event.getSession().getSession();
    if (wrapped != null && wrapped.getId() != null) {
      registry.unregister(wrapped.getId());
    }
  }
}
