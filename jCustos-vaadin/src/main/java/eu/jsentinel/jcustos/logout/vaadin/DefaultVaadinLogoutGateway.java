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
package eu.jsentinel.jcustos.logout.vaadin;

import com.vaadin.flow.component.UI;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.WrappedSession;

/**
 * Default {@link VaadinLogoutGateway} backed by the static Vaadin APIs.
 * Calls become safe no-ops when there is no current UI / session, so the
 * gateway can be invoked from background threads without blowing up.
 */
public final class DefaultVaadinLogoutGateway implements VaadinLogoutGateway {

  @Override
  public void redirectTo(String routePath) {
    UI ui = UI.getCurrent();
    if (ui == null) return;
    // Browser-side redirect — survives subsequent session close/invalidation
    ui.getPage().setLocation(routePath);
  }

  @Override
  public void closeVaadinSession() {
    VaadinSession session = VaadinSession.getCurrent();
    if (session != null) session.close();
  }

  @Override
  public String currentSessionId() {
    VaadinSession vaadin = VaadinSession.getCurrent();
    if (vaadin == null) return null;
    WrappedSession wrapped = vaadin.getSession();
    return wrapped == null ? null : wrapped.getId();
  }

  @Override
  public void invalidateHttpSession() {
    VaadinSession vaadin = VaadinSession.getCurrent();
    if (vaadin == null) return;
    WrappedSession wrapped = vaadin.getSession();
    if (wrapped != null) wrapped.invalidate();
  }
}
