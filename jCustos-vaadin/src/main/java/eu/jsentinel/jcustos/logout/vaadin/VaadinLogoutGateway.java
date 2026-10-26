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

/**
 * Strategy for the Vaadin-side effects of a logout. Existed primarily so
 * {@code VaadinLogoutService} can be unit-tested without a live Vaadin
 * runtime — the default implementation calls the static Vaadin APIs.
 */
public interface VaadinLogoutGateway {

  /**
   * Tells the browser to navigate to the given path. Implementations
   * should use {@code Page.setLocation(...)} so the navigation survives
   * a subsequent {@link #closeVaadinSession()} or
   * {@link #invalidateHttpSession()} call.
   */
  void redirectTo(String routePath);

  /** Closes the current Vaadin session. */
  void closeVaadinSession();

  /** Invalidates the underlying servlet session. */
  void invalidateHttpSession();

  /**
   * The id of the HTTP session the current request belongs to, or {@code null}
   * when none is bound. Since 00.84.00 (JS-SEC-084) the logout service passes it
   * into {@code SessionPolicy.onLogout} so the logout audit correlates with the
   * login; the default keeps older gateways source-compatible.
   *
   * @return the wrapped session id, or {@code null}
   * @since 00.84.00
   */
  default String currentSessionId() {
    return null;
  }
}
