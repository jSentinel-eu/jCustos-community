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
package eu.jsentinel.jcustos.authorization.impl;

import eu.jsentinel.jcustos.components.SessionManagementView;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.InternalServerError;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * RF (exit-review): deny-by-default must not deny the targets the framework itself
 * reroutes to (error views) or ships un-annotated (SessionManagementView), because the
 * consumer cannot annotate them. Pins {@link AuthorizationListener#isDenyByDefaultExempt}.
 *
 * <p>Uses Vaadin's built-in {@link InternalServerError} (a {@code HasErrorParameter}) rather
 * than a bespoke error-view fixture, so no new error-handler type is added to the browserless
 * classpath scan of the sibling navigation tests.
 */
@DisplayName("Deny-by-default exemptions (RF)")
class DenyByDefaultExemptionTest {

  @Test
  @DisplayName("A Vaadin error view (HasErrorParameter) is exempt")
  void errorViewExempt() {
    assertTrue(AuthorizationListener.isDenyByDefaultExempt(InternalServerError.class),
        "error views are the reroute target of a denial and must not themselves be denied");
  }

  @Test
  @DisplayName("The framework's SessionManagementView is no longer exempt (JS-SEC-068)")
  void sessionManagementViewNotExempt() {
    assertFalse(AuthorizationListener.isDenyByDefaultExempt(SessionManagementView.class),
        "JS-SEC-068 (CWE-306): the shipped route carries @ProtectedBy and consumer subclasses "
            + "carry their own annotation, so nothing justifies an exemption any more");
  }

  @Test
  @DisplayName("A plain consumer route is NOT exempt (still denied)")
  void plainRouteNotExempt() {
    assertFalse(AuthorizationListener.isDenyByDefaultExempt(PlainViewFixture.class),
        "an ordinary un-annotated consumer route must still fail closed under deny-by-default");
  }

  static final class PlainViewFixture extends Composite<Div> {
  }
}
