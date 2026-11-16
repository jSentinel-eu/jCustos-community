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
package eu.jsentinel.jcustos.demo.restclient.views.standalone;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;

/**
 * Landing route that the {@code AuthorizationListener} reroutes to
 * when a policy emits {@code StepUpRequired}. The route name matches
 * the default {@link JCustosServiceResolver#DEFAULT_STEP_UP_ROUTE_NAME}
 * — change it at startup via
 * {@code JCustosServiceResolver.setStepUpRouteName("custom-route")}
 * and register the matching view under that route.
 *
 * <p>The view itself is a placeholder: a real MFA / re-auth flow
 * would render a TOTP / WebAuthn challenge here and, on success,
 * mark the subject as step-up-completed so the next navigation to
 * the protected route lets the user through.
 *
 * <p>{@code @PublicRoute}: the bootstrap runs with deny-by-default, and the
 * challenge must stay reachable while the step-up is outstanding. The view
 * lives outside any restricted layout (JS-SEC-152, JS-SEC-154).
 */
@PublicRoute
@Route(StepUpChallengeView.NAV)
public class StepUpChallengeView extends Composite<Div> {

  /** Route name; matches {@link JCustosServiceResolver#DEFAULT_STEP_UP_ROUTE_NAME}. */
  public static final String NAV = "step-up";

  public StepUpChallengeView() {
    VerticalLayout layout = new VerticalLayout();
    layout.add(new H1("Step-up required"));
    layout.add(new Paragraph(
        "The route you navigated to is protected by a policy that "
            + "returned StepUpRequired. The AuthorizationListener "
            + "rerouted you here. A real application would prompt for "
            + "a TOTP code, a WebAuthn challenge, or password re-entry "
            + "and re-issue the navigation on success."));
    layout.add(new Paragraph(
        "This demo just shows the wiring — see "
            + "DemoPolicyInitListener.POLICY_SENSITIVE_REQUIRES_MFA "
            + "for the policy and StepUpDemoView for the protected "
            + "route that lands you here."));
    getContent().add(layout);
  }
}
