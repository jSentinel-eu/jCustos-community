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
package eu.jsentinel.jcustos.demo.app.views;

import eu.jsentinel.jcustos.demo.app.views.components.PermissionDemoCard;
import eu.jsentinel.jcustos.demo.app.views.components.ViewNavigationCard;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;

@PublicRoute
@Route(PublicView.NAV)
public class PublicView extends Composite<Div> {

  public static final String NAV = "public";

  public PublicView() {
    Span badge = new Span("PUBLIC");
    badge.getElement().getThemeList().add("badge");

    H1 heading = new H1("Public standalone view");

    Paragraph description = new Paragraph(
        "Standalone route without @VisibleFor — everyone (including "
            + "unauthenticated visitors) may reach it. The permission demo "
            + "below still reads the current subject's permissions, so an "
            + "anonymous visitor sees nothing in pattern A and red errors "
            + "for every button in pattern B.");

    Button back = new Button("Back to home", VaadinIcon.HOME.create(),
        e -> UI.getCurrent().navigate(MainView.class));
    back.addThemeVariants(ButtonVariant.LUMO_TERTIARY);

    VerticalLayout layout = new VerticalLayout(
        new HorizontalLayout(badge, heading),
        description,
        new PermissionDemoCard(),
        new ViewNavigationCard(),
        back);
    layout.setSpacing(false);
    layout.getThemeList().add("spacing-s");
    layout.addClassNames("workspace", "workspace-public");

    getContent().add(layout);
  }
}
