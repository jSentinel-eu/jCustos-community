/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.dx.vaadin.routes;

import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.Route;

/**
 * Stand-in for the application's login view: the default login route name
 * {@code login} must exist for the unauthenticated reroute to land somewhere
 * observable in a browserless test.
 */
@Route("login")
public class LoginRouteFixture extends Div {
}
