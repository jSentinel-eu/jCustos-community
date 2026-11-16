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
package eu.jsentinel.jcustos.demo.restclient;

import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.impl.RouteRestrictionResolver;
import eu.jsentinel.jcustos.demo.restclient.views.MyLoginView;
import eu.jsentinel.jcustos.demo.restclient.views.SetupView;
import eu.jsentinel.jcustos.demo.restclient.views.standalone.StepUpChallengeView;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.router.Route;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-137 (CWE-1188) and JS-SEC-152: the demo boots with deny-by-default, so every
 * route must be restricted or declared {@code @PublicRoute}. The login, setup and step-up
 * views are public - a denial reroutes there - and none of them lives in a layout.
 */
@DisplayName("JS-SEC-137 — every route is restricted or @PublicRoute under deny-by-default")
class PublicRouteCoverageTest {

  @Test
  @DisplayName("no route of the demo is open by omission")
  void noRouteIsOpenByOmission() throws IOException {
    RouteRestrictionResolver resolver = new RouteRestrictionResolver();
    List<Class<?>> routes = routeClasses();
    assertFalse(routes.isEmpty(), "the demo's routes must be found");
    assertEquals(List.of(), routes.stream()
        .filter(route -> resolver.isOpenByOmission(route, layouts(route)))
        .map(Class::getSimpleName)
        .toList());
  }

  @Test
  @DisplayName("the login, setup and step-up views are public and outside any layout")
  void rerouteTargetsArePublic() {
    for (Class<?> target : List.of(MyLoginView.class, SetupView.class, StepUpChallengeView.class)) {
      assertTrue(target.isAnnotationPresent(PublicRoute.class), target.getSimpleName());
      assertEquals(UI.class, target.getAnnotation(Route.class).layout(), target.getSimpleName());
    }
  }

  private static List<Class<?>> layouts(Class<?> route) {
    Class<?> layout = route.getAnnotation(Route.class).layout();
    return layout == UI.class ? List.<Class<?>>of() : List.<Class<?>>of(layout);
  }

  /** Every {@code @Route} class compiled from {@code src/main/java}. */
  private static List<Class<?>> routeClasses() throws IOException {
    Path classes = Path.of("target/classes");
    try (Stream<Path> files = Files.walk(classes)) {
      return files
          .filter(f -> f.toString().endsWith(".class") && !f.getFileName().toString().contains("$"))
          .map(f -> classes.relativize(f).toString().replace('/', '.').replace(".class", ""))
          .filter(name -> name.startsWith("eu.jsentinel.jcustos.demo.restclient"))
          .map(PublicRouteCoverageTest::load)
          .<Class<?>>map(type -> type)
          .filter(type -> type.isAnnotationPresent(Route.class))
          .toList();
    }
  }

  private static Class<?> load(String name) {
    try {
      return Class.forName(name, false, PublicRouteCoverageTest.class.getClassLoader());
    } catch (ClassNotFoundException e) {
      throw new AssertionError(e);
    }
  }
}
