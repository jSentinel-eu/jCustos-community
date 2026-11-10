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

import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import com.vaadin.flow.router.HasErrorParameter;
import com.vaadin.flow.router.RouteBaseData;
import com.vaadin.flow.router.RouteData;
import com.vaadin.flow.router.RouterLayout;
import com.vaadin.flow.router.internal.RouteUtil;
import com.vaadin.flow.server.RouteRegistry;

import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * Resolves the restrictions that apply to one Vaadin navigation - the single decision
 * {@link AuthorizationListener} enforces at run time and the start-up discovery reports
 * (JS-SEC-154, CWE-862). Both ask this class, so the start-up check and the run-time
 * check cannot disagree about whether a route is protected.
 * <p>
 * A navigation is subject to the restriction of its navigation target <em>and</em> to the
 * restriction of every {@link RouterLayout} in its layout chain. All of them must grant
 * (AND). The scan of each class follows the rules of {@link JCustosAnnotationScanner}:
 * superclasses, interfaces and composed annotations are honoured, and more than one
 * restriction on the same class raises {@link IllegalStateException}.
 * <p>
 * <strong>{@code @PublicRoute} does not lift a layout restriction.</strong>
 * {@link PublicRoute} is the opt-out from deny-by-default for a navigation target that
 * carries no restriction at all. It never removes a restriction - neither one on the
 * target itself nor one declared on a layout the target is rendered in. A view that must
 * stay public has to live outside the restricted layout.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class RouteRestrictionResolver {

  /**
   * One restriction that applies to a navigation.
   *
   * @param source         the navigation target or layout class the restriction was found for
   * @param annotation     the restriction annotation instance
   * @param evaluatorClass the evaluator class declared for the annotation
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public record Restriction(Class<?> source, Annotation annotation, Class<?> evaluatorClass) {

    /** Validates the components. */
    public Restriction {
      requireNonNull(source, "source must not be null");
      requireNonNull(annotation, "annotation must not be null");
      requireNonNull(evaluatorClass, "evaluatorClass must not be null");
    }
  }

  private final JCustosAnnotationScanner scanner;

  /** Creates a resolver with its own scanner cache. */
  public RouteRestrictionResolver() {
    this(new JCustosAnnotationScanner());
  }

  /**
   * Creates a resolver that shares the given scanner and its cache.
   *
   * @param scanner the scanner to delegate to; non-null
   */
  public RouteRestrictionResolver(JCustosAnnotationScanner scanner) {
    this.scanner = requireNonNull(scanner, "scanner must not be null");
  }

  /**
   * Resolves every restriction that applies to a navigation to {@code navigationTarget}
   * rendered inside {@code layouts}.
   *
   * @param navigationTarget the navigation target class; non-null
   * @param layouts          the layout chain as Vaadin reports it
   *                         ({@code BeforeEnterEvent.getLayouts()}), starting with the layout
   *                         that immediately wraps the target; {@code null} counts as empty
   * @return the restrictions in evaluation order - outermost layout first, the navigation
   *         target last; empty when neither the target nor a layout carries a restriction
   * @throws IllegalStateException if the target or a layout carries more than one restriction
   */
  public List<Restriction> resolve(Class<?> navigationTarget, List<? extends Class<?>> layouts) {
    requireNonNull(navigationTarget, "navigationTarget must not be null");
    List<Restriction> restrictions = new ArrayList<>();
    if (layouts != null) {
      for (int i = layouts.size() - 1; i >= 0; i--) {
        addRestrictionOf(layouts.get(i), restrictions);
      }
    }
    addRestrictionOf(navigationTarget, restrictions);
    return List.copyOf(restrictions);
  }

  private void addRestrictionOf(Class<?> type, List<Restriction> restrictions) {
    if (type == null) {
      return;
    }
    scanner.scan(type).ifPresent(pair ->
        restrictions.add(new Restriction(type, pair.annotation(), pair.evaluatorClass())));
  }

  /**
   * Tells whether a navigation is open by omission: no restriction applies to it, the
   * target is not marked {@link PublicRoute} and it is not exempt. These are exactly the
   * navigations deny-by-default (JS-SEC-024) denies, and the routes the start-up
   * diagnostic {@code deny-by-default/unannotated-route} lists.
   *
   * @param navigationTarget the navigation target class; non-null
   * @param layouts          the layout chain, see {@link #resolve(Class, List)}
   * @return {@code true} when the navigation is neither restricted, nor declared public,
   *         nor exempt
   * @throws IllegalStateException if the target or a layout carries more than one restriction
   */
  public boolean isOpenByOmission(Class<?> navigationTarget, List<? extends Class<?>> layouts) {
    requireNonNull(navigationTarget, "navigationTarget must not be null");
    return !navigationTarget.isAnnotationPresent(PublicRoute.class)
        && !isDenyByDefaultExempt(navigationTarget)
        && resolve(navigationTarget, layouts).isEmpty();
  }

  /**
   * Deny-by-default must not deny the navigation targets the framework itself reroutes
   * to: error views ({@link HasErrorParameter}) are the target of a denial, and Vaadin's
   * built-in ones cannot be annotated by the integrator. A restriction that applies to an
   * error view - its own or one of a layout it is rendered in - is still enforced.
   *
   * @param navigationTarget the navigation target class; non-null
   * @return {@code true} for error views
   */
  public static boolean isDenyByDefaultExempt(Class<?> navigationTarget) {
    return HasErrorParameter.class.isAssignableFrom(navigationTarget);
  }

  /**
   * Lists the layout chain of every path a registered route is reachable under - its
   * route template and each alias - the way Vaadin determines it at navigation time,
   * including an automatic {@code @Layout}. An alias may declare another layout than the
   * route, so a route class can be protected under one path and open under another; a
   * start-up check therefore has to look at each chain.
   *
   * @param registry the registry the route comes from; non-null
   * @param route    the registered route; non-null
   * @return one layout chain per path, each starting with the layout that immediately
   *         wraps the target; never empty
   */
  public static List<List<Class<? extends RouterLayout>>> layoutChains(RouteRegistry registry,
                                                                       RouteData route) {
    requireNonNull(registry, "registry must not be null");
    requireNonNull(route, "route must not be null");
    List<List<Class<? extends RouterLayout>>> chains = new ArrayList<>();
    chains.add(layoutChain(registry, route));
    for (RouteBaseData<?> alias : route.getRouteAliases()) {
      chains.add(layoutChain(registry, alias));
    }
    return List.copyOf(chains);
  }

  private static List<Class<? extends RouterLayout>> layoutChain(RouteRegistry registry,
                                                                 RouteBaseData<?> path) {
    List<Class<? extends RouterLayout>> declared = path.getParentLayouts();
    String template = path.getTemplate();
    // Mirrors AbstractNavigationStateRenderer.getTargetParentLayouts: a route without an
    // explicit layout is rendered inside the automatic @Layout registered for its path.
    if ((declared == null || declared.isEmpty())
        && RouteUtil.isAutolayoutEnabled(path.getNavigationTarget(), template)
        && registry.hasLayout(template)) {
      return List.copyOf(RouteUtil.collectRouteParentLayouts(registry.getLayout(template)));
    }
    return declared == null ? List.of() : List.copyOf(declared);
  }
}
