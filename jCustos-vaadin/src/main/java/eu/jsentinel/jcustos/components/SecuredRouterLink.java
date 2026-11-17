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
package eu.jsentinel.jcustos.components;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import com.vaadin.flow.component.AttachEvent;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.router.Router;
import com.vaadin.flow.router.RouterLink;

import java.util.Optional;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

/**
 * {@link RouterLink} subclass that hides or disables itself when the
 * current subject does not satisfy the supplied
 * {@link SecuredVisibility.Requirement}. Defaults to
 * {@link SecuredVisibilityMode#HIDE} — navigation affordances that
 * the user can't follow should disappear, not linger as dead links.
 *
 * <p>The check runs on construction, on every attach, on {@link #refresh()} and, for every
 * link of a UI at once, from
 * {@link SecuredVisibility#refreshAll(com.vaadin.flow.component.UI)} (R8, JS-SEC-167).
 *
 * <p>Authoritative protection of the target route stays with the
 * {@code AuthorizationListener} pipeline. This component is a UI
 * affordance — a hidden link is not a security boundary.
 */
@ExperimentalJCustosApi
public class SecuredRouterLink extends RouterLink {

  private final SecuredVisibility.Requirement requirement;
  private final SecuredVisibilityMode mode;
  private final Supplier<Optional<SecuredVisibility.JCustosView>> viewSupplier;

  /**
   * Builds a secured router link with {@link SecuredVisibilityMode#HIDE}
   * and SPI-backed view lookup.
   *
   * @param text             link label; non-null
   * @param navigationTarget Vaadin route target; non-null
   * @param requirement      what the link requires; non-null
   */
  public SecuredRouterLink(String text,
                           Class<? extends Component> navigationTarget,
                           SecuredVisibility.Requirement requirement) {
    this(text, navigationTarget, requirement, SecuredVisibilityMode.HIDE,
        SecuredVisibility::currentJCustosView);
  }

  /**
   * Builds a secured router link with a custom mode and SPI-backed
   * view lookup.
   *
   * @param text             non-null
   * @param navigationTarget non-null
   * @param requirement      non-null
   * @param mode             non-null
   */
  public SecuredRouterLink(String text,
                           Class<? extends Component> navigationTarget,
                           SecuredVisibility.Requirement requirement,
                           SecuredVisibilityMode mode) {
    this(text, navigationTarget, requirement, mode,
        SecuredVisibility::currentJCustosView);
  }

  /**
   * Full constructor.
   *
   * @param text             non-null
   * @param navigationTarget non-null
   * @param requirement      non-null
   * @param mode             non-null
   * @param viewSupplier     non-null
   */
  public SecuredRouterLink(String text,
                           Class<? extends Component> navigationTarget,
                           SecuredVisibility.Requirement requirement,
                           SecuredVisibilityMode mode,
                           Supplier<Optional<SecuredVisibility.JCustosView>> viewSupplier) {
    super(
        requireNonNull(text, "text must not be null"),
        requireNonNull(navigationTarget, "navigationTarget must not be null"));
    this.requirement = requireNonNull(requirement, "requirement must not be null");
    this.mode = requireNonNull(mode, "mode must not be null");
    this.viewSupplier = requireNonNull(viewSupplier, "viewSupplier must not be null");
    refresh();
    // R8 (JS-SEC-167): refreshAll(UI) re-evaluates the link when the subject's roles change
    SecuredBindingRegistry.register(this, this::refresh);
  }

  /**
   * Router-explicit constructor — for headless tests or routing
   * setups where the router isn't bound on
   * {@code VaadinService.getCurrent()}.
   *
   * @param router           explicit router; non-null
   * @param text             non-null
   * @param navigationTarget non-null
   * @param requirement      non-null
   * @param mode             non-null
   * @param viewSupplier     non-null
   */
  public SecuredRouterLink(Router router,
                           String text,
                           Class<? extends Component> navigationTarget,
                           SecuredVisibility.Requirement requirement,
                           SecuredVisibilityMode mode,
                           Supplier<Optional<SecuredVisibility.JCustosView>> viewSupplier) {
    super(
        requireNonNull(router, "router must not be null"),
        requireNonNull(text, "text must not be null"),
        requireNonNull(navigationTarget, "navigationTarget must not be null"));
    this.requirement = requireNonNull(requirement, "requirement must not be null");
    this.mode = requireNonNull(mode, "mode must not be null");
    this.viewSupplier = requireNonNull(viewSupplier, "viewSupplier must not be null");
    refresh();
    // R8 (JS-SEC-167): refreshAll(UI) re-evaluates the link when the subject's roles change
    SecuredBindingRegistry.register(this, this::refresh);
  }

  @Override
  protected void onAttach(AttachEvent attachEvent) {
    super.onAttach(attachEvent);
    refresh();
  }

  /** Re-runs the visibility check against the current subject. */
  public final void refresh() {
    SecuredVisibility.apply(new ComponentTarget(this), requirement, mode, viewSupplier);
  }

  /** @return the requirement this link was constructed with */
  public final SecuredVisibility.Requirement requirement() {
    return requirement;
  }

  /** @return the visibility mode this link uses on denial */
  public final SecuredVisibilityMode mode() {
    return mode;
  }
}
