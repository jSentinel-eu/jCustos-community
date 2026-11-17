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
import com.vaadin.flow.component.button.Button;

import java.util.Optional;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

/**
 * {@link Button} subclass that hides or disables itself when the
 * current subject does not satisfy the supplied
 * {@link SecuredVisibility.Requirement}. Defaults to
 * {@link SecuredVisibilityMode#DISABLE} — primary buttons should
 * stay visible so the absence of the affordance does not surprise
 * the user.
 *
 * <p>The visibility check runs:
 * <ul>
 *   <li>on first attach (so freshly-constructed buttons land in
 *       the correct state before the user sees them), and</li>
 *   <li>whenever the app calls {@link #refresh() refresh()} — the
 *       canonical hook after a permission change — and</li>
 *   <li>for every button of a UI at once, from
 *       {@link SecuredVisibility#refreshAll(com.vaadin.flow.component.UI)}: the button
 *       registers itself with the {@link SecuredBindingRegistry} of its UI (R8,
 *       JS-SEC-167).</li>
 * </ul>
 *
 * <p>This is a UI affordance only — the server-side handler
 * <strong>must</strong> still call {@code PermissionGuard.require*}
 * (or its annotation-driven equivalent) in the click listener.
 * A hidden button does not protect against a hand-crafted RPC.
 */
@ExperimentalJCustosApi
public class SecuredButton extends Button {

  private final SecuredVisibility.Requirement requirement;
  private final SecuredVisibilityMode mode;
  private final Supplier<Optional<SecuredVisibility.JCustosView>> viewSupplier;

  /**
   * Builds a secured button with the default
   * {@link SecuredVisibilityMode#DISABLE} mode and SPI-backed
   * security-view lookup.
   *
   * @param text        button label; non-null
   * @param requirement what the button requires; non-null
   */
  public SecuredButton(String text, SecuredVisibility.Requirement requirement) {
    this(text, requirement, SecuredVisibilityMode.DISABLE,
        SecuredVisibility::currentJCustosView);
  }

  /**
   * Builds a secured button with a custom mode and SPI-backed
   * security-view lookup.
   *
   * @param text        non-null button label
   * @param requirement non-null
   * @param mode        non-null
   */
  public SecuredButton(String text,
                       SecuredVisibility.Requirement requirement,
                       SecuredVisibilityMode mode) {
    this(text, requirement, mode, SecuredVisibility::currentJCustosView);
  }

  /**
   * Full constructor — useful in tests where the caller supplies
   * the security view directly rather than going through the SPI.
   *
   * @param text         non-null button label
   * @param requirement  non-null
   * @param mode         non-null
   * @param viewSupplier non-null
   */
  public SecuredButton(String text,
                       SecuredVisibility.Requirement requirement,
                       SecuredVisibilityMode mode,
                       Supplier<Optional<SecuredVisibility.JCustosView>> viewSupplier) {
    super(requireNonNull(text, "text must not be null"));
    this.requirement = requireNonNull(requirement, "requirement must not be null");
    this.mode = requireNonNull(mode, "mode must not be null");
    this.viewSupplier = requireNonNull(viewSupplier, "viewSupplier must not be null");
    refresh();
    // R8 (JS-SEC-167): refreshAll(UI) re-evaluates the button when the subject's roles change
    SecuredBindingRegistry.register(this, this::refresh);
  }

  @Override
  protected void onAttach(AttachEvent attachEvent) {
    super.onAttach(attachEvent);
    refresh();
  }

  /**
   * Re-runs the visibility check against the current subject.
   * Apps call this after a permission change to keep the button's
   * state in sync.
   */
  public final void refresh() {
    SecuredVisibility.apply(new ComponentTarget(this), requirement, mode, viewSupplier);
  }

  /** @return the requirement this button was constructed with */
  public final SecuredVisibility.Requirement requirement() {
    return requirement;
  }

  /** @return the visibility mode this button uses on denial */
  public final SecuredVisibilityMode mode() {
    return mode;
  }
}
