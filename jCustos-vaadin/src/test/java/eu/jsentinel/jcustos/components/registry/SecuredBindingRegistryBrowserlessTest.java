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
package eu.jsentinel.jcustos.components.registry;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.components.ComponentTarget;
import eu.jsentinel.jcustos.components.SecuredBindingRegistry;
import eu.jsentinel.jcustos.components.SecuredButton;
import eu.jsentinel.jcustos.components.SecuredMenuItem;
import eu.jsentinel.jcustos.components.SecuredRouterLink;
import eu.jsentinel.jcustos.components.SecuredVisibility;
import eu.jsentinel.jcustos.components.SecuredVisibility.Requirement;
import eu.jsentinel.jcustos.components.SecuredVisibilityMode;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.browserless.ViewPackages;
import com.vaadin.browserless.internal.MockVaadin;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.contextmenu.MenuItem;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.menubar.MenuBar;
import com.vaadin.flow.router.Route;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R8 (JS-SEC-167, CWE-613): {@link SecuredVisibility#refreshAll(UI)} evaluates every secured
 * binding of a UI again. Until 00.84.00 an open view kept the controls of the subject's old
 * roles until the next navigation. Real components, the real SPI lookup, the project's test
 * doubles for the services.
 */
@DisplayName("R8 - refreshAll(UI) re-evaluates every secured binding of a UI")
@ViewPackages
class SecuredBindingRegistryBrowserlessTest extends BrowserlessTest {

  private static final RoleName ADMIN = new RoleName("ADMIN");
  private static final PermissionName EXPORT = new PermissionName("doc:export");

  private final InMemorySubjectStore subjects = new InMemorySubjectStore();
  private final FakeAuthorizationService<String> authorization = new FakeAuthorizationService<>();

  @BeforeEach
  void wire() {
    JCustosServiceResolver.resetAll();
    SubjectStores.setSubjectStore(subjects);
    JCustosServiceResolver.setAuthenticationService(FakeAuthenticationService.forType(String.class));
    JCustosServiceResolver.setAuthorizationService(authorization);
    authorization.putRoles("alice", Set.of(ADMIN));
    subjects.setCurrentSubject("alice", String.class);
  }

  @AfterEach
  void reset() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
  }

  @Test
  @DisplayName("button, router link and menu item follow a role change at refreshAll, without navigation")
  void refreshAll_followsRoleChange() {
    UI ui = UI.getCurrent();
    SecuredButton button = new SecuredButton("Delete", Requirement.role(ADMIN));
    SecuredRouterLink link = new SecuredRouterLink("Admin", AdminTarget.class, Requirement.role(ADMIN));
    MenuBar menu = new MenuBar();
    MenuItem item = menu.addItem("Users");
    SecuredMenuItem.bind(item, Requirement.role(ADMIN));
    ui.add(new Div(button, link, menu));
    assertTrue(button.isEnabled());
    assertTrue(link.isVisible());
    assertTrue(item.isVisible());

    authorization.putRoles("alice", Set.of());
    assertTrue(button.isEnabled(), "precondition: nothing re-evaluates by itself");

    int refreshed = SecuredVisibility.refreshAll(ui);

    assertEquals(3, refreshed, "the button, the link and the menu item are registered with the UI");
    assertFalse(button.isEnabled(), "the button is disabled once the role is gone");
    assertFalse(link.isVisible(), "the link is hidden");
    assertFalse(item.isVisible(), "the menu item is hidden");

    authorization.putRoles("alice", Set.of(ADMIN));
    SecuredVisibility.refreshAll(ui);
    assertTrue(button.isEnabled());
    assertTrue(link.isVisible());
    assertTrue(item.isVisible());
  }

  @Test
  @DisplayName("a binding whose component was garbage-collected is dropped")
  void refreshAll_dropsCollectedBindings() throws InterruptedException {
    UI ui = UI.getCurrent();
    SecuredButton kept = new SecuredButton("Kept", Requirement.role(ADMIN));
    ui.add(kept);
    WeakReference<SecuredButton> dropped = createUnreferencedButton();
    assertEquals(2, SecuredBindingRegistry.registeredCount(ui),
        "precondition: the unattached button is registered with the current UI");

    awaitCollection(dropped);

    assertEquals(1, SecuredVisibility.refreshAll(ui), "only the live button is refreshed");
    assertEquals(1, SecuredBindingRegistry.registeredCount(ui));
  }

  @Test
  @DisplayName("a refresh that throws hides its component and does not stop the others")
  void refreshAll_failingBindingIsHiddenAndIsolated() {
    UI ui = UI.getCurrent();
    Div broken = new Div();
    ui.add(broken);
    SecuredBindingRegistry.register(broken, () -> {
      throw new IllegalStateException("policy backend unreachable");
    });
    SecuredButton button = new SecuredButton("Delete", Requirement.role(ADMIN));
    ui.add(button);
    authorization.putRoles("alice", Set.of());

    assertEquals(2, SecuredVisibility.refreshAll(ui));

    assertFalse(broken.isVisible(), "fail closed: a binding that cannot be evaluated is hidden");
    assertFalse(button.isEnabled(), "the other binding is still refreshed");
  }

  @Test
  @DisplayName("a secured menu item is evaluated again when its menu bar is attached")
  void menuItem_reEvaluatedOnAttach() {
    MenuBar menu = new MenuBar();
    MenuItem item = menu.addItem("Users");
    SecuredMenuItem.bind(item, Requirement.role(ADMIN));
    assertTrue(item.isVisible(), "bound while alice held the role");
    authorization.putRoles("alice", Set.of());

    UI.getCurrent().add(menu);
    // the menu bar attaches its items while it prepares the response to the browser
    MockVaadin.clientRoundtrip();

    assertTrue(item.isAttached(), "precondition: the item is attached now");
    assertFalse(item.isVisible(), "the role was withdrawn before the menu was shown");
  }

  @Test
  @DisplayName("RF18: two bindings on one button combine with AND - an allowing binding does not undo a denying one")
  void twoBindings_combineWithAnd() {
    UI ui = UI.getCurrent();
    // what SecuredUi.action(new SecuredButton(.., role(ADMIN)), onClick).requiresPermission(..) binds
    SecuredButton button = new SecuredButton("Export", Requirement.role(ADMIN));
    SecuredBindingRegistry.register(button, permissionBinding(button, SecuredVisibilityMode.DISABLE));
    ui.add(button);
    authorization.putRoles("alice", Set.of());
    authorization.putPermissions("alice", Set.of(EXPORT));

    SecuredVisibility.refreshAll(ui);

    assertFalse(button.isEnabled(), "alice holds the permission but not the role: both are required");
    assertTrue(button.isVisible());

    authorization.putRoles("alice", Set.of(ADMIN));
    SecuredVisibility.refreshAll(ui);
    assertTrue(button.isEnabled(), "both satisfied: enabled");

    authorization.putPermissions("alice", Set.of());
    SecuredVisibility.refreshAll(ui);
    assertFalse(button.isEnabled(), "the other way round: the role alone is not enough either");
  }

  @Test
  @DisplayName("RF18: a binding that throws hides the component, even when a later binding allows it")
  void throwingBinding_thenAllowingBinding_hidden() {
    UI ui = UI.getCurrent();
    Div panel = new Div();
    ui.add(panel);
    SecuredBindingRegistry.register(panel, () -> {
      throw new IllegalStateException("policy backend unreachable");
    });
    SecuredBindingRegistry.register(panel, () -> SecuredVisibility.apply(new ComponentTarget(panel),
        Requirement.role(ADMIN), SecuredVisibilityMode.HIDE));
    assertFalse(panel.isVisible(), "the second registration shows the combined verdict at once");

    panel.setVisible(true);
    assertEquals(1, SecuredVisibility.refreshAll(ui));

    assertFalse(panel.isVisible(), "fail closed across bindings: alice holds the role, the other "
        + "binding cannot be evaluated");
  }

  @Test
  @DisplayName("RF18: after an attach the combined verdict applies, not the binding that re-evaluated last")
  void twoBindings_combinedAfterAttach() {
    authorization.putRoles("alice", Set.of());
    authorization.putPermissions("alice", Set.of(EXPORT));
    SecuredButton button = new SecuredButton("Export", Requirement.role(ADMIN));
    Runnable permission = permissionBinding(button, SecuredVisibilityMode.DISABLE);
    // as SecuredUi binds: evaluated on every attach, after the button's own re-evaluation
    button.addAttachListener(attach -> permission.run());
    SecuredBindingRegistry.register(button, permission);
    assertFalse(button.isEnabled(), "precondition: combined when the second binding was registered");

    UI.getCurrent().add(button);
    MockVaadin.clientRoundtrip();

    assertFalse(button.isEnabled(), "the permission binding re-evaluated last must not enable it");
  }

  @Test
  @DisplayName("RF17: evaluating 50 secured components does not resolve the subject id once")
  void securedComponents_doNotResolveTheSubjectId() {
    AtomicInteger resolved = new AtomicInteger();
    JCustosServiceResolver.setSubjectIdResolver((SubjectIdResolver<String>) subject -> {
      resolved.incrementAndGet();
      return SubjectId.of(subject);
    });
    UI ui = UI.getCurrent();
    for (int i = 0; i < 50; i++) {
      ui.add(new SecuredButton("Action " + i, Requirement.role(ADMIN)));
    }

    assertEquals(50, SecuredVisibility.refreshAll(ui));

    assertEquals(0, resolved.get(), "no requirement reads the subject id");
  }

  @Test
  @DisplayName("control: without registered bindings refreshAll does nothing")
  void refreshAll_withoutBindings() {
    assertEquals(0, SecuredVisibility.refreshAll(UI.getCurrent()));
  }

  private static Runnable permissionBinding(SecuredButton button, SecuredVisibilityMode mode) {
    return () -> SecuredVisibility.apply(new ComponentTarget(button), Requirement.permission(EXPORT),
        mode);
  }

  private static WeakReference<SecuredButton> createUnreferencedButton() {
    return new WeakReference<>(new SecuredButton("Dropped", Requirement.role(ADMIN)));
  }

  private static void awaitCollection(WeakReference<?> reference) throws InterruptedException {
    List<byte[]> pressure = new ArrayList<>();
    for (int attempt = 0; attempt < 50 && reference.get() != null; attempt++) {
      pressure.add(new byte[1 << 20]);
      System.gc();
      Thread.sleep(20);
      if (pressure.size() > 8) {
        pressure.clear();
      }
    }
    assertNull(reference.get(), "the button must be collectable - nothing may keep it alive");
  }

  /** The target of the secured router link. */
  @Route("r8-registry/admin")
  public static class AdminTarget extends Div {
  }
}
