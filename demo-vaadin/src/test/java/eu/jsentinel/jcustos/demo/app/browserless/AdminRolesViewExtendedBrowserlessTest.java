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
package eu.jsentinel.jcustos.demo.app.browserless;

import eu.jsentinel.jcustos.audit.RoleRevoked;
import eu.jsentinel.jcustos.audit.UserCreated;
import eu.jsentinel.jcustos.audit.UserDeleted;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.demo.app.TestDirectories;
import eu.jsentinel.jcustos.demo.app.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectoryProvider;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.demo.app.views.AdminRolesView;
import eu.jsentinel.jcustos.demo.app.views.MyLoginView;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.combobox.ComboBox;
import com.vaadin.flow.component.combobox.ComboBoxTester;
import com.vaadin.flow.component.confirmdialog.ConfirmDialog;
import com.vaadin.flow.component.confirmdialog.ConfirmDialogTester;
import com.vaadin.flow.component.dialog.Dialog;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.grid.GridTester;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationTester;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Browserless adapter tests for the secondary flows of
 * {@link AdminRolesView}: Revoke, Delete (with the ConfirmDialog), the
 * Create-user Dialog, the Back-to-home button, the {@code selectableRoles}
 * test seam, and the per-action warn/success Notification branches.
 * <p>
 * The primary path (Grid renders, Assign mutates the directory and emits
 * {@code RoleAssigned}) is pinned by {@code AdminRolesViewBrowserlessTest}.
 */
@DisplayName("AdminRolesView — extended flows (revoke, delete, create, warn/success)")
class AdminRolesViewExtendedBrowserlessTest extends BrowserlessTest {

  private final RecordingAuditSink audit = new RecordingAuditSink();

  @BeforeEach
  void setUp() throws Exception {
    System.setProperty("security.bootstrap.mode", "DISABLED");
    resetBootstrapWiringSingleton();

    JCustosServiceResolver.resetAll();
    // The grid flows need the demo accounts user (id 2) and demo (id 3),
    // which exist only behind the development switch (JS-SEC-137).
    TestDirectories.installWithDemoAccounts();
    DemoUserDirectoryProvider.directory().addUser("admin", "admin",
        new MyUser(1L, "Admin",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    JCustosServiceResolver.setJCustosAuditService(audit);
    audit.clear();
  }

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
  }

  // ── Revoke flow ────────────────────────────────────────────────

  @Test
  @DisplayName("Revoke removes the role + emits RoleRevoked")
  void revokeMutatesAndAudits() {
    DemoUserDirectoryProvider.directory().assignRole(2L, AuthorizationRole.NERD);
    audit.clear();

    navigateAsAdmin();
    GridTester<Grid<MyUser>, MyUser> grid = grid();
    int row = rowOf(grid, 2L);
    HorizontalLayout editor = (HorizontalLayout) grid.getCellComponent(row, 3);

    @SuppressWarnings({"unchecked", "rawtypes"})
    ComboBoxTester combo = test(roleSelect(editor));
    combo.selectItem(AuthorizationRole.NERD.name());
    test(button(editor, "Revoke")).click();

    MyUser after = DemoUserDirectoryProvider.directory().findById(2L).orElseThrow();
    assertFalse(after.roles().contains(AuthorizationRole.NERD),
        "Revoke must remove the role from the directory");

    RoleRevoked event = audit.events().stream()
        .filter(RoleRevoked.class::isInstance)
        .map(RoleRevoked.class::cast)
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "expected a RoleRevoked event; got: " + audit.events()));
    assertEquals("2", event.subjectId());
    assertEquals(AuthorizationRole.NERD.name(), event.role());
  }

  @Test
  @DisplayName("Assign with no role selected surfaces 'Pick a role first.'")
  void assignWithoutRoleWarns() {
    navigateAsAdmin();
    int row = rowOf(grid(), 2L);
    HorizontalLayout editor = (HorizontalLayout) grid().getCellComponent(row, 3);

    test(button(editor, "Assign")).click();

    assertWarn("Pick a role first.");
  }

  @Test
  @DisplayName("Assign for a role the user already has surfaces 'User already has ...'")
  void assignDuplicateWarns() {
    navigateAsAdmin();
    int row = rowOf(grid(), 2L);
    HorizontalLayout editor = (HorizontalLayout) grid().getCellComponent(row, 3);

    test(roleSelect(editor)).selectItem(AuthorizationRole.USER.name());
    test(button(editor, "Assign")).click();

    assertWarn("User already has USER.");
  }

  @Test
  @DisplayName("Revoke without picking a role surfaces 'Pick a role first.'")
  void revokeWithoutRoleWarns() {
    navigateAsAdmin();
    int row = rowOf(grid(), 2L);
    HorizontalLayout editor = (HorizontalLayout) grid().getCellComponent(row, 3);

    test(button(editor, "Revoke")).click();

    assertWarn("Pick a role first.");
  }

  @Test
  @DisplayName("Revoke for a role the user does not have surfaces 'User does not have ...'")
  void revokeMissingRoleWarns() {
    navigateAsAdmin();
    int row = rowOf(grid(), 2L);
    HorizontalLayout editor = (HorizontalLayout) grid().getCellComponent(row, 3);

    test(roleSelect(editor)).selectItem(AuthorizationRole.ADMIN.name());
    test(button(editor, "Revoke")).click();

    assertWarn("User does not have ADMIN.");
  }

  // ── Delete flow ────────────────────────────────────────────────

  @Test
  @DisplayName("Trash button opens a ConfirmDialog; confirming deletes the user + emits UserDeleted")
  void deleteConfirmedRemovesUser() {
    navigateAsAdmin();
    GridTester<Grid<MyUser>, MyUser> grid = grid();
    int row = rowOf(grid, 2L);
    Button trash = (Button) grid.getCellComponent(row, 4);

    test(trash).click();

    ConfirmDialog dialog = $(ConfirmDialog.class).first();
    ConfirmDialogTester dialogTester = test(dialog);
    assertTrue(dialog.isOpened(), "trash click must open the ConfirmDialog");
    assertTrue(dialogTester.getText().contains("'Herr User'"),
        "dialog must reference the user; got: " + dialogTester.getText());

    audit.clear();
    dialogTester.confirm();

    assertFalse(DemoUserDirectoryProvider.directory().findById(2L).isPresent(),
        "after confirm the directory must no longer contain id=2");
    assertTrue(audit.events().stream().anyMatch(UserDeleted.class::isInstance),
        "delete must publish a UserDeleted audit event");

    assertSuccess("Deleted user Herr User.");
  }

  @Test
  @DisplayName("Trash button + Cancel keeps the user in the directory")
  void deleteCancelKeepsUser() {
    navigateAsAdmin();
    GridTester<Grid<MyUser>, MyUser> grid = grid();
    int row = rowOf(grid, 2L);
    test((Button) grid.getCellComponent(row, 4)).click();

    ConfirmDialog dialog = $(ConfirmDialog.class).first();
    audit.clear();
    test(dialog).cancel();

    assertTrue(DemoUserDirectoryProvider.directory().findById(2L).isPresent(),
        "Cancel must not delete the user");
    assertFalse(audit.events().stream().anyMatch(UserDeleted.class::isInstance),
        "no UserDeleted event must be emitted on cancel");
  }

  // ── Create-user dialog ─────────────────────────────────────────

  @Test
  @DisplayName("'New user' opens a dialog with username/password/role fields marked required")
  void createDialogOpensWithRequiredFields() {
    navigateAsAdmin();

    test(findButton("New user")).click();

    Dialog dialog = $(Dialog.class).first();
    assertTrue(dialog.isOpened());

    TextField username = $(TextField.class).all().stream()
        .filter(f -> "Username".equals(f.getLabel()))
        .findFirst()
        .orElseThrow();
    PasswordField password = $(PasswordField.class).first();
    @SuppressWarnings("rawtypes")
    ComboBox role = $(ComboBox.class).all().stream()
        .filter(c -> "Initial role".equals(((ComboBox<?>) c).getLabel()))
        .findFirst()
        .orElseThrow();
    TextField displayName = $(TextField.class).all().stream()
        .filter(f -> "Display name".equals(f.getLabel()))
        .findFirst()
        .orElseThrow();

    assertTrue(username.isRequiredIndicatorVisible(),
        "Username field must be required");
    assertTrue(password.isRequiredIndicatorVisible(),
        "Password field must be required");
    assertTrue(role.isRequiredIndicatorVisible(),
        "Role ComboBox must be required");
    assertEquals(AuthorizationRole.USER, role.getValue(),
        "Initial role ComboBox must default to USER");
    assertEquals("(defaults to username)", displayName.getPlaceholder(),
        "Display-name field must surface the fallback hint");
  }

  @Test
  @DisplayName("Create with empty username surfaces the validation warn")
  void createValidationEmptyUsername() {
    navigateAsAdmin();
    test(findButton("New user")).click();

    PasswordField password = $(PasswordField.class).first();
    password.setValue("secret");
    test(findButton("Create")).click();

    assertWarn("Username, password and initial role are required.");
  }

  @Test
  @DisplayName("Create with valid input adds a user + emits UserCreated; dialog closes")
  void createSuccessAddsUser() {
    navigateAsAdmin();
    test(findButton("New user")).click();

    TextField username = $(TextField.class).all().stream()
        .filter(f -> "Username".equals(f.getLabel()))
        .findFirst()
        .orElseThrow();
    PasswordField password = $(PasswordField.class).first();
    username.setValue("charlie");
    password.setValue("c0de");

    long beforeMaxId = DemoUserDirectoryProvider.directory().all()
        .mapToLong(MyUser::id).max().orElse(0);

    Dialog dialog = $(Dialog.class).first(); // capture before close
    test(findButton("Create")).click();

    long afterMaxId = DemoUserDirectoryProvider.directory().all()
        .mapToLong(MyUser::id).max().orElse(0);
    assertEquals(beforeMaxId + 1, afterMaxId,
        "Create must assign nextId() = max + 1");

    MyUser created = DemoUserDirectoryProvider.directory().all()
        .filter(u -> u.id() == afterMaxId)
        .findFirst()
        .orElseThrow();
    assertEquals("charlie", created.name(),
        "displayName defaults to the username when no display name is given");
    assertTrue(created.roles().contains(AuthorizationRole.USER),
        "created user must carry the selected role (USER default)");

    assertTrue(audit.events().stream().anyMatch(UserCreated.class::isInstance),
        "Create must publish a UserCreated audit event; got: " + audit.events());
    assertSuccess("Created user charlie.");

    assertFalse(dialog.isOpened(), "successful create must close the dialog");
  }

  @Test
  @DisplayName("Create with a Display name overrides the username fallback")
  void createWithExplicitDisplayName() {
    navigateAsAdmin();
    test(findButton("New user")).click();

    TextField username = $(TextField.class).all().stream()
        .filter(f -> "Username".equals(f.getLabel())).findFirst().orElseThrow();
    TextField displayName = $(TextField.class).all().stream()
        .filter(f -> "Display name".equals(f.getLabel())).findFirst().orElseThrow();
    PasswordField password = $(PasswordField.class).first();
    username.setValue("d");
    password.setValue("d");
    displayName.setValue("Diana Prince");

    test(findButton("Create")).click();

    MyUser created = DemoUserDirectoryProvider.directory().all()
        .filter(u -> "Diana Prince".equals(u.name()))
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "no user with display name 'Diana Prince' after create"));
    assertEquals("Diana Prince", created.name(),
        "explicit Display name must override the username fallback");
  }

  @Test
  @DisplayName("Create dialog Cancel closes the dialog without mutating the directory")
  void createCancelDoesNotMutate() {
    navigateAsAdmin();
    test(findButton("New user")).click();

    long beforeCount = DemoUserDirectoryProvider.directory().all().count();
    audit.clear();

    Dialog dialog = $(Dialog.class).first(); // capture before close
    test(findButton("Cancel")).click();

    assertFalse(dialog.isOpened(), "Cancel must close the dialog");
    assertEquals(beforeCount,
        DemoUserDirectoryProvider.directory().all().count(),
        "Cancel must not touch the directory");
    assertFalse(audit.events().stream().anyMatch(UserCreated.class::isInstance),
        "Cancel must not emit UserCreated");
  }

  // ── Back to home button + selectableRoles seam ────────────────

  @Test
  @DisplayName("'Back to home' button is rendered alongside 'New user'")
  void backToHomeButtonRendered() {
    navigateAsAdmin();

    assertNotNull(findButton("Back to home"),
        "the toolbar must include a 'Back to home' button");
    assertNotNull(findButton("New user"),
        "the toolbar must include a 'New user' button");
  }

  // ── Helpers ────────────────────────────────────────────────────

  private void navigateAsAdmin() {
    navigate(MyLoginView.class);
    SubjectStores.subjectStore().setCurrentSubject(
        new MyUser(1L, "Admin",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)),
        MyUser.class);
    navigate(AdminRolesView.class);
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private GridTester<Grid<MyUser>, MyUser> grid() {
    return test($view(Grid.class).first());
  }

  private static int rowOf(GridTester<Grid<MyUser>, MyUser> grid, Long id) {
    for (int i = 0; i < grid.size(); i++) {
      if (grid.getRow(i).id().equals(id)) return i;
    }
    throw new AssertionError("no row with id=" + id);
  }

  private static ComboBox<?> roleSelect(HorizontalLayout editor) {
    return (ComboBox<?>) editor.getChildren()
        .filter(ComboBox.class::isInstance)
        .findFirst()
        .orElseThrow();
  }

  private static Button button(HorizontalLayout editor, String label) {
    return editor.getChildren()
        .filter(Button.class::isInstance)
        .map(Button.class::cast)
        .filter(b -> label.equals(b.getText()))
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "no '" + label + "' button in role-editor row"));
  }

  private Button findButton(String label) {
    return $(Button.class).all().stream()
        .filter(b -> label.equals(b.getText()))
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "no button labelled '" + label + "'; got: "
                + $(Button.class).all().stream().map(Button::getText).toList()));
  }

  /** Asserts that a Notification with the given text was shown. */
  private void assertWarn(String expectedText) {
    boolean found = $(Notification.class).all().stream()
        .map(n -> ((NotificationTester) test(n)).getText())
        .anyMatch(t -> t.contains(expectedText));
    assertTrue(found,
        "expected a warn Notification containing '" + expectedText + "'; got: "
            + $(Notification.class).all().stream()
                .map(n -> ((NotificationTester) test(n)).getText())
                .toList());
  }

  private void assertSuccess(String expectedText) {
    boolean found = $(Notification.class).all().stream()
        .map(n -> ((NotificationTester) test(n)).getText())
        .anyMatch(t -> t.contains(expectedText));
    assertTrue(found,
        "expected a success Notification containing '" + expectedText + "'");
  }

  private static void resetBootstrapWiringSingleton() throws Exception {
    var field = BootstrapWiring.class.getDeclaredField("current");
    field.setAccessible(true);
    field.set(null, null);
  }

}
