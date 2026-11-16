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

import eu.jsentinel.jcustos.audit.RoleAssigned;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.demo.app.TestDirectories;
import eu.jsentinel.jcustos.demo.app.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectoryProvider;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.demo.app.views.AdminRolesView;
import eu.jsentinel.jcustos.demo.app.views.MyLoginView;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.combobox.ComboBox;
import com.vaadin.flow.component.combobox.ComboBoxTester;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.grid.GridTester;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Browserless adapter test for the {@code /admin/roles}-route.
 * <p>
 * Asserts that, with an admin subject bound, {@link AdminRolesView}
 * <ol>
 *   <li>renders the Grid populated with every directory user, and</li>
 *   <li>"Assign" actually mutates the directory and emits the matching
 *       {@link RoleAssigned} audit event.</li>
 * </ol>
 */
@DisplayName("AdminRolesView — Grid + Assign action")
class AdminRolesViewBrowserlessTest extends BrowserlessTest {

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
  }

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
  }

  @Test
  @DisplayName("Grid lists all directory users; Assign grants a role and emits RoleAssigned")
  void gridListsAndAssignGrantsRole() {
    // Bring the UI up via a public route, then bind the admin so the
    // @RequiresPermission("admin:roles") gate passes on the next navigate.
    navigate(MyLoginView.class);
    SubjectStores.subjectStore().setCurrentSubject(
        new MyUser(1L, "Admin",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)),
        MyUser.class);

    navigate(AdminRolesView.class);

    @SuppressWarnings({"unchecked", "rawtypes"})
    GridTester<Grid<MyUser>, MyUser> grid = test($view(Grid.class).first());
    assertEquals(3, grid.size(),
        "Grid must list all three seeded users (admin, user, demo)");

    int userRow = rowOf(grid, 2L);
    assertTrue(userRow >= 0, "directory must contain the seeded 'user' (id=2)");
    MyUser before = grid.getRow(userRow);
    assertTrue(before.roles().contains(AuthorizationRole.USER));
    assertTrue(!before.roles().contains(AuthorizationRole.NERD),
        "seeded 'user' must not start out with NERD");

    // Columns: 0=Id, 1=Name, 2=Roles, 3=Modify, 4=Delete. The Modify
    // column is built via addComponentColumn with no property key, so we
    // address it positionally.
    HorizontalLayout editor = (HorizontalLayout) grid.getCellComponent(userRow, 3);
    ComboBox<?> roleSelect = findChild(editor, ComboBox.class);
    Button assign = findChildButton(editor, "Assign");
    assertNotNull(roleSelect, "Modify cell must expose a role ComboBox");
    assertNotNull(assign, "Modify cell must expose an Assign button");

    @SuppressWarnings({"unchecked", "rawtypes"})
    ComboBoxTester roleTester = test(roleSelect);
    roleTester.selectItem(AuthorizationRole.NERD.name());
    test(assign).click();

    MyUser after = DemoUserDirectoryProvider.directory().findById(2L).orElseThrow();
    assertTrue(after.roles().contains(AuthorizationRole.NERD),
        "Assign must grant NERD to the user");

    RoleAssigned event = audit.events().stream()
        .filter(RoleAssigned.class::isInstance)
        .map(RoleAssigned.class::cast)
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "expected one RoleAssigned event after Assign; got: " + audit.events()));
    assertEquals("2", event.subjectId(),
        "RoleAssigned must carry the mutated user's id");
    assertEquals(AuthorizationRole.NERD.name(), event.role(),
        "RoleAssigned must carry the granted role");
  }

  private static int rowOf(GridTester<Grid<MyUser>, MyUser> grid, Long id) {
    for (int i = 0; i < grid.size(); i++) {
      if (grid.getRow(i).id().equals(id)) return i;
    }
    return -1;
  }

  @SuppressWarnings("unchecked")
  private static <C extends Component> C findChild(HorizontalLayout layout, Class<C> type) {
    return (C) layout.getChildren()
        .filter(type::isInstance)
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "no " + type.getSimpleName() + " child in role-editor row"));
  }

  private static Button findChildButton(HorizontalLayout layout, String label) {
    return layout.getChildren()
        .filter(Button.class::isInstance)
        .map(Button.class::cast)
        .filter(b -> label.equals(b.getText()))
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "no Button labelled '" + label + "' in role-editor row"));
  }

  private static void resetBootstrapWiringSingleton() throws Exception {
    var field = BootstrapWiring.class.getDeclaredField("current");
    field.setAccessible(true);
    field.set(null, null);
  }

}
