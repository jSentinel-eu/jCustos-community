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

import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.demo.app.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectoryProvider;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.demo.app.security.services.DemoSessionStoreProvider;
import eu.jsentinel.jcustos.demo.app.views.AdminSessionsView;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.SessionStore;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.html.H1;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Smoke test for {@link AdminSessionsView}, the Phase-8a demo wiring
 * for {@link eu.jsentinel.jcustos.components.SessionManagementView}.
 * Confirms:
 * <ul>
 *   <li>The route renders the framework composite (H1 + Grid).</li>
 *   <li>The shared {@link DemoSessionStoreProvider} feeds the grid:
 *       a record saved to the store surfaces in the rendered view.</li>
 *   <li>The grid shows the reference of a record's session id, also for
 *       a record stored under the raw id (JS-SEC-117).</li>
 * </ul>
 * Revoke itself is covered by {@code SessionRevocationBrowserlessTest}.
 */
@DisplayName("AdminSessionsView — Phase-8a SessionManagementView wiring")
class AdminSessionsViewBrowserlessTest extends BrowserlessTest {

  /** As the login view records it: under the reference of the session id. */
  private static final SessionId SID = SessionId.of(SessionRef.of("demo-session-1"));

  /** A record a store without references would hold. */
  private static final SessionId RAW_SID = SessionId.of("demo-session-2");

  @org.junit.jupiter.api.BeforeEach
  @Override
  protected void initVaadinEnvironment() {
    System.setProperty("security.bootstrap.mode", "DISABLED");
    try {
      var field = BootstrapWiring.class.getDeclaredField("current");
      field.setAccessible(true);
      field.set(null, null);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    JCustosServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
    MyUser admin = new MyUser(1L, "Admin",
        java.util.EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER));
    DemoUserDirectoryProvider.directory().addUser("admin", "admin", admin);

    // Clean state in the shared session store between tests.
    SessionStore store = DemoSessionStoreProvider.sessionStore();
    store.delete(SID);
    store.delete(RAW_SID);

    super.initVaadinEnvironment();

    // Bind the admin so the @RequiresPermission("admin:sessions") guard
    // on AdminSessionsView lets the navigation through.
    SubjectStores.subjectStore().setCurrentSubject(admin, MyUser.class);
  }

  @AfterEach
  void tearDown() {
    DemoSessionStoreProvider.sessionStore().delete(SID);
    DemoSessionStoreProvider.sessionStore().delete(RAW_SID);
    JCustosServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
  }

  @Test
  @DisplayName("Renders the framework SessionManagementView H1 + Grid")
  void rendersHeadingAndGrid() {
    navigate(AdminSessionsView.class);

    H1 heading = $view(H1.class).first();
    assertNotNull(heading, "SessionManagementView must render an H1");
    assertEquals("Active Sessions", heading.getText(),
        "framework heading text must surface in the demo subclass");

    Grid<?> grid = $view(Grid.class).first();
    assertNotNull(grid, "SessionManagementView must render a Grid<SessionRecord>");
  }

  @Test
  @DisplayName("A record saved to the shared SessionStore is surfaced by the view")
  void recordInStoreIsRendered() {
    Instant now = Instant.now();
    SessionRecord record = new SessionRecord(
        SID, SubjectId.of("1"), TenantId.DEFAULT,
        now, now, JCustosVersion.INITIAL, SessionStatus.ACTIVE);
    DemoSessionStoreProvider.sessionStore().save(record);

    navigate(AdminSessionsView.class);

    @SuppressWarnings("unchecked")
    Grid<SessionRecord> grid = $view(Grid.class).first();
    assertEquals(List.of(record), grid.getGenericDataView().getItems().toList(),
        "the demo store must surface the saved record to the view");
    assertEquals(List.of(SID.value()), sessionIdColumn(grid),
        "the column shows the reference the record is stored under");
  }

  @Test
  @DisplayName("JS-SEC-117: a record stored under a raw session id is shown by its reference")
  void rawIdIsRenderedAsReference() {
    Instant now = Instant.now();
    DemoSessionStoreProvider.sessionStore().save(new SessionRecord(
        RAW_SID, SubjectId.of("1"), TenantId.DEFAULT,
        now, now, JCustosVersion.INITIAL, SessionStatus.ACTIVE));

    navigate(AdminSessionsView.class);

    @SuppressWarnings("unchecked")
    Grid<SessionRecord> grid = $view(Grid.class).first();
    assertEquals(List.of(SessionRef.of(RAW_SID.value())), sessionIdColumn(grid),
        "the grid must never show a session cookie");
  }

  /** The rendered texts of the "Session id" column. */
  private List<String> sessionIdColumn(Grid<SessionRecord> grid) {
    List<Grid.Column<SessionRecord>> columns = grid.getColumns();
    int index = columns.indexOf(columns.stream()
        .filter(c -> "Session id".equals(c.getHeaderText()))
        .findFirst().orElseThrow(() -> new AssertionError("no 'Session id' column")));
    var tester = test(grid);
    return java.util.stream.IntStream.range(0, tester.size())
        .mapToObj(row -> tester.getCellText(row, index))
        .toList();
  }
}
