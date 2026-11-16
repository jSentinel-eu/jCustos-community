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

import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.components.SessionManagementView;
import eu.jsentinel.jcustos.demo.app.security.services.DemoSessionStoreProvider;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import com.vaadin.flow.router.Route;

/**
 * Admin-only Phase-8a session inventory. Re-uses the framework's
 * {@link SessionManagementView} composite — the only demo-specific
 * code is wiring it to {@link DemoSessionStoreProvider} and to a
 * revoke callback that updates the same store. Demonstrates how a
 * downstream app integrates Phase-8a with two lines of glue.
 * <p>
 * The grid shows the reference of each session ({@code sref-…}), never
 * the session id: the records are stored under the reference
 * (JS-SEC-117, CWE-522), so an administrator cannot copy a session
 * cookie out of this view.
 * <p>
 * Revoke ends the session (JS-SEC-131, CWE-613): the callback marks the
 * record {@link SessionStatus#REVOKED}, and the bootstrap registered the
 * same store for the per-request check of {@code SessionLifetimeListener},
 * which ends a session whose record is revoked on its next request and
 * audits {@code SessionInvalidated} with the reason {@code Revoked}.
 */
@Route(AdminSessionsView.NAV)
@RequiresPermission("admin:sessions")
public class AdminSessionsView extends SessionManagementView {

  public static final String NAV = "admin/sessions";

  public AdminSessionsView() {
    super(DemoSessionStoreProvider.sessionStore(), AdminSessionsView::revoke);
  }

  /**
   * Revoke callback: marks the supplied record as
   * {@link SessionStatus#REVOKED}. The record carries the reference, and
   * the store keys every lookup by the reference, so the session's next
   * request finds the record revoked and is refused. Do not wire
   * {@code LogoutService.logout(subjectId, CurrentSession)} here: the
   * current session is the administrator's own.
   */
  private static void revoke(SessionRecord record) {
    DemoSessionStoreProvider.sessionStore()
        .save(record.withStatus(SessionStatus.REVOKED));
  }
}
