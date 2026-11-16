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
import eu.jsentinel.jcustos.session.vaadin.VaadinSessionRevocation;
import com.vaadin.flow.router.Route;

/**
 * Admin-only Phase-8a session inventory. Re-uses the framework's
 * {@link SessionManagementView} composite — the only demo-specific
 * code is wiring it to {@link DemoSessionStoreProvider} and to the
 * library's revoke. Demonstrates how a downstream app integrates
 * Phase-8a with two lines of glue.
 * <p>
 * The grid shows the reference of each session ({@code sref-…}), never
 * the session id: the records are stored under the reference
 * (JS-SEC-117, CWE-522), so an administrator cannot copy a session
 * cookie out of this view.
 * <p>
 * Revoke ends the session at the click (JS-SEC-131, CWE-613):
 * {@link VaadinSessionRevocation#revoke(SessionRecord)} removes the
 * record and ends the live session of this node that carries the
 * referenced id - subject dropped, {@code SessionInvalidated} audited
 * with the reason {@code Revoked}, Vaadin session closed, HTTP session
 * invalidated. On another node the missing record ends the session on
 * its next request. Do not wire
 * {@code LogoutService.logout(subjectId, CurrentSession)} here: the
 * current session is the administrator's own.
 */
@Route(AdminSessionsView.NAV)
@RequiresPermission("admin:sessions")
public class AdminSessionsView extends SessionManagementView {

  public static final String NAV = "admin/sessions";

  public AdminSessionsView() {
    super(DemoSessionStoreProvider.sessionStore(), VaadinSessionRevocation::revoke);
  }
}
