package eu.jsentinel.jcustos.demo.skill.vaadin.views.admin;

import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.components.SessionManagementView;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import com.vaadin.flow.router.Route;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.services.SessionStoreProvider;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.HomeButton;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.MainLayout;

/**
 * Admin-only session inventory + revoke. Re-uses the framework's
 * {@link SessionManagementView} composite — the only project-specific
 * glue is wiring it to {@link SessionStoreProvider} and to a revoke
 * callback.
 *
 * <p>The grid shows the reference of each session ({@code sref-…}), never
 * the session id: the records are stored under the reference
 * (JS-SEC-117, CWE-522), so an administrator cannot copy a session cookie
 * out of this view.
 *
 * <p>Revoke ends the session (JS-SEC-131, CWE-613): the callback marks the
 * record {@link SessionStatus#REVOKED}. The bootstrap registered the same
 * store for the per-request check of {@code SessionLifetimeListener}, which
 * ends a session whose record is revoked on its next request - on this
 * node and on every other node that shares the store - and audits
 * {@code SessionInvalidated} with the reason {@code Revoked}. The row stays
 * in the grid with a disabled button, so the administrator sees what
 * happened.
 *
 * <p>The constructor adds a Home button at the top of the content
 * layout via {@link HomeButton#forStandalone(Class)}: the button only
 * renders when this view is registered as a top-level {@code @Route}.
 * Once embedded in an {@code AppLayout} the helper returns empty and
 * the layout's drawer takes over navigation.
 */
@Route(value = SessionsView.NAV, layout = MainLayout.class)
@RequiresPermission("admin:sessions")
public class SessionsView extends SessionManagementView {

  public static final String NAV = "admin/sessions";

  public SessionsView() {
    super(SessionStoreProvider.sessionStore(), SessionsView::revoke);
    HomeButton.forStandalone(getClass())
        .ifPresent(home -> getContent().addComponentAsFirst(home));
  }

  /**
   * Revokes by reference: the record carries the reference, and the store
   * keys every lookup by the reference, so the session's next request
   * finds the record revoked and is refused.
   */
  private static void revoke(SessionRecord record) {
    SessionStoreProvider.sessionStore()
        .save(record.withStatus(SessionStatus.REVOKED));
  }
}
