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

import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.components.SecuredVisibility.Requirement;
import eu.jsentinel.jcustos.session.SessionRecord;
import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.SessionStore;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;

import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Optional;
import java.util.function.Consumer;

import static java.util.Objects.requireNonNull;

/**
 * Reusable session-management UI for security administrators.
 * <p>
 * Renders every persisted {@link SessionRecord} from the supplied
 * {@link SessionStore} as a {@link Grid} row showing tenant,
 * subject, session id, status, created-at, last-activity-at, and
 * the security version snapshot. Each row carries a Revoke button;
 * clicking it invokes the supplied revoke callback (typically
 * {@code LogoutService.logout(subjectId, CurrentSession)} or a
 * direct {@code SessionStore.delete}).
 *
 * <p>Apps integrate by subclassing, annotating with
 * {@code @Route(...)} and the desired permission annotation:
 * <pre>{@code
 *   @Route("admin/sessions")
 *   @RequiresPermission("admin:sessions")
 *   public class AdminSessionsView extends SessionManagementView {
 *     public AdminSessionsView() {
 *       super(MyServices.sessionStore(), MyServices.revoker());
 *     }
 *   }
 * }</pre>
 *
 * <p>The view does not subscribe to live updates — the grid
 * snapshots the store on construction and on every
 * {@link #refresh()} call. Apps that want auto-refresh can wire a
 * polling timer via {@code UI.setPollInterval(...)} and call
 * {@code refresh()} from a {@code PollEvent} listener.
 *
 * <p><strong>Who may revoke (JS-SEC-068, CWE-306).</strong> A hidden
 * or disabled button is not a security boundary: the Revoke handler
 * runs on the server for whoever reached the view. The three-argument
 * constructor therefore takes a {@link Requirement}; when it is
 * non-empty the handler re-checks the current subject against it
 * before touching the store and audits a refused attempt as
 * {@code AccessDenied}. The two-argument constructor keeps the
 * requirement empty — use it only from a route that carries its own
 * security annotation, as in the example above.
 */
@ExperimentalJCustosApi
public class SessionManagementView extends Composite<VerticalLayout> implements HasLogger {

  private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ISO_INSTANT;

  /** Resource name the revoke guard audits under. */
  static final String AUDIT_ROUTE = "session-management";
  /** Audit reason when the revoke guard refuses. */
  static final String REASON_REQUIREMENT_NOT_MET = "session-management:requirement-not-met";

  private final SessionStore sessionStore;
  private final Consumer<SessionRecord> revoke;
  private final Requirement requirement;
  private final Grid<SessionRecord> grid;

  /**
   * Creates a view without a view-level revoke guard. Protect the
   * route with a security annotation.
   *
   * @param sessionStore source of session records; non-null
   * @param revoke       callback invoked when an admin clicks
   *                     Revoke on a row; non-null. Implementations
   *                     typically delete the record from the store
   *                     and emit a {@code LogoutPerformed} audit
   *                     event
   */
  public SessionManagementView(SessionStore sessionStore,
                               Consumer<SessionRecord> revoke) {
    this(sessionStore, revoke, Requirement.none());
  }

  /**
   * Creates a view whose Revoke handler re-checks {@code requirement}
   * against the current subject before it revokes (JS-SEC-068).
   *
   * @param sessionStore source of session records; non-null
   * @param revoke       callback invoked when an admitted admin clicks
   *                     Revoke on a row; non-null
   * @param requirement  roles and permissions a subject must hold to
   *                     revoke; non-null, {@link Requirement#none()}
   *                     disables the guard
   * @since 00.84.00
   */
  public SessionManagementView(SessionStore sessionStore,
                               Consumer<SessionRecord> revoke,
                               Requirement requirement) {
    this.sessionStore = requireNonNull(sessionStore, "sessionStore must not be null");
    this.revoke = requireNonNull(revoke, "revoke must not be null");
    this.requirement = requireNonNull(requirement, "requirement must not be null");
    this.grid = buildGrid();

    VerticalLayout root = getContent();
    root.addClassName("session-management-view");
    root.setSizeFull();
    root.add(new H1("Active Sessions"));
    root.add(new Paragraph(
        "Inventory of every persisted session. Use Revoke to invalidate "
            + "a session — the user's next request will be refused."));
    root.add(grid);

    refresh();
  }

  private Grid<SessionRecord> buildGrid() {
    Grid<SessionRecord> g = new Grid<>(SessionRecord.class, false);
    g.setSizeFull();
    g.addColumn(r -> r.tenant().value()).setHeader("Tenant").setWidth("8em").setFlexGrow(0);
    g.addColumn(r -> r.subjectId().value()).setHeader("Subject").setAutoWidth(true);
    g.addColumn(r -> r.sessionId().value()).setHeader("Session id").setAutoWidth(true);
    g.addColumn(r -> r.status().name()).setHeader("Status").setWidth("8em").setFlexGrow(0);
    g.addColumn(r -> TIMESTAMP_FORMAT.format(r.createdAt()))
        .setHeader("Created at").setAutoWidth(true);
    g.addColumn(r -> TIMESTAMP_FORMAT.format(r.lastActivityAt()))
        .setHeader("Last activity").setAutoWidth(true);
    g.addColumn(r -> Long.toString(r.securityVersionAtLogin().value()))
        .setHeader("Version").setWidth("6em").setFlexGrow(0);
    g.addComponentColumn(record -> {
      Button revokeBtn = new Button("Revoke", e -> {
        revokeIfAllowed(record);
        refresh();
      });
      revokeBtn.addThemeVariants(ButtonVariant.LUMO_ERROR, ButtonVariant.LUMO_SMALL);
      // already-revoked / already-expired rows: keep the button
      // but disable it so the admin sees what happened to the
      // record without being able to double-revoke.
      if (record.status() != SessionStatus.ACTIVE) {
        revokeBtn.setEnabled(false);
      }
      return revokeBtn;
    }).setKey("action").setHeader("Action").setWidth("9em").setFlexGrow(0);
    return g;
  }

  /**
   * Revokes {@code record} if the current subject satisfies the
   * requirement this view was constructed with. An empty requirement
   * admits every caller — the route's own security annotation is then
   * the boundary. A refused attempt is audited as {@code AccessDenied}
   * and leaves the store untouched (JS-SEC-068, CWE-306).
   *
   * @param record the session to revoke
   * @return {@code true} when the revoke callback ran
   */
  final boolean revokeIfAllowed(SessionRecord record) {
    requireNonNull(record, "record must not be null");
    if (!requirement.isEmpty()) {
      Optional<SecuredVisibility.JCustosView> view = SecuredVisibility.currentJCustosView();
      boolean allowed = view
          .map(v -> SecuredVisibility.isAllowed(requirement, v.roles(), v.permissions()))
          .orElse(false);
      if (!allowed) {
        auditRefusedRevoke();
        return false;
      }
    }
    revoke.accept(record);
    return true;
  }

  private void auditRefusedRevoke() {
    try {
      JCustosAuditService sink = JCustosServiceResolver.securityAuditService();
      sink.publish(new AccessDenied(
          Instant.now(Clock.systemUTC()), null, AUDIT_ROUTE, REASON_REQUIREMENT_NOT_MET));
    } catch (RuntimeException auditFailure) {
      logger().warn("session-management: AccessDenied audit for a refused revoke failed: {}",
          auditFailure.toString());
    }
  }

  /** @return the requirement the Revoke guard enforces; empty when none */
  public final Requirement requirement() {
    return requirement;
  }

  /**
   * Re-reads {@link SessionStore#findAll()} and rebinds the grid.
   * Apps call this after a known mutation (e.g. from an external
   * audit event) to keep the view current.
   */
  public final void refresh() {
    grid.setItems(sessionStore.findAll());
  }

  /** @return the grid the view renders — exposed for tests */
  public final Grid<SessionRecord> grid() {
    return grid;
  }

  /** @return the SessionStore the view was constructed with */
  public final SessionStore sessionStore() {
    return sessionStore;
  }
}
