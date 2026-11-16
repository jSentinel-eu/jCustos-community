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
package eu.jsentinel.jcustos.demo.restclient.views.standalone;

import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.audit.AccessGranted;
import eu.jsentinel.jcustos.audit.ActionDenied;
import eu.jsentinel.jcustos.audit.ApiKeyDenied;
import eu.jsentinel.jcustos.audit.ApiKeyUsed;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.BootstrapAdminCreated;
import eu.jsentinel.jcustos.audit.BootstrapTokenRejected;
import eu.jsentinel.jcustos.audit.BruteForceLimitReached;
import eu.jsentinel.jcustos.audit.EmailVerificationRequested;
import eu.jsentinel.jcustos.audit.EmailVerified;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.PasswordResetCompleted;
import eu.jsentinel.jcustos.audit.PasswordResetRequested;
import eu.jsentinel.jcustos.audit.PolicyEvaluated;
import eu.jsentinel.jcustos.audit.RateLimitExceeded;
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.audit.StepUpChallenged;
import eu.jsentinel.jcustos.audit.LogoutPerformed;
import eu.jsentinel.jcustos.audit.RoleAssigned;
import eu.jsentinel.jcustos.audit.RoleRevoked;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.SessionCreated;
import eu.jsentinel.jcustos.audit.SessionExpired;
import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.audit.SessionStale;
import eu.jsentinel.jcustos.audit.TokenRotated;
import eu.jsentinel.jcustos.audit.UserCreated;
import eu.jsentinel.jcustos.audit.UserDeleted;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.demo.restclient.views.MainView;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.combobox.ComboBox;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.router.Route;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Standalone Vaadin route showing the Vaadin shell's local in-memory ring
 * buffer of audit events. Restricted at view level by
 * {@link RequiresPermission @RequiresPermission("audit:read")}. The
 * permission is granted by the backend (demo-rest) to {@code ROLE_ADMIN}
 * and arrives on the {@code RemoteUser} snapshot at login time.
 * <p>
 * The events shown here are the Vaadin shell's own audit stream (login,
 * navigation, session, action) — not the backend's. To inspect the
 * backend's audit log, the corresponding {@code demo-vaadin} application
 * runs the same view against its own ring buffer.
 */
@Route(AuditView.NAV)
@RequiresPermission("audit:read")
public class AuditView extends Composite<VerticalLayout> {

  public static final String NAV = "audit";

  private static final DateTimeFormatter TIMESTAMP =
      DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

  private static final List<Class<? extends AuditEvent>> EVENT_TYPES = List.of(
      LoginSucceeded.class, LoginFailed.class, LogoutPerformed.class,
      AccessGranted.class, AccessDenied.class, ActionDenied.class,
      BruteForceLimitReached.class,
      SessionCreated.class, SessionExpired.class, SessionInvalidated.class,
      RoleAssigned.class, RoleRevoked.class,
      UserCreated.class, UserDeleted.class,
      BootstrapAdminCreated.class, BootstrapTokenRejected.class);

  private final Grid<AuditEvent> grid = new Grid<>(AuditEvent.class, false);
  private final ComboBox<Class<? extends AuditEvent>> typeFilter = new ComboBox<>("Type");
  private final TextField subjectFilter = new TextField("Subject");
  private final Span rowCount = new Span();

  public AuditView() {
    VerticalLayout root = getContent();
    root.addClassName("audit-view");
    root.setSizeFull();
    root.setSpacing(false);
    root.getThemeList().add("spacing-s");

    root.add(new H1("Security audit log"));
    root.add(new Paragraph(
        "In-memory snapshot of the Vaadin shell's RingBufferAuditSink "
            + "(default capacity 256). Shows the locally-emitted events "
            + "(login/navigation/session/action). Backend audit lives in "
            + "the demo-rest process and would be queried there."));

    root.add(buildToolbar());
    root.add(grid);
    root.add(rowCount);
    root.setFlexGrow(1, grid);

    grid.setSizeFull();
    grid.setPageSize(50);
    grid.addColumn(e -> TIMESTAMP.format(e.timestamp()))
        .setHeader("Timestamp").setWidth("11em").setFlexGrow(0);
    grid.addColumn(e -> e.getClass().getSimpleName())
        .setHeader("Type").setWidth("16em").setFlexGrow(0);
    grid.addColumn(AuditView::subjectOf).setHeader("Subject").setWidth("14em").setFlexGrow(0);
    grid.addColumn(AuditView::summaryOf).setHeader("Detail").setFlexGrow(1);

    refresh();
  }

  private HorizontalLayout buildToolbar() {
    typeFilter.setItems(EVENT_TYPES);
    typeFilter.setItemLabelGenerator(Class::getSimpleName);
    typeFilter.setClearButtonVisible(true);
    typeFilter.addValueChangeListener(e -> refresh());

    subjectFilter.setPlaceholder("filter by subject id");
    subjectFilter.setClearButtonVisible(true);
    subjectFilter.addValueChangeListener(e -> refresh());

    Button refresh = new Button("Refresh", VaadinIcon.REFRESH.create(), e -> refresh());
    refresh.addThemeVariants(ButtonVariant.LUMO_TERTIARY);

    Button back = new Button("Back to home", VaadinIcon.HOME.create(),
        e -> UI.getCurrent().navigate(MainView.class));
    back.addThemeVariants(ButtonVariant.LUMO_TERTIARY);

    HorizontalLayout toolbar = new HorizontalLayout(typeFilter, subjectFilter, refresh, back);
    toolbar.setSpacing(true);
    return toolbar;
  }

  private void refresh() {
    JCustosAuditService audit = JCustosServiceResolver.securityAuditService();
    Class<? extends AuditEvent> selectedType = typeFilter.getValue();
    String subject = subjectFilter.getValue() == null ? null : subjectFilter.getValue().trim();
    if (subject != null && subject.isEmpty()) {
      subject = null;
    }
    AuditQuery query = new AuditQuery(
        selectedType == null ? Set.of() : Set.of(selectedType),
        subject, null, null, 0);

    List<AuditEvent> events = audit.query(query);
    List<AuditEvent> reversed = new ArrayList<>(events);
    Collections.reverse(reversed);
    grid.setItems(reversed);
    rowCount.setText("Showing " + reversed.size() + " event(s).");
  }

  private static String subjectOf(AuditEvent event) {
    return switch (event) {
      case AccessGranted e -> nullToDash(e.subjectId());
      case AccessDenied e -> nullToDash(e.subjectId());
      case ActionDenied e -> nullToDash(e.subjectId());
      case LogoutPerformed e -> e.subjectId();
      case SessionCreated e -> e.subjectId();
      case SessionExpired e -> e.subjectId();
      case SessionInvalidated e -> e.subjectId();
      case SessionStale e -> e.subjectId();
      case RoleAssigned e -> e.subjectId();
      case RoleRevoked e -> e.subjectId();
      case LoginSucceeded e -> e.username();
      case LoginFailed e -> e.username();
      case BruteForceLimitReached e -> e.username();
      case BootstrapAdminCreated e -> e.username();
      case BootstrapTokenRejected ignored -> "—";
      case UserCreated e -> e.username();
      case UserDeleted e -> e.username();
      case PolicyEvaluated e -> nullToDash(e.subjectId());
      case StepUpChallenged e -> nullToDash(e.subjectId());
      case PasswordResetRequested e -> e.subjectId();
      case PasswordResetCompleted e -> e.subjectId();
      case EmailVerificationRequested e -> e.subjectId();
      case EmailVerified e -> e.subjectId();
      case ApiKeyUsed e -> e.subjectId();
      case ApiKeyDenied e -> nullToDash(e.subjectId());
      case TokenRotated e -> e.subjectId();
      case RateLimitExceeded e -> nullToDash(e.subjectId());
      case eu.jsentinel.jcustos.audit.CredentialVerificationSucceeded e -> e.username();
      case eu.jsentinel.jcustos.audit.CredentialVerificationFailed e -> e.username();
      case eu.jsentinel.jcustos.audit.CredentialRehashed e -> e.username();
      case eu.jsentinel.jcustos.audit.CredentialStatusChanged e -> e.username();
    };
  }

  private static String summaryOf(AuditEvent event) {
    return switch (event) {
      case AccessGranted e -> "route=" + nullToDash(e.route());
      case AccessDenied e -> "route=" + nullToDash(e.route())
          + " reason=" + nullToDash(e.reason());
      case ActionDenied e -> "action=" + e.action();
      case LogoutPerformed e -> "scope=" + e.scope().name()
          + " session=" + sessionRef(e.sessionId());
      case SessionCreated e -> "session=" + sessionRef(e.sessionId());
      case SessionExpired e -> "session=" + sessionRef(e.sessionId())
          + " reason=" + e.reason();
      case SessionInvalidated e -> "session=" + sessionRef(e.sessionId())
          + " reason=" + e.reason();
      case RoleAssigned e -> "role=" + e.role() + " by=" + nullToDash(e.assignedBy());
      case RoleRevoked e -> "role=" + e.role() + " by=" + nullToDash(e.revokedBy());
      case LoginSucceeded e -> "client=" + nullToDash(e.clientAddress())
          + " session=" + sessionRef(e.sessionId());
      case LoginFailed e -> "client=" + nullToDash(e.clientAddress())
          + " reason=" + nullToDash(e.reason());
      case BruteForceLimitReached e -> "client=" + nullToDash(e.clientAddress())
          + " failures=" + e.failedAttempts()
          + " lockoutSeconds=" + e.lockoutDuration().toSeconds();
      case BootstrapAdminCreated e -> "client=" + nullToDash(e.clientAddress());
      case BootstrapTokenRejected e -> "reason=" + e.reason()
          + " client=" + nullToDash(e.clientAddress());
      case UserCreated e -> "role=" + nullToDash(e.role())
          + " by=" + nullToDash(e.createdBy());
      case UserDeleted e -> "by=" + nullToDash(e.deletedBy());
      case PolicyEvaluated e -> "policy=" + e.policyName()
          + " decision=" + e.decision()
          + " reason=" + nullToDash(e.reason());
      case StepUpChallenged e -> "route=" + nullToDash(e.route())
          + " method=" + e.method()
          + " reason=" + nullToDash(e.reason());
      case SessionStale e -> "session=" + sessionRef(e.sessionId())
          + " route=" + nullToDash(e.route())
          + " snapshot=" + e.snapshotVersion()
          + " current=" + e.currentVersion();
      case PasswordResetRequested e -> "tokenHash=" + e.tokenHash();
      case PasswordResetCompleted e -> "tokenHash=" + e.tokenHash();
      case EmailVerificationRequested e -> "email=" + e.email()
          + " tokenHash=" + e.tokenHash();
      case EmailVerified e -> "email=" + e.email()
          + " tokenHash=" + e.tokenHash();
      case ApiKeyUsed e -> "key=" + e.keyName()
          + " keyHash=" + e.keyHash();
      case ApiKeyDenied e -> "keyHash=" + e.keyHash()
          + " reason=" + e.reason();
      case TokenRotated e -> "oldHash=" + e.oldHash()
          + " newHash=" + e.newHash();
      case RateLimitExceeded e -> "scope=" + e.scope()
          + " limit=" + e.limit()
          + " windowSeconds=" + e.window().toSeconds()
          + " events=" + e.eventsInWindow();
      case eu.jsentinel.jcustos.audit.CredentialVerificationSucceeded e ->
          "alg=" + e.algorithm()
              + " prov=" + e.providerId()
              + " pol=" + e.policyVersion()
              + " peppered=" + e.pepperKeyIdPresent()
              + " rehash=" + e.rehashRequired();
      case eu.jsentinel.jcustos.audit.CredentialVerificationFailed e ->
          "internal=" + e.internalAuditEventType().name()
              + " client=" + nullToDash(e.clientAddress());
      case eu.jsentinel.jcustos.audit.CredentialRehashed e ->
          "from=" + e.fromAlgorithm()
              + " to=" + e.toAlgorithm()
              + " reason=" + e.reason().name()
              + " pol=" + e.targetPolicyVersion();
      case eu.jsentinel.jcustos.audit.CredentialStatusChanged e ->
          "from=" + e.fromStatus().name()
              + " to=" + e.toStatus().name()
              + " reason=" + nullToDash(e.reason());
    };
  }

  private static String nullToDash(String value) {
    return value == null ? "—" : value;
  }

  /** JS-SEC-117 (CWE-522): a session is shown by its reference, never by the session id. */
  private static String sessionRef(String sessionId) {
    return nullToDash(SessionRef.ofNullable(sessionId));
  }
}
