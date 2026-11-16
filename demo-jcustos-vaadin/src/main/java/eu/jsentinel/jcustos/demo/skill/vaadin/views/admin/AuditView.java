package eu.jsentinel.jcustos.demo.skill.vaadin.views.admin;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.LogoutPerformed;
import eu.jsentinel.jcustos.audit.RoleAssigned;
import eu.jsentinel.jcustos.audit.RoleRevoked;
import eu.jsentinel.jcustos.audit.SessionCreated;
import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.audit.UserCreated;
import eu.jsentinel.jcustos.audit.UserDeleted;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.combobox.ComboBox;
import com.vaadin.flow.component.datetimepicker.DateTimePicker;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.data.value.ValueChangeMode;
import com.vaadin.flow.router.Route;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.HomeButton;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.MainLayout;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Renders the in-memory audit ring buffer as a filterable grid.
 *
 * <p>The ring buffer was wired in
 * {@code JCustosBootstrapInitListener.audit(a -> a.ringBuffer(256).logging())}.
 * Every login, role change, session creation, etc. lands here.
 *
 * <p>Filter toolbar:
 * <ul>
 *   <li><b>Type</b> — pick one of the well-known {@link AuditEvent}
 *       variants; empty = all types.</li>
 *   <li><b>Subject</b> — substring match against the username /
 *       subject id of each event.</li>
 *   <li><b>From / To</b> — {@link DateTimePicker} bounds; converted to
 *       {@link Instant} via the system zone.</li>
 * </ul>
 *
 * <p>All four filters compose: every value-change triggers a fresh
 * {@link AuditQuery} against
 * {@link JCustosServiceResolver#securityAuditService()}.
 *
 * <p>Restricted by {@code @RequiresPermission("audit:read")} — only
 * subjects holding the permission can navigate to {@code /audit}.
 */
@Route(value = AuditView.NAV, layout = MainLayout.class)
@RequiresPermission("audit:read")
public class AuditView extends Composite<VerticalLayout> {

  public static final String NAV = "audit";

  /** Wall-clock zone for DateTimePicker ↔ Instant conversion. */
  private static final ZoneId ZONE = ZoneId.systemDefault();

  private static final DateTimeFormatter TIMESTAMP =
      DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZONE);

  /** Well-known AuditEvent variants offered in the Type filter. */
  private static final List<Class<? extends AuditEvent>> FILTERABLE_TYPES = List.of(
      LoginSucceeded.class, LoginFailed.class, LogoutPerformed.class,
      SessionCreated.class, SessionInvalidated.class,
      RoleAssigned.class, RoleRevoked.class,
      UserCreated.class, UserDeleted.class);

  private final Grid<AuditEvent> grid = new Grid<>(AuditEvent.class, false);
  private final Span rowCount = new Span();

  private final ComboBox<Class<? extends AuditEvent>> typeFilter = new ComboBox<>("Type");
  private final TextField subjectFilter = new TextField("Subject");
  private final DateTimePicker fromFilter = new DateTimePicker("From");
  private final DateTimePicker toFilter = new DateTimePicker("To");

  public AuditView() {
    VerticalLayout root = getContent();
    root.setSizeFull();
    root.setSpacing(false);
    root.getThemeList().add("spacing-s");

    root.add(new H1("Security audit log"));
    root.add(new Paragraph(
        "In-memory ring buffer from JCustosAuditService. "
            + "Use the toolbar to filter by event type, subject, and time window. "
            + "Restricted to subjects holding the audit:read permission."));

    root.add(buildToolbar());

    grid.setSizeFull();
    grid.setPageSize(50);
    grid.addColumn(e -> TIMESTAMP.format(e.timestamp()))
        .setHeader("Timestamp").setWidth("11em").setFlexGrow(0);
    grid.addColumn(e -> e.getClass().getSimpleName())
        .setHeader("Type").setWidth("16em").setFlexGrow(0);
    grid.addColumn(AuditView::subjectOf)
        .setHeader("Subject").setWidth("14em").setFlexGrow(0);
    grid.addColumn(AuditView::summaryOf)
        .setHeader("Detail").setFlexGrow(1);
    root.add(grid);
    root.add(rowCount);
    root.setFlexGrow(1, grid);

    refresh();
  }

  private HorizontalLayout buildToolbar() {
    typeFilter.setItems(FILTERABLE_TYPES);
    typeFilter.setItemLabelGenerator(Class::getSimpleName);
    typeFilter.setClearButtonVisible(true);
    typeFilter.addValueChangeListener(e -> refresh());

    subjectFilter.setPlaceholder("substring of subject / username");
    subjectFilter.setClearButtonVisible(true);
    subjectFilter.setValueChangeMode(ValueChangeMode.LAZY);
    subjectFilter.setValueChangeTimeout(300);
    subjectFilter.addValueChangeListener(e -> refresh());

    fromFilter.setStep(java.time.Duration.ofMinutes(1));
    fromFilter.addValueChangeListener(e -> refresh());
    toFilter.setStep(java.time.Duration.ofMinutes(1));
    toFilter.addValueChangeListener(e -> refresh());

    Button reset = new Button("Reset", VaadinIcon.CLOSE_SMALL.create(), e -> resetFilters());
    reset.addThemeVariants(ButtonVariant.LUMO_TERTIARY);

    Button refresh = new Button("Refresh", VaadinIcon.REFRESH.create(), e -> refresh());
    refresh.addThemeVariants(ButtonVariant.LUMO_TERTIARY);

    HorizontalLayout toolbar = new HorizontalLayout(
        typeFilter, subjectFilter, fromFilter, toFilter, reset, refresh);
    HomeButton.forStandalone(getClass()).ifPresent(toolbar::add);
    toolbar.setSpacing(true);
    toolbar.setDefaultVerticalComponentAlignment(FlexComponent.Alignment.END);
    toolbar.setWidthFull();
    return toolbar;
  }

  private void resetFilters() {
    typeFilter.clear();
    subjectFilter.clear();
    fromFilter.clear();
    toFilter.clear();
    // The four clear() calls each fire a value-change event, each of
    // which calls refresh(). The final state is consistent — we just
    // pay 4 redundant queries against an in-memory ring buffer, which
    // is fine.
  }

  /**
   * Builds a fresh {@link AuditQuery} from the current filter state and
   * pushes the result into the grid.
   *
   * <p>Subject substring matching is applied client-side because
   * {@link AuditQuery#subjectId()} is an exact match — the ring buffer
   * implementation does not understand substrings. For a persistent
   * store with millions of rows the right move is a custom
   * {@code AuditEventStore} query method; for the in-memory demo,
   * client-side filtering is adequate.
   */
  private void refresh() {
    JCustosAuditService audit = JCustosServiceResolver.securityAuditService();
    Class<? extends AuditEvent> selectedType = typeFilter.getValue();
    Set<Class<? extends AuditEvent>> types = selectedType == null
        ? Set.of()
        : Set.of(selectedType);
    Instant from = toInstant(fromFilter.getValue());
    Instant to = toInstant(toFilter.getValue());

    AuditQuery query = new AuditQuery(types, null, from, to, 0);
    List<AuditEvent> events = new ArrayList<>(audit.query(query));

    String subjectNeedle = trimToNull(subjectFilter.getValue());
    if (subjectNeedle != null) {
      String needle = subjectNeedle.toLowerCase();
      events.removeIf(event -> {
        String subject = subjectOf(event);
        return subject == null || !subject.toLowerCase().contains(needle);
      });
    }
    Collections.reverse(events); // newest first
    grid.setItems(events);
    rowCount.setText("Showing " + events.size() + " event(s).");
  }

  private static Instant toInstant(LocalDateTime value) {
    return value == null ? null : value.atZone(ZONE).toInstant();
  }

  private static String trimToNull(String value) {
    if (value == null) return null;
    String trimmed = value.trim();
    return trimmed.isEmpty() ? null : trimmed;
  }

  private static String subjectOf(AuditEvent event) {
    return switch (event) {
      case LoginSucceeded e -> e.username();
      case LoginFailed e -> e.username();
      case LogoutPerformed e -> e.subjectId();
      case SessionCreated e -> e.subjectId();
      case SessionInvalidated e -> e.subjectId();
      case RoleAssigned e -> e.subjectId();
      case RoleRevoked e -> e.subjectId();
      case UserCreated e -> e.username();
      case UserDeleted e -> e.username();
      default -> "—";
    };
  }

  private static String summaryOf(AuditEvent event) {
    return switch (event) {
      case LoginSucceeded e -> "client=" + nullToDash(e.clientAddress());
      case LoginFailed e -> "client=" + nullToDash(e.clientAddress())
          + " reason=" + nullToDash(e.reason());
      case LogoutPerformed e -> "scope=" + e.scope().name();
      case SessionCreated e -> "session=" + sessionRef(e.sessionId());
      case SessionInvalidated e -> "session=" + sessionRef(e.sessionId())
          + " reason=" + e.reason();
      case RoleAssigned e -> "role=" + e.role();
      case RoleRevoked e -> "role=" + e.role();
      case UserCreated e -> "role=" + nullToDash(e.role());
      case UserDeleted e -> "by=" + nullToDash(e.deletedBy());
      default -> event.toString();
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
