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
package eu.jsentinel.jcustos.authorization;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.net.vaadin.VaadinClientAddress;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.JCustosVersionStore;
import eu.jsentinel.jcustos.session.SessionContext;
import eu.jsentinel.jcustos.session.SessionDecision;
import eu.jsentinel.jcustos.session.SessionPolicy;
import eu.jsentinel.jcustos.session.vaadin.VaadinJCustosVersionContext;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.checkbox.Checkbox;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.Autocomplete;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinService;
import com.vaadin.flow.server.VaadinServletRequest;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.WrappedSession;
import jakarta.servlet.http.HttpServletRequest;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;


/**
 * Abstract base class for login views.
 * <p>
 * Provides a pre-built login form with username, password, remember-me
 * checkbox, and sign-in / clear buttons. Subclasses implement the three
 * abstract methods to wire credential checking, navigation after login,
 * and error handling.
 * <p>
 * The form can be extended with custom UI elements via
 * {@link #setCustomElements(Component)}.
 */
public abstract class LoginView
    extends Composite<HorizontalLayout>
    implements HasLogger {

  /** Test ID for the login button. */
  public static final String BTN_LOGIN_ID      = "loginview-btn-login";
  /** Test ID for the cancel/clear button. */
  public static final String BTN_CANCEL_ID     = "loginview-btn-cancel";
  /** Test ID for the username field. */
  public static final String TF_USERNAME_ID    = "loginview-tf-username";
  /** Test ID for the password field. */
  public static final String PF_PASSWORD_ID    = "loginview-pf-password";
  /** Test ID for the remember-me checkbox. */
  public static final String CB_REMEMBER_ME_ID = "loginview-cb-remember-me";

  /** Form title heading. */
  private final H2 title = new H2("Sign In");

  /** Username input field. */
  private final TextField username = new TextField("Username") {{
    setId(TF_USERNAME_ID);
    setPlaceholder("Enter your username");
    setWidthFull();
    setAutocomplete(Autocomplete.USERNAME);
  }};

  /** Password input field. */
  private final PasswordField password = new PasswordField("Password") {{
    setId(PF_PASSWORD_ID);
    setRequired(true);
    setPlaceholder("Enter your password");
    setWidthFull();
  }};

  /** Container for custom elements added via {@link #setCustomElements(Component)}. */
  private final Div customElements = new Div();

  /** Remember-me checkbox. */
  private final Checkbox rememberMe = new Checkbox("Remember me") {{
    setId(CB_REMEMBER_ME_ID);
    setIndeterminate(false);
  }};

  /** Sign-in button that triggers credential validation. */
  private final Button btnLogin = new Button("Sign In") {{
    setId(BTN_LOGIN_ID);
    addThemeVariants(ButtonVariant.LUMO_PRIMARY, ButtonVariant.LUMO_LARGE);
    addClickListener(e -> validate());
    setWidthFull();
  }};

  /** Clear button that resets the form fields. */
  private final Button btnCancel = new Button("Clear") {{
    setId(BTN_CANCEL_ID);
    addThemeVariants(ButtonVariant.LUMO_TERTIARY);
    addClickListener(e -> clearFields());
    setWidthFull();
  }};

  /** Row containing the login and cancel buttons. */
  private final HorizontalLayout buttonRow = new HorizontalLayout(btnLogin, btnCancel) {{
    setWidthFull();
    setDefaultVerticalComponentAlignment(FlexComponent.Alignment.CENTER);
    expand(btnLogin);
  }};

  /** Card layout containing all form elements. */
  private final VerticalLayout card = new VerticalLayout(
      title, username, password, customElements, rememberMe, buttonRow) {{
    addClassName("login-card");
    setAlignItems(Alignment.STRETCH);
    setWidth("22em");
    setPadding(true);
    setSpacing(false);
    getThemeList().add("spacing-s");
  }};

  /**
   * Assembles the login form layout.
   */
  public LoginView() {
    logger().info("setting now the login ui content..");
    final HorizontalLayout wrapper = getContent();
    wrapper.addClassName("login-view");
    wrapper.setDefaultVerticalComponentAlignment(FlexComponent.Alignment.CENTER);
    wrapper.setJustifyContentMode(FlexComponent.JustifyContentMode.CENTER);
    wrapper.add(card);
    wrapper.setSizeFull();
  }

  private void clearFields() {
    username.clear();
    password.clear();
  }

  /**
   * Returns the current value of the username field.
   *
   * @return the entered username
   */
  public String username() {
    return username.getValue();
  }

  /**
   * Returns the current value of the password field.
   *
   * @return the entered password
   */
  public String password() {
    return password.getValue();
  }

  private void validate() {
    boolean isValid = checkCredentials();
    if (isValid) {
      logger().info("Login was accepted .. {}", LocalDateTime.now());
      notifyOnLogin();
      captureJCustosVersionSnapshot();
      navigateToApp();
    } else {
      logger().warn("Login was not accepted .. {}", LocalDateTime.now());
      reactOnFailedLogin();
    }
    clearFields();
  }

  /**
   * JS-SEC-027: warns once (not per login) when a JCustosVersionStore is
   * registered but no SubjectIdResolver is resolvable, so drift detection is
   * silently inert.
   */
  private static final java.util.concurrent.atomic.AtomicBoolean DRIFT_INERT_WARNED =
      new java.util.concurrent.atomic.AtomicBoolean(false);

  /**
   * Phase 4c-Followup: best-effort capture of the
   * {@link JCustosVersion} snapshot into
   * {@link VaadinJCustosVersionContext} so the
   * {@code JCustosVersionEnforcerListener} can detect drift on
   * subsequent requests.
   * <p>
   * Fires after {@link #notifyOnLogin()} so any session rotation
   * has already happened and the recorded {@code sessionId}
   * matches the new servlet session. The capture is a strict
   * three-way no-op when any prerequisite is missing:
   * <ol>
   *   <li>No SPI-registered {@link JCustosVersionStore} (Phase 4a
   *       not wired) — skip.</li>
   *   <li>No SPI-registered {@link SubjectIdResolver} — the
   *       framework cannot derive a {@link SubjectId} from the
   *       application's typed user, so skip.</li>
   *   <li>No active Vaadin session / no current subject — skip.</li>
   * </ol>
   * Any exception thrown by the resolver, the store, or
   * {@link VaadinJCustosVersionContext#record} is swallowed —
   * snapshot capture must never block the login flow.
   */
  @SuppressWarnings({"unchecked", "rawtypes"})
  private void captureJCustosVersionSnapshot() {
    try {
      Optional<JCustosVersionStore> storeOpt = JCustosServiceResolver.findJCustosVersionStore();
      if (storeOpt.isEmpty()) {
        return;
      }
      Optional<SubjectIdResolver<Object>> resolverOpt =
          JCustosServiceResolver.findSubjectIdResolver();
      if (resolverOpt.isEmpty()) {
        // JS-SEC-027 (CWE-636): a version store is registered but no
        // SubjectIdResolver — the snapshot is never captured, so the drift
        // enforcer no-ops on every navigation (mid-session revocation is silently
        // not enforced). Warn once so a manual-SPI integrator gets a runtime
        // signal (the DX bootstrap fails this as a STRICT/ERROR diagnostic).
        if (DRIFT_INERT_WARNED.compareAndSet(false, true)) {
          logger().warn("JCustosVersion drift detection is inert: a JCustosVersionStore "
              + "is registered but no SubjectIdResolver is resolvable, so no login snapshot is "
              + "captured and mid-session role/permission revocation will not be enforced. "
              + "Register a SubjectIdResolver.");
        }
        return;
      }
      Object subject = currentSubject().orElse(null);
      if (subject == null) {
        return;
      }
      VaadinSession session = VaadinSession.getCurrent();
      if (session == null) {
        return;
      }
      SubjectIdResolver<Object> resolver = resolverOpt.get();
      SubjectId subjectId = resolver.resolve(subject);
      TenantId tenant = resolver.tenantFor(subject);
      JCustosVersion snapshot = storeOpt.get()
          .current(new JCustosVersionKey(tenant, subjectId));
      WrappedSession wrapped = session.getSession();
      String sessionId = wrapped == null ? null : wrapped.getId();
      VaadinJCustosVersionContext.record(session, subjectId, tenant, snapshot, sessionId);
    } catch (RuntimeException captureFailure) {
      logger().warn("JCustosVersion snapshot capture failed: {}", captureFailure.toString());
    }
  }

  /**
   * Best-effort notification of {@link SessionPolicy#onLogin(SessionContext)}.
   * <p>
   * Fires after a successful {@link #checkCredentials()}. It <em>always</em>
   * rotates the HTTP session id first (session-fixation mitigation,
   * secure-by-default — JS-SEC-003 / CWE-384) and only then lets the
   * configured {@link SessionPolicy} observe the login, so every observer —
   * the policy's {@code SessionCreated} event, the {@code JCustosVersion}
   * snapshot and any {@code SessionStore} record created in
   * {@link #onSessionRotated(String, String)} — sees the id that lives on
   * (JS-SEC-060). Failures, a missing Vaadin session, or a missing SPI are
   * silently absorbed — the lifecycle hook must never block the login flow.
   * <p>
   * Rotation goes through {@code HttpServletRequest.changeSessionId()} on
   * the current {@link VaadinServletRequest}: the servlet session object and
   * with it the {@link VaadinSession}, the just-bound subject and every other
   * attribute stay in place; only the id changes. Non-servlet transports fall
   * back to {@link VaadinService#reinitializeSession(VaadinRequest)}. A
   * {@code SessionInvalidated} audit event is emitted for the <em>old</em>
   * session id after the policy ran; when the policy returns
   * {@link SessionDecision.Invalidate Invalidate} its {@code reason} is used,
   * otherwise the default {@code "RotationAfterLogin"} reason is recorded. The
   * {@code loginRoute} of an {@code Invalidate} decision is deliberately
   * ignored in the post-login context: the user proceeds to
   * {@link #navigateToApp()} on the rotated session. Invalidation
   * <em>from {@code beforeNavigation}</em> (session expired) follows a
   * different code path and uses {@code loginRoute} as written.
   */
  private void notifyOnLogin() {
    try {
      SessionPolicy<Object> policy = JCustosServiceResolver.sessionPolicy();
      Optional<SessionContext<Object>> beforeRotation = buildSessionContext();
      if (beforeRotation.isEmpty()) {
        return;
      }
      String previousSessionId = beforeRotation.get().sessionId();
      // JS-SEC-003 / JS-SEC-060 (CWE-384): rotate the HTTP session id on every
      // successful login, independently of the SessionPolicy decision, and do
      // it before the policy runs so SessionCreated names the surviving id.
      boolean rotated = rotateSessionId();
      SessionContext<Object> context = rotated
          ? buildSessionContext().orElse(beforeRotation.get())
          : beforeRotation.get();
      SessionDecision decision = policy.onLogin(context);
      String reason = decision instanceof SessionDecision.Invalidate invalidate
          ? invalidate.reason()
          : "RotationAfterLogin";
      if (rotated) {
        auditRotation(context, previousSessionId, reason);
        notifySessionRotated(previousSessionId, context.sessionId());
      }
    } catch (RuntimeException notifyFailure) {
      logger().warn("SessionPolicy.onLogin notification failed: {}", notifyFailure.toString());
    }
  }

  /**
   * Rotates the underlying HTTP session id while preserving the
   * {@link VaadinSession} (and therefore the just-bound subject). Standard
   * session-fixation mitigation: callers that pass credentials over a
   * pre-existing session id cannot replay the post-login session because
   * the id changes here.
   *
   * @return {@code true} when the id was rotated, {@code false} when no
   *         request is bound or the container refused
   */
  private boolean rotateSessionId() {
    VaadinRequest request = VaadinRequest.getCurrent();
    if (request == null) {
      return false;
    }
    try {
      if (request instanceof VaadinServletRequest servletRequest) {
        HttpServletRequest http = servletRequest.getHttpServletRequest();
        http.changeSessionId();
        return true;
      }
      // Non-servlet transport: the legacy path copies the attributes into a
      // fresh session. Deprecated for removal from Flow 25.4, kept only here.
      VaadinService.reinitializeSession(request);
      return true;
    } catch (RuntimeException rotationFailure) {
      logger().warn("Session id rotation after login failed: {}", rotationFailure.toString());
      return false;
    }
  }

  private void notifySessionRotated(String previousSessionId, String currentSessionId) {
    try {
      onSessionRotated(previousSessionId, currentSessionId);
    } catch (RuntimeException hookFailure) {
      logger().warn("onSessionRotated hook failed: {}", hookFailure.toString());
    }
  }

  /**
   * Called once per successful login after the HTTP session id has rotated,
   * with the id the session had before and the id it carries now
   * (JS-SEC-060, CWE-384). Override it to create or re-key anything that is
   * keyed by the session id — a {@code SessionStore} record for the session
   * inventory, a {@code SubjectSessionRegistry} entry, an external
   * correlation — so revocation by id reaches the live session. Records
   * written inside {@link #checkCredentials()} carry the pre-rotation id and
   * must be moved here, for example with {@code SessionStore.rekey(old, new)}.
   * <p>
   * Runs after the {@link SessionPolicy} observed the login and after the
   * rotation was audited; it is not called when no rotation took place.
   * Exceptions are logged and never block the login flow. The default does
   * nothing.
   *
   * @param previousSessionId the id before rotation (may be {@code null} when
   *                          the transport exposed none)
   * @param currentSessionId  the surviving id
   * @since 00.84.00
   */
  protected void onSessionRotated(String previousSessionId, String currentSessionId) {
    // default: nothing to re-key
  }

  private void auditRotation(SessionContext<Object> context, String oldSessionId, String reason) {
    try {
      JCustosAuditService sink = JCustosServiceResolver.securityAuditService();
      sink.publish(new SessionInvalidated(
          Instant.now(),
          subjectIdOf(context),
          oldSessionId,
          reason == null ? "RotationAfterLogin" : reason));
    } catch (RuntimeException auditFailure) {
      // never block login because the audit sink failed
    }
  }

  // Package-private for direct testing of the id-derivation (R14): the
  // auditRotation() path itself needs a live Vaadin session, so the
  // security-relevant logic — never leak subject.toString() — is unit-tested
  // here in isolation.
  static String subjectIdOf(SessionContext<Object> context) {
    Object subject = context.subject();
    if (subject == null) {
      return "";
    }
    // R14 (V00.76.10): never publish subject.toString() as the audit subject id.
    // An application user object's toString() commonly serialises email / hash /
    // internal ids into the audit channel — the leak class R019 / R020-R021
    // closed on the REST / StepUp / policy paths. Derive a stable id via the
    // registered SubjectIdResolver (the same resolver the JCustosVersion
    // snapshot path uses), falling back to a non-PII empty id when none is
    // registered (audit attribution requires a resolver by design).
    Optional<SubjectIdResolver<Object>> resolver =
        JCustosServiceResolver.findSubjectIdResolver();
    return resolver.map(r -> r.resolve(subject).value()).orElse("");
  }

  /**
   * Builds a {@link SessionContext} from the current Vaadin runtime —
   * subject (best-effort, looked up via the active
   * {@link SubjectStore} keyed on the application's subject type),
   * sessionId + createdAt from the {@link WrappedSession}, lastActivity
   * = createdAt for a fresh login, clientAddress from the
   * {@link VaadinRequest}.
   *
   * @return populated context, or empty when no Vaadin session is bound
   */
  private static Optional<SessionContext<Object>> buildSessionContext() {
    VaadinSession vaadin = VaadinSession.getCurrent();
    if (vaadin == null) {
      return Optional.empty();
    }
    WrappedSession wrapped = vaadin.getSession();
    Instant createdAt = wrapped == null
        ? Instant.now()
        : Instant.ofEpochMilli(wrapped.getCreationTime());
    String sessionId = wrapped == null ? null : wrapped.getId();
    String clientAddress = currentClientAddress();
    Object subject = currentSubject().orElse(null);
    return Optional.of(new SessionContext<>(
        subject, sessionId, createdAt, createdAt, clientAddress, Map.of()));
  }

  private static Optional<Object> currentSubject() {
    try {
      Class<?> subjectType = JCustosServiceResolver
          .<Object, Object>authenticationService()
          .subjectType();
      if (subjectType == null) {
        return Optional.empty();
      }
      SubjectStore store = SubjectStores.findSubjectStore().orElse(null);
      if (store == null) {
        return Optional.empty();
      }
      @SuppressWarnings({"rawtypes", "unchecked"})
      Class raw = subjectType;
      return store.currentSubject(raw).map(value -> (Object) value);
    } catch (RuntimeException ignored) {
      return Optional.empty();
    }
  }

  /**
   * JS-SEC-061 (CWE-348): the client address comes from the registered
   * {@code ClientAddressResolver}, never from {@code getRemoteAddr()} directly,
   * so a reverse-proxy deployment cannot be keyed on a forgeable header.
   */
  private static String currentClientAddress() {
    return VaadinClientAddress.current().orElse(null);
  }

  /**
   * Adds a custom UI component to the login form (below the password
   * field and above the remember-me checkbox).
   *
   * @param component the component to add
   */
  public void setCustomElements(Component component) {
    customElements.add(component);
  }

  /**
   * Removes all previously added custom elements from the login form.
   */
  public void clearCustomElements() {
    customElements.removeAll();
  }

  /**
   * Called when credential validation fails.
   * Implementations typically show a notification or close the session.
   */
  public abstract void reactOnFailedLogin();

  /**
   * Called after successful credential validation.
   * Implementations typically navigate to the main application view.
   */
  public abstract void navigateToApp();

  /**
   * Validates the credentials entered by the user.
   * Implementations should call
   * {@link eu.jsentinel.jcustos.authentication.AuthenticationService#checkCredentials(Object)}
   * and, on success, store the subject via the configured
   * {@link eu.jsentinel.jcustos.authorization.api.SubjectStore}.
   *
   * @return {@code true} if the credentials are valid
   */
  public abstract boolean checkCredentials();
}
