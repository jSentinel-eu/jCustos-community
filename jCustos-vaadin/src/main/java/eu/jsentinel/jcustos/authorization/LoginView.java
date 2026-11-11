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
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationUnavailableException;
import eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore;
import eu.jsentinel.jcustos.net.vaadin.VaadinClientAddress;
import eu.jsentinel.jcustos.session.SessionContext;
import eu.jsentinel.jcustos.session.SessionPolicy;
import eu.jsentinel.jcustos.session.vaadin.VaadinSessionRevocation;
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

import java.time.Instant;
import java.time.LocalDateTime;


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
 * <p>
 * <strong>Login throttling (JS-SEC-124, CWE-307).</strong> Since 00.84.00 the view
 * consults the registered {@link LoginAttemptPolicy} itself, with the complete protocol
 * of JS-SEC-123: {@link LoginAttemptPolicy#beforeAttempt beforeAttempt} before
 * {@link #checkCredentials()}, and exactly one report afterwards -
 * {@link LoginAttemptPolicy#confirmSuccess confirmSuccess},
 * {@link LoginAttemptPolicy#recordFailure recordFailure} or, when the check produced no
 * verdict, {@link LoginAttemptPolicy#abandonAttempt abandonAttempt}. The attempt is keyed
 * on {@link #username()} and on the client address of the registered
 * {@code ClientAddressResolver} ({@link VaadinClientAddress#current()}), never on
 * {@code getRemoteAddr()}. An application with this view and a plain
 * {@code AuthenticationService} is therefore throttled by the resolver's default policy
 * without writing a line for it. Until 00.84.00 the view called
 * {@code checkCredentials()} directly, and throttling existed only where the
 * {@code AuthenticationService} implemented it.
 * <p>
 * <strong>Do not consult the policy a second time.</strong> An
 * {@code AuthenticationService} (or a {@code checkCredentials()} override) that calls
 * the policy itself would reserve and count every attempt twice. Remove those calls, or
 * - when the service is shared with a login path that has no such view - keep them and
 * switch the view's part off by overriding {@link #throttleLoginAttempts()}.
 * <p>
 * After a successful {@link #checkCredentials()} the view runs
 * {@link LoginSessionRotation#afterLogin(LoginSessionRotation.RotationHook)}: the HTTP
 * session id is <em>always</em> rotated (session-fixation mitigation, secure by default —
 * JS-SEC-003 / CWE-384), the configured {@link SessionPolicy} observes the login with the id
 * that lives on (JS-SEC-060), the rotation is audited, {@link #onSessionRotated(String, String)}
 * is called and the security-version snapshot is recorded. Failures, a missing Vaadin
 * session or a missing SPI are logged and never block the login flow.
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

  /**
   * Audit reason of the {@code SessionInvalidated} event when a login is undone because the
   * {@link LoginAttemptPolicy} did not confirm it: the key was locked while the credentials
   * were being checked (JS-SEC-123), or the policy failed to answer.
   *
   * @since 00.84.00
   */
  public static final String REASON_LOGIN_NOT_CONFIRMED = "LoginNotConfirmed";

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
    try {
      attemptLogin();
    } finally {
      // whatever happened, the password does not stay in the field
      clearFields();
    }
  }

  private void attemptLogin() {
    // JS-SEC-124 (CWE-307): the view owns the throttle protocol; null = opted out.
    final LoginAttemptPolicy policy = throttleLoginAttempts()
        ? JCustosServiceResolver.loginAttemptPolicy()
        : null;
    final LoginAttemptContext attempt = policy == null
        ? null
        : LoginAttemptContext.now(username(), VaadinClientAddress.current().orElse(null), null);

    if (policy != null
        && policy.beforeAttempt(attempt) instanceof LoginAttemptDecision.LockedOut lockout) {
      // Denied before the check: nothing was reserved, so there is nothing to report back.
      logger().warn("Login was throttled .. {}", LocalDateTime.now());
      reactOnLockedOut(lockout);
      return;
    }

    boolean isValid;
    try {
      isValid = checkCredentials();
    } catch (CredentialVerificationUnavailableException unavailable) {
      // JS-SEC-126 (CWE-703): "could not verify" is not "wrong". The reservation is given
      // back, no failure is counted, and the user is told to try again.
      abandon(policy, attempt);
      logger().warn("Login could not be checked right now .. {}", LocalDateTime.now());
      reactOnVerificationUnavailable();
      return;
    } catch (RuntimeException noVerdict) {
      // Any other exception says nothing about the credentials either: release the
      // reservation (JS-SEC-123) and let Vaadin's error handler see the exception.
      abandon(policy, attempt);
      throw noVerdict;
    }

    if (!isValid) {
      if (policy != null) {
        policy.recordFailure(attempt);
      }
      logger().warn("Login was not accepted .. {}", LocalDateTime.now());
      reactOnFailedLogin();
      return;
    }

    if (policy != null) {
      // JS-SEC-123 (CWE-367, CWE-307): the key can have been locked while the credentials
      // were being checked. A correct password neither lifts that lockout nor passes it -
      // and checkCredentials() has already bound the subject, so the login is undone. A
      // policy that cannot answer is treated the same way: fail closed.
      LoginAttemptDecision confirmed;
      try {
        confirmed = policy.confirmSuccess(attempt);
      } catch (RuntimeException policyFailure) {
        undoLogin(attempt, "Login attempt policy failed while confirming the login");
        throw policyFailure;
      }
      if (confirmed instanceof LoginAttemptDecision.LockedOut lockout) {
        logger().warn("Login was refused, the key was locked during the check .. {}",
            LocalDateTime.now());
        undoLogin(attempt, "Locked out while the attempt was in flight");
        try {
          reactOnLockedOut(lockout);
        } catch (RuntimeException reactionFailure) {
          // The session of this UI has just been ended; a reaction that cannot render in it
          // must not turn the refusal into an error page.
          logger().warn("reactOnLockedOut failed after the login was undone: {}",
              reactionFailure.toString());
        }
        return;
      }
    }

    logger().info("Login was accepted .. {}", LocalDateTime.now());
    // JS-SEC-003 / JS-SEC-060 / JS-SEC-146 (CWE-384): the post-login sequence - session id
    // rotation, SessionPolicy.onLogin, rotation audit, onSessionRotated hook, security
    // version snapshot - lives in LoginSessionRotation, shared with the OAuth2 callback.
    // A rotation the transport refuses is logged there and the login continues.
    LoginSessionRotation.afterLogin(this::onSessionRotated);
    navigateToApp();
  }

  private static void abandon(LoginAttemptPolicy policy, LoginAttemptContext attempt) {
    if (policy == null) {
      return;
    }
    try {
      policy.abandonAttempt(attempt);
    } catch (RuntimeException policyFailure) {
      // The reservation lapses on its own; the exception of the check must not be replaced.
      HasLogger.staticLogger().warn("LoginAttemptPolicy.abandonAttempt failed: {}",
          policyFailure.toString());
    }
  }

  /**
   * Takes back what {@link #checkCredentials()} established for a login the policy refused
   * afterwards. The view cannot know what a subclass or its {@code AuthenticationService}
   * put into the session, so with a Vaadin session it ends that session - subject,
   * security-version snapshot and token credential cleared, {@code SessionInvalidated}
   * audited, HTTP session invalidated. Without one (a view driven outside a request) the
   * subject and the token credential are removed from their stores. A {@code LoginFailed}
   * event with {@code auditReason} records the refusal first - an
   * {@code AuthenticationService} that audits {@code LoginSucceeded} itself has already
   * written that event when the policy answers.
   */
  private void undoLogin(LoginAttemptContext attempt, String auditReason) {
    try {
      JCustosServiceResolver.securityAuditService().publish(new LoginFailed(
          Instant.now(), attempt.username() == null ? "" : attempt.username(),
          attempt.clientAddress(), auditReason));
    } catch (RuntimeException auditFailure) {
      // never keep a refused login alive because the audit sink failed
    }
    try {
      if (VaadinSessionRevocation.endCurrentSession(REASON_LOGIN_NOT_CONFIRMED)) {
        return;
      }
      Class<?> subjectType = JCustosServiceResolver
          .<Object, Object>authenticationService()
          .subjectType();
      if (subjectType != null) {
        SubjectStores.findSubjectStore()
            .ifPresent(store -> store.deleteCurrentSubject(subjectType));
      }
      JCustosServiceResolver.findTokenCredentialStore().ifPresent(TokenCredentialStore::clear);
    } catch (RuntimeException undoFailure) {
      logger().warn("A login refused by the LoginAttemptPolicy could not be undone "
          + "completely: {}", undoFailure.toString());
    }
  }

  /**
   * Whether this view consults the {@link LoginAttemptPolicy} around
   * {@link #checkCredentials()} (JS-SEC-124, CWE-307). The default is {@code true}.
   * <p>
   * Override it to return {@code false} only when the {@code AuthenticationService} behind
   * {@link #checkCredentials()} runs the protocol itself - {@code beforeAttempt}, then
   * exactly one of {@code confirmSuccess}, {@code recordFailure} or {@code abandonAttempt}
   * - for instance because the same service also answers a REST login. With both layers
   * active every attempt is reserved and counted twice. Returning {@code false} without
   * such a service leaves the login unthrottled.
   *
   * @return {@code true} when the view runs the throttle protocol
   * @since 00.84.00
   */
  protected boolean throttleLoginAttempts() {
    return true;
  }

  /**
   * Called instead of {@link #reactOnFailedLogin()} when the {@link LoginAttemptPolicy}
   * refused the attempt: before the credential check, or - rarely - after it, when the key
   * was locked while the check ran (the login is then undone). The credentials were not
   * evaluated, or their result does not count. The default delegates to
   * {@link #reactOnFailedLogin()}, so an existing view answers as it did when its
   * {@code AuthenticationService} returned {@code false} for a throttled attempt; override
   * it to tell the user how long the lockout lasts.
   *
   * @param lockout the lockout in force; never {@code null}
   * @since 00.84.00
   */
  protected void reactOnLockedOut(LoginAttemptDecision.LockedOut lockout) {
    reactOnFailedLogin();
  }

  /**
   * Called when {@link #checkCredentials()} threw
   * {@link CredentialVerificationUnavailableException}: the credentials could not be
   * checked right now (JS-SEC-126, CWE-703). Nothing was counted against the user. The
   * default delegates to {@link #reactOnFailedLogin()}; override it to say "try again in a
   * moment" instead of "credentials not accepted".
   *
   * @since 00.84.00
   */
  protected void reactOnVerificationUnavailable() {
    reactOnFailedLogin();
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

  // Package-private for direct testing of the id-derivation (R14): the
  // security-relevant logic — never leak subject.toString() into the audit
  // channel — lives in LoginSessionRotation since 00.84.00 and stays reachable
  // here for the existing tests.
  static String subjectIdOf(SessionContext<Object> context) {
    return LoginSessionRotation.subjectIdOf(context);
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
   * <p>
   * The view has asked the {@link LoginAttemptPolicy} before this method runs and reports
   * the outcome afterwards (JS-SEC-124); the implementation must not consult the policy
   * again, see {@link #throttleLoginAttempts()}. An implementation that cannot check the
   * credentials at all throws {@link CredentialVerificationUnavailableException} instead
   * of returning {@code false} (JS-SEC-126).
   *
   * @return {@code true} if the credentials are valid
   */
  public abstract boolean checkCredentials();
}
