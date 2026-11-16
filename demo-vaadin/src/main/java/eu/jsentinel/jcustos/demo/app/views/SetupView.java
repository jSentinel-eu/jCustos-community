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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bootstrap.CreateInitialAdminCommand;
import eu.jsentinel.jcustos.bootstrap.InitialAdminCreationResult;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordChecker;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordResult;
import eu.jsentinel.jcustos.credential.compromised.LocalBlocklistCompromisedPasswordChecker;
import eu.jsentinel.jcustos.credential.input.ContextAwarePasswordValidator;
import eu.jsentinel.jcustos.credential.input.PasswordContext;
import eu.jsentinel.jcustos.credential.input.PasswordInputPolicy;
import eu.jsentinel.jcustos.credential.input.PasswordInputValidationResult;
import eu.jsentinel.jcustos.credential.input.PasswordInputViolation;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.demo.app.security.bootstrap.BootstrapWiring;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationVariant;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterObserver;
import com.vaadin.flow.router.Route;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;

import java.util.List;
import java.util.Set;

/**
 * Initial administrator setup view.
 * <p>
 * Visible only while the system is uninitialized. After successful setup,
 * navigates to the login view; subsequent attempts to open {@code /setup}
 * are redirected to {@code /login}.
 */
@PublicRoute
@Route(SetupView.NAV)
public class SetupView extends Composite<Div> implements BeforeEnterObserver {

  public static final String NAV = "setup";

  private static final ContextAwarePasswordValidator INPUT_VALIDATOR =
      new ContextAwarePasswordValidator();
  private static final PasswordInputPolicy INPUT_POLICY =
      PasswordInputPolicy.defaults();
  private static final CompromisedPasswordChecker COMPROMISED_CHECKER =
      new LocalBlocklistCompromisedPasswordChecker(List.of(
          "password", "password1", "password123",
          "qwerty", "qwerty123", "letmein",
          "admin", "admin123", "administrator",
          "welcome", "welcome1",
          "12345678", "123456789", "abc12345",
          "iloveyou", "monkey", "dragon",
          "hunter2", "trustno1"));

  private final PasswordField tokenField = new PasswordField("Bootstrap token");
  private final TextField usernameField = new TextField("Admin username");
  private final PasswordField passwordField = new PasswordField("New password");
  private final PasswordField confirmField = new PasswordField("Repeat password");
  private final TextField displayNameField = new TextField("Display name (optional)");
  private final TextField emailField = new TextField("Email (optional)");

  public SetupView() {
    H2 heading = new H2("Initial administrator setup");
    Paragraph hint = new Paragraph(
        "The bootstrap token is shown on the server console (transient mode) or "
            + "stored in the configured token file (persistent mode). The token "
            + "authorizes the one-time creation of the first administrator. It "
            + "is not the administrator password.");

    tokenField.setWidthFull();
    usernameField.setWidthFull();
    usernameField.setValue("admin");
    passwordField.setWidthFull();
    confirmField.setWidthFull();
    displayNameField.setWidthFull();
    emailField.setWidthFull();

    Button submit = new Button("Create administrator", e -> submit());
    submit.addThemeVariants(ButtonVariant.LUMO_PRIMARY);

    VerticalLayout form = new VerticalLayout(
        heading, hint,
        tokenField, usernameField,
        passwordField, confirmField,
        displayNameField, emailField,
        submit);
    form.setMaxWidth("520px");
    form.addClassName("setup-view");
    getContent().add(form);
  }

  @Override
  public void beforeEnter(BeforeEnterEvent event) {
    if (!BootstrapWiring.instance().stateService().bootstrapRequired()) {
      event.forwardTo(MyLoginView.class);
    }
  }

  private void submit() {
    String token = tokenField.getValue();
    String username = usernameField.getValue();
    String password = passwordField.getValue();
    String confirm = confirmField.getValue();
    if (token == null || token.isBlank() || username == null || username.isBlank()
        || password == null || password.isEmpty()) {
      error("Token, username and password are required.");
      return;
    }
    if (!password.equals(confirm)) {
      error("Passwords do not match.");
      return;
    }

    // V00.71 pre-flight: structural + context-aware input validation,
    // followed by a local compromised-password blocklist check. The
    // framework's bootstrap policy still runs after this — the demo
    // simply gives the operator faster, more specific feedback before
    // the bootstrap token is consumed.
    PasswordContext context = PasswordContext.fromEmail(
        username, emailField.getValue(), TenantId.DEFAULT, Set.of());
    PasswordInputValidationResult inputResult = INPUT_VALIDATOR.validate(
        SecretValue.ofString(password), INPUT_POLICY, context);
    if (inputResult instanceof PasswordInputValidationResult.Rejected(
        PasswordInputViolation violation
    )) {
      error("Password rejected: " + humanise(violation.name()));
      return;
    }
    CompromisedPasswordResult cpResult = COMPROMISED_CHECKER.check(
        SecretValue.ofString(password));
    if (cpResult instanceof CompromisedPasswordResult.Pwned) {
      // Generic message — CWE-209 — never name the dictionary.
      error("Password rejected: this password is on a known-bad list. Choose another.");
      return;
    }

    char[] pwd = password.toCharArray();
    InitialAdminCreationResult result = BootstrapWiring.instance().bootstrapService()
        .createInitialAdmin(new CreateInitialAdminCommand(
            token, username, pwd,
            blankToNull(displayNameField.getValue()),
            blankToNull(emailField.getValue())));
    // Drop the token reference from the form before any further UI update
    tokenField.clear();
    passwordField.clear();
    confirmField.clear();

    switch (result) {
      case InitialAdminCreationResult.Created created -> {
        success("Administrator '" + created.username() + "' created. You can now log in.");
        UI.getCurrent().navigate(MyLoginView.class);
      }
      case InitialAdminCreationResult.AlreadyInitialized ignored -> {
        info("System already initialized — redirecting to login.");
        UI.getCurrent().navigate(MyLoginView.class);
      }
      case InitialAdminCreationResult.InvalidBootstrapToken ignored -> error("Bootstrap token rejected.");
      case InitialAdminCreationResult.PasswordPolicyViolation policy ->
          error(policy.reason() == null ? "Password rejected by policy." : policy.reason());
      case InitialAdminCreationResult.InvalidUsername invalid ->
          error(invalid.reason() == null ? "Invalid username." : invalid.reason());
      case InitialAdminCreationResult.InternalError ignored ->
          error("Internal error during setup. Please retry.");
    }
  }

  private static String blankToNull(String value) {
    return value == null || value.isBlank() ? null : value;
  }

  private static String humanise(String violation) {
    return violation.toLowerCase().replace('_', ' ');
  }

  private static void success(String message) {
    Notification n = Notification.show(message, 3000, Notification.Position.BOTTOM_END);
    n.addThemeVariants(NotificationVariant.LUMO_SUCCESS);
  }

  private static void info(String message) {
    Notification.show(message, 3000, Notification.Position.BOTTOM_END);
  }

  private static void error(String message) {
    Notification n = Notification.show(message, 4000, Notification.Position.BOTTOM_END);
    n.addThemeVariants(NotificationVariant.LUMO_ERROR);
  }
}