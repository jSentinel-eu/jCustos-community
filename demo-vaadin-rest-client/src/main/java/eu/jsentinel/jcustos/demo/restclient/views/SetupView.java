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
package eu.jsentinel.jcustos.demo.restclient.views;

import eu.jsentinel.jcustos.demo.restclient.backend.BackendClientProvider;
import eu.jsentinel.jcustos.demo.restclient.backend.BootstrapAdminRequest;
import eu.jsentinel.jcustos.demo.restclient.backend.BootstrapResult;
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

import java.util.Arrays;

/**
 * Initial-administrator setup. Calls {@code POST /api/bootstrap/admin}
 * via {@link BackendClientProvider} — the REST backend stays
 * authoritative.
 */
@PublicRoute
@Route(SetupView.NAV)
public class SetupView extends Composite<Div> implements BeforeEnterObserver {

  public static final String NAV = "setup";

  private final PasswordField tokenField = new PasswordField("Bootstrap token");
  private final TextField usernameField = new TextField("Admin username");
  private final PasswordField passwordField = new PasswordField("New password");
  private final PasswordField confirmField = new PasswordField("Repeat password");
  private final TextField displayNameField = new TextField("Display name (optional)");
  private final TextField emailField = new TextField("Email (optional)");

  public SetupView() {
    H2 heading = new H2("Initial administrator setup");
    Paragraph hint = new Paragraph(
        "The backend prints a bootstrap token to its console (transient mode) "
            + "or stores it in a token file (persistent mode). Use it once to "
            + "create the first administrator. The token is not the admin "
            + "password; you will choose the password below.");

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
    try {
      if (!BackendClientProvider.client().bootstrapStatus().bootstrapRequired()) {
        event.forwardTo(MyLoginView.class);
      }
    } catch (RuntimeException ex) {
      Notification.show("Backend unreachable — retry later.", 4000,
          Notification.Position.BOTTOM_END)
          .addThemeVariants(NotificationVariant.LUMO_ERROR);
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
    char[] pwd = password.toCharArray();
    BootstrapResult result;
    try {
      result = BackendClientProvider.client().createInitialAdmin(new BootstrapAdminRequest(
          token, username, pwd,
          blankToNull(displayNameField.getValue()),
          blankToNull(emailField.getValue())));
    } finally {
      Arrays.fill(pwd, '\0');
      tokenField.clear();
      passwordField.clear();
      confirmField.clear();
    }

    switch (result) {
      case BootstrapResult.Created created -> {
        success("Administrator '" + created.username() + "' created. Please log in.");
        UI.getCurrent().navigate(MyLoginView.class);
      }
      case BootstrapResult.AlreadyInitialized ignored -> {
        info("System already initialized — redirecting to login.");
        UI.getCurrent().navigate(MyLoginView.class);
      }
      case BootstrapResult.InvalidToken ignored -> error("Bootstrap token rejected.");
      case BootstrapResult.PolicyViolation policy ->
          error(policy.reason() == null || policy.reason().isBlank()
              ? "Password rejected by policy."
              : policy.reason());
      case BootstrapResult.InvalidUsername invalid ->
          error(invalid.reason() == null || invalid.reason().isBlank()
              ? "Invalid username."
              : invalid.reason());
      case BootstrapResult.TransportError t ->
          error("Backend unreachable: " + t.message());
      case BootstrapResult.InternalError t ->
          error("Backend reported an internal error: " + t.message());
    }
  }

  private static String blankToNull(String value) {
    return value == null || value.isBlank() ? null : value;
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
