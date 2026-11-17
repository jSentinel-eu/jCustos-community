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
package eu.jsentinel.jcustos.starter.errors;

import eu.jsentinel.jcustos.authorization.api.AccessDeniedException;
import eu.jsentinel.jcustos.authorization.api.JCustosEnforcer;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import com.vaadin.browserless.internal.MockVaadin;
import com.vaadin.browserless.internal.Routes;
import com.vaadin.browserless.mocks.MockVaadinServlet;
import com.vaadin.browserless.mocks.MockedUI;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.HasElement;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.function.DeploymentConfiguration;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.ErrorParameter;
import com.vaadin.flow.router.HasErrorParameter;
import com.vaadin.flow.router.InternalServerError;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.DefaultErrorHandler;
import com.vaadin.flow.server.ErrorEvent;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinServletService;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.communication.ServerRpcHandler;
import com.vaadin.flow.shared.ApplicationConstants;
import com.vaadin.flow.shared.JsonConstants;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-067 (CWE-209): an error that escapes a click listener reaches the session's error
 * handler through Vaadin's own {@link ServerRpcHandler}; {@link JCustosErrorHandler} shows the
 * user a reference and nothing of the exception, and logs the stack trace under that
 * reference. The Vaadin service runs on the browserless servlet stand-ins; the handler is
 * installed the way an application installs it, through {@link JCustosErrorHandler#install}
 * at service init, so every session gets it from its {@code SessionInitListener}. No mocking
 * framework.
 * <p>
 * Log output is read from {@code System.err}, where slf4j-simple writes it.
 */
@DisplayName("JS-SEC-067 - an unhandled error shows a reference, the log carries the stack trace")
class JCustosErrorHandlerBrowserlessTest {

  private static final String SECRET = "pw-SECRET-4711";
  /** What a careless handler would show: SQL, a credential and an e-mail address. */
  private static final String LEAKY_MESSAGE =
      "UPDATE accounts SET password='" + SECRET + "' failed for alice@example.test";
  private static final Pattern LOGGED_REFERENCE =
      Pattern.compile("Unhandled error, reference ([A-Z2-7]{16})");
  private static final Pattern NESTED_REFERENCE = Pattern.compile(
      "Unhandled error while another error was being reported, reference ([A-Z2-7]{16})");
  /** The event data a browser sends with a click on a {@code Button}. */
  private static final String CLICK_EVENT_DATA = "{\"event.screenX\":0,\"event.screenY\":0,"
      + "\"event.clientX\":0,\"event.clientY\":0,\"event.detail\":1,\"event.button\":0,"
      + "\"event.ctrlKey\":false,\"event.shiftKey\":false,\"event.altKey\":false,"
      + "\"event.metaKey\":false}";

  /** Strong references: Vaadin's CurrentInstance holds session and UI weakly. */
  private VaadinSession session;
  private UI ui;

  @BeforeEach
  void start() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    // a real subject store and authentication service, nobody logged in: JCustosEnforcer
    // denies with an AccessDeniedException as it does in an application
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    JCustosServiceResolver.setAuthenticationService(
        FakeAuthenticationService.<String, String>forType(String.class));
    ActionView.failure = () -> {
      throw new IllegalStateException(LEAKY_MESSAGE);
    };
    AccessDeniedView.received.clear();
    startVaadin(true);
  }

  @AfterEach
  void stop() {
    try {
      MockVaadin.tearDown();
    } finally {
      JCustosServiceResolver.resetAll();
      SubjectStores.reset();
    }
  }

  // ── installation ───────────────────────────────────────────────

  @Test
  @DisplayName("install(...) sets the handler on every session; without it Vaadin's default stays")
  void install_setsTheHandlerOnEverySession() {
    assertInstanceOf(JCustosErrorHandler.class, session.getErrorHandler(),
        "the SessionInitListener registered by install(...) sets the handler");

    MockVaadin.tearDown();
    startVaadin(false);

    assertInstanceOf(DefaultErrorHandler.class, session.getErrorHandler(),
        "opt-in: an application that does not call install(...) keeps Vaadin's handler");
  }

  // ── the reference ──────────────────────────────────────────────

  @Test
  @DisplayName("an exception in a click listener: the user sees the reference, the log the stack trace")
  void clickListenerFailure_showsOnlyTheReference() throws Exception {
    ActionView view = navigateToActions();

    String log = capturingStdErr(() -> clickThroughTheRpcHandler(view.action));

    Matcher logged = LOGGED_REFERENCE.matcher(log);
    assertTrue(logged.find(), "the error is logged under a reference; stderr was: " + log);
    String reference = logged.group(1);
    assertTrue(log.contains(IllegalStateException.class.getName()), "the log names the exception");
    assertTrue(log.contains("\tat " + ActionView.class.getName()),
        "the log carries the stack trace down to the failing listener; stderr was: " + log);

    List<Notification> notifications = openNotifications();
    assertEquals(1, notifications.size());
    String shown = textOf(notifications.getFirst());
    assertEquals(MessageFormat.format(JCustosErrorHandler.FALLBACK_MESSAGE, reference), shown,
        "the user sees the reference and nothing else of the error");
    for (String leak : List.of(SECRET, "alice@example.test", "UPDATE accounts",
        IllegalStateException.class.getSimpleName())) {
      assertFalse(shown.contains(leak), "the notification leaked '" + leak + "': " + shown);
    }
    assertEquals(JCustosErrorHandler.NOTIFICATION_ID, notifications.getFirst().getId().orElseThrow());
  }

  @Test
  @DisplayName("every error gets a reference of its own: 16 Base32 characters from SecureRandom")
  void references_areFreshBase32() {
    Set<String> references = new HashSet<>();
    for (int i = 0; i < 64; i++) {
      String reference = JCustosErrorHandler.newReference();
      assertTrue(reference.matches("[A-Z2-7]{" + JCustosErrorHandler.REFERENCE_LENGTH + "}"), reference);
      references.add(reference);
    }
    assertEquals(64, references.size(), "references must not repeat");
  }

  @Test
  @DisplayName("the notification text is the translation of jcustos.error.reference when it carries the reference")
  void translation_isUsedWhenItCarriesTheReference() {
    ui.setLocale(Locale.of("fi"));

    session.getErrorHandler().error(new ErrorEvent(new IllegalStateException(LEAKY_MESSAGE)));
    MockVaadin.clientRoundtrip();

    String shown = textOf(openNotifications().getFirst());
    assertTrue(shown.startsWith("Odottamaton virhe. Ilmoita viite "), shown);
    assertTrue(shown.matches(".*[A-Z2-7]{16}\\.$"), shown);
  }

  @Test
  @DisplayName("a translation without the reference, or none at all, falls back to the English text")
  void translationWithoutTheReference_fallsBackToEnglish() {
    for (Locale locale : List.of(Locale.of("sv"), Locale.ENGLISH)) {
      ui.setLocale(locale);
      String log = capturingStdErr(() -> session.getErrorHandler()
          .error(new ErrorEvent(new IllegalStateException(LEAKY_MESSAGE))));
      MockVaadin.clientRoundtrip();

      Matcher logged = LOGGED_REFERENCE.matcher(log);
      assertTrue(logged.find(), log);
      List<Notification> notifications = openNotifications();
      assertEquals(MessageFormat.format(JCustosErrorHandler.FALLBACK_MESSAGE, logged.group(1)),
          textOf(notifications.getLast()), "locale " + locale);
    }
  }

  // ── error views keep working ───────────────────────────────────

  @Test
  @DisplayName("an AccessDeniedException in a click listener reaches the HasErrorParameter<AccessDeniedException> view")
  void accessDeniedInAClickListener_reachesTheErrorView() throws Exception {
    ActionView.failure = () -> JCustosEnforcer.requirePermission("reports:export");
    ActionView view = navigateToActions();

    String log = capturingStdErr(() -> clickThroughTheRpcHandler(view.action));

    assertInstanceOf(AccessDeniedView.class, activeView(),
        "the handler asks ErrorHandlerUtil first, as Vaadin's default handler does");
    assertEquals(1, AccessDeniedView.received.size());
    assertInstanceOf(AccessDeniedException.class, AccessDeniedView.received.getFirst());
    assertTrue(openNotifications().isEmpty(), "an error shown in its error view needs no reference");
    assertFalse(log.contains("Unhandled error"), log);
  }

  @Test
  @DisplayName("an AccessDeniedException on navigation reaches the HasErrorParameter<AccessDeniedException> view")
  void accessDeniedOnNavigation_reachesTheErrorView() {
    String log = capturingStdErr(() -> ui.navigate(GuardedView.class));

    assertInstanceOf(AccessDeniedView.class, activeView());
    assertInstanceOf(AccessDeniedException.class, AccessDeniedView.received.getFirst());
    assertTrue(openNotifications().isEmpty());
    assertFalse(log.contains("Unhandled error"), log);
  }

  @Test
  @DisplayName("RF15: a plain java.lang.Exception shows the reference, not Vaadin's InternalServerError with its root cause")
  void plainException_takesTheReferencePath() throws Exception {
    ActionView.failure = () -> sneakyThrow(
        new Exception("wrapper", new IllegalStateException(LEAKY_MESSAGE)));
    ActionView view = navigateToActions();

    String log = capturingStdErr(() -> clickThroughTheRpcHandler(view.action));

    assertInstanceOf(ActionView.class, activeView(),
        "Vaadin's InternalServerError - registered for java.lang.Exception - must not be shown");
    Matcher logged = LOGGED_REFERENCE.matcher(log);
    assertTrue(logged.find(), "the error is logged under a reference; stderr was: " + log);
    List<Notification> notifications = openNotifications();
    assertEquals(1, notifications.size());
    assertEquals(MessageFormat.format(JCustosErrorHandler.FALLBACK_MESSAGE, logged.group(1)),
        textOf(notifications.getFirst()));
    String page = pageText();
    for (String leak : List.of(SECRET, "alice@example.test", "UPDATE accounts", "root cause")) {
      assertFalse(page.contains(leak), "the page leaked '" + leak + "': " + page);
    }
  }

  @Test
  @DisplayName("RF15 control: InternalServerError is the error view Vaadin would pick for a plain Exception")
  void internalServerError_isRegisteredForException() {
    session.setErrorHandler(new DefaultErrorHandler());
    ActionView.failure = () -> sneakyThrow(
        new Exception("wrapper", new IllegalStateException(LEAKY_MESSAGE)));
    ActionView view = navigateToActions();

    capturingStdErr(() -> clickThroughTheRpcHandler(view.action));

    assertInstanceOf(InternalServerError.class, activeView(),
        "precondition: without the jCustos handler Vaadin shows its InternalServerError");
    assertTrue(pageText().contains(SECRET),
        "precondition: that view writes the root cause into the page");
  }

  // ── failures inside the handler ────────────────────────────────

  @Test
  @DisplayName("a throwing notification is logged and never leaves the handler")
  void throwingNotification_neverLeavesTheHandler() throws Exception {
    ThrowingNotificationHandler handler = new ThrowingNotificationHandler();
    session.setErrorHandler(handler);
    ActionView view = navigateToActions();

    String log = capturingStdErr(() -> assertDoesNotThrow(() -> clickThroughTheRpcHandler(view.action),
        "a failure inside the handler must not escape into Vaadin's request handling"));

    assertEquals(1, handler.errorCalls, "the handler ran once");
    assertEquals(1, handler.showCalls);
    assertTrue(LOGGED_REFERENCE.matcher(log).find(), log);
    assertTrue(log.contains("The error handler failed while reporting an error"), log);
    assertTrue(openNotifications().isEmpty());
  }

  @Test
  @DisplayName("an error raised while the reference is being shown is logged, not shown: no recursion")
  void errorRaisedWhileShowing_doesNotRecurse() throws Exception {
    ReenteringHandler handler = new ReenteringHandler();
    session.setErrorHandler(handler);
    ActionView view = navigateToActions();

    String log = capturingStdErr(() -> clickThroughTheRpcHandler(view.action));

    assertEquals(1, handler.showCalls, "the nested error must not be shown a second time");
    assertEquals(1, openNotifications().size());
    assertTrue(NESTED_REFERENCE.matcher(log).find(), "the nested error is logged; stderr was: " + log);
    assertTrue(log.contains("nested failure"), "with its stack trace");
  }

  @Test
  @DisplayName("a client that went away is not reported")
  void clientDisconnect_isNotReported() {
    String log = capturingStdErr(() -> session.getErrorHandler()
        .error(new ErrorEvent(new SocketException("Broken pipe"))));
    MockVaadin.clientRoundtrip();

    assertTrue(openNotifications().isEmpty());
    assertFalse(log.contains("Unhandled error"), log);
  }

  @Test
  @DisplayName("without a UI the error is logged with its reference and nothing is shown")
  void withoutAUi_theErrorIsOnlyLogged() {
    UI.setCurrent(null);
    try {
      String log = capturingStdErr(() -> assertDoesNotThrow(() -> session.getErrorHandler()
          .error(new ErrorEvent(new IllegalStateException(LEAKY_MESSAGE)))));
      assertTrue(LOGGED_REFERENCE.matcher(log).find(), log);
    } finally {
      UI.setCurrent(ui);
    }
    MockVaadin.clientRoundtrip();
    assertTrue(openNotifications().isEmpty());
  }

  // ── helpers ────────────────────────────────────────────────────

  private void startVaadin(boolean installHandler) {
    Routes routes = new Routes();
    routes.getRoutes().addAll(List.of(ActionView.class, GuardedView.class));
    routes.getErrorRoutes().add(AccessDeniedView.class);
    // as in every application: Vaadin registers its InternalServerError for java.lang.Exception
    routes.getErrorRoutes().add(InternalServerError.class);
    MockVaadin.setup(MockedUI::new, new ApplicationServlet(routes, installHandler));
    session = VaadinSession.getCurrent();
    ui = UI.getCurrent();
  }

  private ActionView navigateToActions() {
    ui.navigate(ActionView.class);
    return assertInstanceOf(ActionView.class, activeView());
  }

  private HasElement activeView() {
    return ui.getInternals().getActiveRouterTargetsChain().getFirst();
  }

  /** The text the browser shows: the active view and whatever else hangs off the UI. */
  private String pageText() {
    return activeView().getElement().getTextRecursively() + "\n" + ui.getElement().getTextRecursively();
  }

  /**
   * Sends a click on {@code target} through Vaadin's {@link ServerRpcHandler}, as the browser
   * would: the handler dispatches the DOM event to the click listener and passes what the
   * listener throws to the session's error handler. Then the response is prepared, which is
   * when an opened notification is added to the UI.
   */
  private void clickThroughTheRpcHandler(Component target) throws Exception {
    int clientId = ui.getInternals().getLastProcessedClientToServerId() + 1;
    String message = "{\"" + ApplicationConstants.CSRF_TOKEN + "\":\"" + ui.getCsrfToken() + "\","
        + "\"" + ApplicationConstants.SERVER_SYNC_ID + "\":0,"
        + "\"" + ApplicationConstants.CLIENT_TO_SERVER_ID + "\":" + clientId + ","
        + "\"" + ApplicationConstants.RPC_INVOCATIONS + "\":[{"
        + "\"" + JsonConstants.RPC_TYPE + "\":\"" + JsonConstants.RPC_TYPE_EVENT + "\","
        + "\"" + JsonConstants.RPC_NODE + "\":" + target.getElement().getNode().getId() + ","
        + "\"" + JsonConstants.RPC_EVENT_TYPE + "\":\"click\","
        + "\"" + JsonConstants.RPC_EVENT_DATA + "\":" + CLICK_EVENT_DATA + "}]}";
    new ServerRpcHandler().handleRpc(ui, message, VaadinRequest.getCurrent());
    MockVaadin.clientRoundtrip();
  }

  private List<Notification> openNotifications() {
    List<Notification> found = new ArrayList<>();
    collect(ui, found);
    return found.stream().filter(Notification::isOpened).toList();
  }

  private static void collect(Component component, List<Notification> found) {
    if (component instanceof Notification notification) {
      found.add(notification);
    }
    component.getChildren().forEach(child -> collect(child, found));
  }

  private static String textOf(Notification notification) {
    return notification.getElement().getProperty("text");
  }

  /** Runs {@code action} and returns what was written to {@code System.err} meanwhile. */
  private static String capturingStdErr(ThrowingRunnable action) {
    PrintStream original = System.err;
    ByteArrayOutputStream captured = new ByteArrayOutputStream();
    System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
    try {
      action.run();
    } catch (Exception unexpected) {
      throw new AssertionError("the action failed", unexpected);
    } finally {
      System.setErr(original);
    }
    return captured.toString(StandardCharsets.UTF_8);
  }

  @FunctionalInterface
  private interface ThrowingRunnable {
    void run() throws Exception;
  }

  /** Throws a checked exception from a {@link Runnable}, as Kotlin or a sneaky throw does. */
  @SuppressWarnings("unchecked")
  private static <T extends Throwable> void sneakyThrow(Throwable throwable) throws T {
    throw (T) throwable;
  }

  // ── fixtures ───────────────────────────────────────────────────

  /** A view with one button; what its click listener does is swapped per test. */
  @Route("r7/actions")
  public static class ActionView extends Div {
    static Runnable failure;
    final Button action = new Button("Export", click -> failure.run());

    public ActionView() {
      add(action);
    }
  }

  /** A view that calls a secured service while it is created: nobody is logged in. */
  @Route("r7/guarded")
  public static class GuardedView extends Div {
    public GuardedView() {
      JCustosEnforcer.requirePermission("reports:export");
    }
  }

  /** The application's error view for denials. */
  public static class AccessDeniedView extends Div implements HasErrorParameter<AccessDeniedException> {
    static final List<Exception> received = new ArrayList<>();

    @Override
    public int setErrorParameter(BeforeEnterEvent event, ErrorParameter<AccessDeniedException> parameter) {
      received.add(parameter.getException());
      setText("You may not do that.");
      return 403;
    }
  }

  /** Counts its calls; showing the reference fails. */
  static final class ThrowingNotificationHandler extends JCustosErrorHandler {
    int errorCalls;
    int showCalls;

    @Override
    public void error(ErrorEvent event) {
      errorCalls++;
      super.error(event);
    }

    @Override
    protected void showReference(UI ui, String reference) {
      showCalls++;
      throw new IllegalStateException("the notification could not be opened");
    }
  }

  /** While showing the first reference, another error reaches the session's handler. */
  static final class ReenteringHandler extends JCustosErrorHandler {
    int showCalls;

    @Override
    protected void showReference(UI ui, String reference) {
      showCalls++;
      if (showCalls == 1) {
        ui.getSession().getErrorHandler().error(new ErrorEvent(new IllegalStateException("nested failure")));
      }
      super.showReference(ui, reference);
    }
  }

  /** The browserless servlet; installs the handler at service init like an application does. */
  private static final class ApplicationServlet extends MockVaadinServlet {
    private final boolean installHandler;

    ApplicationServlet(Routes routes, boolean installHandler) {
      super(routes, MockedUI::new);
      this.installHandler = installHandler;
    }

    @Override
    protected VaadinServletService createServletService(DeploymentConfiguration configuration) {
      VaadinServletService service = super.createServletService(configuration);
      if (installHandler) {
        JCustosErrorHandler.install(new ServiceInitEvent(service));
      }
      return service;
    }
  }
}
