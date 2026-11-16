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
package eu.jsentinel.jcustos.demo.skill.vaadin;

import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.ConfiguredHashingService;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.InMemoryUserDirectoryPersistence;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.PersistentUserDirectory;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.StoredUser;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.User;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.services.PasswordPreflight;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.services.PreflightPasswordPolicy;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.MyLoginView;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.SetupView;
import com.sun.net.httpserver.HttpServer;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.HasLabel;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationTester;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-134 (CWE-684, CWE-916, CWE-521): the hardening layer does what it promises.
 * Passwords are stored as Argon2id - those the role administration sets and the first
 * administrator's; the first administrator created through the real {@link SetupView}
 * logs in through the real {@link MyLoginView}; a weak first-administrator password is
 * refused by the preflight, both by the local blocklist and by the HIBP range query.
 *
 * <p>The HIBP range API is a JDK {@code HttpServer} on loopback answering like the real
 * one; the demo's preflight is pointed at it with
 * {@link PasswordPreflight#HIBP_ENDPOINT_PROPERTY}.
 */
@DisplayName("JS-SEC-134 — hardening: Argon2id in use, the first administrator logs in, weak passwords refused")
class FirstAdministratorBrowserlessTest extends BrowserlessTest {

  private static final String STRONG = "Glacier-Lantern-Orbit-42";
  /** Strong-looking, but listed by the (loopback) HIBP range API. */
  private static final String BREACHED = "Tangerine-Harbour-Kite-77";

  private InMemoryUserDirectoryPersistence persistence;
  private HttpServer hibp;
  private final AtomicInteger hibpQueries = new AtomicInteger();

  @BeforeAll
  static void isolateStorage() {
    TestDirectories.isolateStorage();
  }

  @BeforeEach
  void setUp() throws IOException {
    startHibp();
    SkillDemoTestSupport.runDemoBootstrap();
    persistence = new InMemoryUserDirectoryPersistence();
    UserDirectoryProvider.setDirectory(
        new PersistentUserDirectory(persistence, ConfiguredHashingService.INSTANCE));
    TestDirectories.writeKnownToken();
    TestDirectories.resetBootstrapWiring();
  }

  @AfterEach
  void tearDown() {
    System.clearProperty(PasswordPreflight.HIBP_ENDPOINT_PROPERTY);
    if (hibp != null) {
      hibp.stop(0);
    }
    UserDirectoryProvider.setDirectory(TestDirectories.fresh());
    TestDirectories.resetBootstrapWiring();
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("a user created in the role administration is stored as Argon2id")
  void newUserIsArgon2id() {
    UserDirectoryProvider.directory().addUser("carol", STRONG,
        new User(42L, "Carol", EnumSet.of(AuthorizationRole.USER)));

    assertTrue(storedHash("carol").contains("alg=Argon2id"),
        "the hardening layer configures Argon2id; got " + envelopeHead(storedHash("carol")));
  }

  @Test
  @DisplayName("the first administrator created through the setup view is stored as Argon2id and logs in")
  void firstAdministratorIsArgon2idAndLogsIn() {
    submitSetup(STRONG);

    assertNotification("Administrator 'admin' created");
    assertTrue(storedHash("admin").contains("alg=Argon2id"),
        "the setup hashes with the configured service; got " + envelopeHead(storedHash("admin")));
    assertTrue(hibpQueries.get() > 0, "the preflight queried the HIBP range API");

    navigate(MyLoginView.class);
    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue("admin");
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue(STRONG);
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();

    Optional<User> subject = SubjectStores.subjectStore().currentSubject(User.class);
    assertTrue(subject.isPresent(), "the administrator the setup created must be able to log in");
    assertTrue(subject.get().roles().contains(AuthorizationRole.ADMIN));
  }

  @Test
  @DisplayName("a first-administrator password on the local blocklist is refused")
  void blocklistedPasswordIsRefused() {
    submitSetup("password123");

    assertNotification(PreflightPasswordPolicy.REJECTED);
    assertFalse(BootstrapWiring.instance().stateService().hasAdministrator());
  }

  @Test
  @DisplayName("a first-administrator password the HIBP range API lists is refused")
  void breachedPasswordIsRefused() {
    submitSetup(BREACHED);

    assertNotification(PreflightPasswordPolicy.REJECTED);
    assertFalse(BootstrapWiring.instance().stateService().hasAdministrator());
  }

  @Test
  @DisplayName("a password shorter than the minimum is refused before any lookup")
  void shortPasswordIsRefused() {
    submitSetup("Ab1-x");

    assertFalse(BootstrapWiring.instance().stateService().hasAdministrator());
    assertEquals(0, hibpQueries.get());
  }

  // ── helpers ────────────────────────────────────────────────────

  private void submitSetup(String password) {
    navigate(SetupView.class);
    field(PasswordField.class, "Bootstrap token").setValue(TestDirectories.KNOWN_TOKEN);
    field(PasswordField.class, "New password").setValue(password);
    field(PasswordField.class, "Repeat password").setValue(password);
    test($view(Button.class).all().stream()
        .filter(b -> "Create administrator".equals(b.getText()))
        .findFirst().orElseThrow()).click();
  }

  private <F extends com.vaadin.flow.component.Component & HasLabel> F field(Class<F> type, String label) {
    return $view(type).all().stream()
        .filter(f -> label.equals(f.getLabel()))
        .findFirst()
        .orElseThrow(() -> new AssertionError("no field labelled '" + label + "'"));
  }

  private String storedHash(String username) {
    StoredUser stored = persistence.load().get(username);
    if (stored == null) {
      throw new AssertionError("no stored user '" + username + "'");
    }
    return stored.passwordHash();
  }

  /** The envelope up to the parameters - never the derived bytes. */
  private static String envelopeHead(String hash) {
    int cut = hash.indexOf("$p=");
    return cut < 0 ? hash.substring(0, Math.min(40, hash.length())) : hash.substring(0, cut);
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  private void assertNotification(String expected) {
    List<String> texts = $(Notification.class).all().stream()
        .map(n -> ((NotificationTester) test(n)).getText())
        .toList();
    assertTrue(texts.stream().anyMatch(t -> t.contains(expected)),
        "expected a notification containing '" + expected + "'; got " + texts);
  }

  /** A range API on loopback that lists {@link #BREACHED} and pads with count-0 entries. */
  private void startHibp() throws IOException {
    String sha1 = sha1Hex(BREACHED);
    String breachedPrefix = sha1.substring(0, 5);
    String breachedSuffix = sha1.substring(5);
    hibp = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    hibp.createContext("/range/", exchange -> {
      hibpQueries.incrementAndGet();
      String prefix = exchange.getRequestURI().getPath().substring("/range/".length());
      StringBuilder body = new StringBuilder("0000000000000000000000000000000000A:0\r\n");
      if (prefix.equalsIgnoreCase(breachedPrefix)) {
        body.append(breachedSuffix).append(":4711\r\n");
      }
      byte[] bytes = body.toString().getBytes(StandardCharsets.US_ASCII);
      exchange.sendResponseHeaders(200, bytes.length);
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(bytes);
      }
    });
    hibp.start();
    System.setProperty(PasswordPreflight.HIBP_ENDPOINT_PROPERTY,
        "http://127.0.0.1:" + hibp.getAddress().getPort() + "/range/");
  }

  private static String sha1Hex(String value) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-1")
          .digest(value.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest).toUpperCase(Locale.ROOT);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}
