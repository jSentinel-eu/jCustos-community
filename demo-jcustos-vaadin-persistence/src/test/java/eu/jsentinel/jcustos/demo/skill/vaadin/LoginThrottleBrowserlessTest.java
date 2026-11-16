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

import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.NoopLoginAttemptPolicy;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.User;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.MyLoginView;
import eu.jsentinel.jcustos.net.vaadin.VaadinClientAddress;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-124 (CWE-307): the demo is throttled as shipped. The library {@code LoginView}
 * runs the login-attempt protocol around {@code checkCredentials()}, the demo's
 * authentication service no longer calls the policy itself, and the bootstrap leaves the
 * secure default policy in place - five failures lock the account. Every attempt is
 * counted exactly once.
 */
@DisplayName("JS-SEC-124 — the demo's login view is throttled, every attempt counted once")
class LoginThrottleBrowserlessTest extends BrowserlessTest {

  private static final User ADMIN = new User(1L, "Admin",
      EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER));
  private static final User ALICE = new User(5L, "Alice", EnumSet.of(AuthorizationRole.USER));
  private static final String ALICE_PASSWORD = "alice-pass-1234";

  private final RecordingAuditSink audit = new RecordingAuditSink();

  @BeforeAll
  static void isolateStorage() {
    TestDirectories.isolateStorage();
  }

  @BeforeEach
  void setUp() {
    SkillDemoTestSupport.runDemoBootstrap();
    JCustosServiceResolver.setJCustosAuditService(audit);
    UserDirectoryProvider.setDirectory(TestDirectories.fresh());
    UserDirectoryProvider.directory().addUser("admin", "admin-pass-1234", ADMIN);
    UserDirectoryProvider.directory().addUser("alice", ALICE_PASSWORD, ALICE);
    TestDirectories.resetBootstrapWiring();
    audit.clear();
  }

  @AfterEach
  void tearDown() {
    UserDirectoryProvider.setDirectory(TestDirectories.fresh());
    TestDirectories.resetBootstrapWiring();
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("the shipped configuration throttles: no no-op policy is in effect")
  void throttlingIsActive() {
    assertFalse(JCustosServiceResolver.loginAttemptPolicy() instanceof NoopLoginAttemptPolicy,
        "the demo must not run with the no-op policy");
  }

  @Test
  @DisplayName("five wrong passwords lock the account: the correct password is refused afterwards")
  void fiveFailuresLockTheAccount() {
    for (int i = 0; i < 5; i++) {
      attempt("alice", "wrong-" + i);
    }
    assertEquals(5, audit.events().stream().filter(LoginFailed.class::isInstance).count(),
        "every failed attempt is audited");

    attempt("alice", ALICE_PASSWORD);

    assertTrue(SubjectStores.subjectStore().currentSubject(User.class).isEmpty(),
        "a locked-out account must not log in, not even with the right password");
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        JCustosServiceResolver.loginAttemptPolicy().peek(
            LoginAttemptContext.now("alice", VaadinClientAddress.current().orElse(null), null)),
        "the policy reports the account as locked out");
  }

  @Test
  @DisplayName("four wrong passwords, then the right one logs in - nothing is counted twice")
  void fourFailuresThenSuccess() {
    for (int i = 0; i < 4; i++) {
      attempt("alice", "wrong-" + i);
    }

    attempt("alice", ALICE_PASSWORD);

    assertEquals(Optional.of(ALICE), SubjectStores.subjectStore().currentSubject(User.class),
        "four failures are below the threshold; a second count per attempt would lock here");
  }

  private void attempt(String username, String password) {
    navigate(MyLoginView.class);
    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue(username);
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue(password);
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();
  }
}
