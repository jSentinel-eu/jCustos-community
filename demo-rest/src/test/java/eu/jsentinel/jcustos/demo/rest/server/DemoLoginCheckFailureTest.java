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
package eu.jsentinel.jcustos.demo.rest.server;

import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptLimits;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.password.RehashDecision;
import eu.jsentinel.jcustos.demo.rest.domain.DemoDocumentStore;
import eu.jsentinel.jcustos.demo.rest.domain.DemoRole;
import eu.jsentinel.jcustos.demo.rest.domain.DemoRolePermissionMapping;
import eu.jsentinel.jcustos.demo.rest.domain.DemoUserStore;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.util.Arrays;
import java.util.Map;

import static com.svenruppert.dependencies.core.net.HttpStatus.OK;
import static com.svenruppert.dependencies.core.net.HttpStatus.TOO_MANY_REQUESTS;
import static com.svenruppert.dependencies.core.net.HttpStatus.UNAUTHORIZED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * XR09-6 (CWE-755, CWE-307): a credential check that throws - anything but the "could not verify"
 * of JS-SEC-126 - is a failed attempt in the demo login, as it is in {@code LoginView} and
 * {@code StandaloneLoginFlow}. Until then the handler gave the attempt back and rethrew, so input
 * that made the check throw could be tried without limit. The check here is the real PBKDF2
 * pipeline behind a hand-written delegate that throws for one password, the shape of a directory
 * lookup that breaks on a crafted input.
 */
@DisplayName("Demo REST login - a credential check that throws counts as a failed attempt")
class DemoLoginCheckFailureTest {

  private static final String CLIENT = "203.0.113.51";
  /** The input that makes the check throw. */
  private static final String BREAKS_THE_CHECK = "crafted-input-that-breaks-the-lookup";

  @BeforeEach
  void resetResolver() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("five throwing checks are answered 401 and lock the account: the sixth login is 429, the right password included")
  void throwingCheckLocksTheAccount() {
    DemoUserStore users = new DemoUserStore(new BreaksOn(BREAKS_THE_CHECK,
        PasswordHashingServices.defaults()));
    users.create("check-user", "correct horse", "Check User", DemoRole.ROLE_VIEWER);
    InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy(
        LoginAttemptLimits.defaults(), Clock.systemUTC(), null);
    DemoHandlers handlers = handlers(users, policy);
    int threshold = LoginAttemptLimits.defaults().perAccount().failureThreshold();

    for (int i = 0; i < threshold; i++) {
      assertEquals(UNAUTHORIZED.code(), login(handlers, "check-user", BREAKS_THE_CHECK).status(),
          "a throwing check is answered like wrong credentials, attempt " + (i + 1));
    }

    assertEquals(TOO_MANY_REQUESTS.code(), login(handlers, "check-user", "correct horse").status(),
        "the throwing checks were counted: the account is locked");
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.peek(LoginAttemptContext.now("check-user", CLIENT, null)));
    assertTrue(JCustosServiceResolver.securityAuditService().query(AuditQuery.all()).stream()
            .anyMatch(e -> e instanceof LoginFailed failed
                && DemoHandlers.CHECK_FAILED_REASON.equals(failed.reason())),
        "the failure is audited with its own reason");
    assertEquals(0, policy.credentialCheckGate().inUse());
  }

  @Test
  @DisplayName("the right password still logs in while the check breaks only on other input")
  void otherInputIsUnaffected() {
    DemoUserStore users = new DemoUserStore(new BreaksOn(BREAKS_THE_CHECK,
        PasswordHashingServices.defaults()));
    users.create("check-user", "correct horse", "Check User", DemoRole.ROLE_VIEWER);
    DemoHandlers handlers = handlers(users, new InMemoryLoginAttemptPolicy(
        LoginAttemptLimits.defaults(), Clock.systemUTC(), null));

    assertEquals(UNAUTHORIZED.code(), login(handlers, "check-user", BREAKS_THE_CHECK).status());
    assertEquals(OK.code(), login(handlers, "check-user", "correct horse").status());
  }

  private static DemoHandlers handlers(DemoUserStore users, InMemoryLoginAttemptPolicy policy) {
    DemoTokenStore tokens = new DemoTokenStore();
    DemoSubjectResolver resolver = new DemoSubjectResolver(tokens, new DemoRolePermissionMapping());
    return new DemoHandlers(users, tokens, new DemoDocumentStore(), new DemoOperationRegistry(),
        resolver, policy, new InMemoryJCustosVersionStore(), null, null);
  }

  private static DemoHttpResponse login(DemoHandlers handlers, String username, String password) {
    DemoHttpRequest request = new DemoHttpRequest("POST", "/api/login", Map.of(), Map.of(),
        "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}", CLIENT);
    DemoHttpResponse response = new DemoHttpResponse();
    handlers.login(request, response);
    return response;
  }

  /** The real pipeline, except that a verification of {@code poison} throws. */
  private static final class BreaksOn implements PasswordHashingService {
    private final char[] poison;
    private final PasswordHashingService delegate;

    BreaksOn(String poison, PasswordHashingService delegate) {
      this.poison = poison.toCharArray();
      this.delegate = delegate;
    }

    private void breakOn(char[] password) {
      if (Arrays.equals(poison, password)) {
        throw new IllegalStateException("the directory lookup failed on this input");
      }
    }

    @Override
    public PasswordHashResult hash(char[] password) {
      return delegate.hash(password);
    }

    @Override
    public CredentialVerificationResult verify(char[] password, String encodedHash) {
      breakOn(password);
      return delegate.verify(password, encodedHash);
    }

    @Override
    public RehashDecision needsRehash(String encodedHash) {
      return delegate.needsRehash(encodedHash);
    }

    @Override
    public CredentialVerificationResult verifyAgainstNothing(char[] password) {
      breakOn(password);
      return delegate.verifyAgainstNothing(password);
    }
  }
}
