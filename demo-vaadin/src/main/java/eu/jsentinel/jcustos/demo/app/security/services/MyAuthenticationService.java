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
package eu.jsentinel.jcustos.demo.app.security.services;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.autoservice.api.JCustosAutoService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.demo.app.security.model.Credentials;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectory;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectoryProvider;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.net.vaadin.VaadinClientAddress;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

@JCustosAutoService(AuthenticationService.class)
public class MyAuthenticationService
    implements AuthenticationService<Credentials, MyUser>, HasLogger {

  @Override
  public boolean checkCredentials(Credentials credentials) {
    if (credentials == null) {
      return false;
    }

    LoginAttemptPolicy policy = JCustosServiceResolver.loginAttemptPolicy();
    LoginAttemptContext attempt = LoginAttemptContext.now(
        credentials.username(), currentClientAddress(), null);

    LoginAttemptDecision decision = policy.beforeAttempt(attempt);
    if (decision instanceof LoginAttemptDecision.LockedOut(Duration remaining, int failedAttempts)) {
      logger().warn("Login throttled for username={} (remaining={}s, failedAttempts={})",
                    credentials.username(), remaining.toSeconds(), failedAttempts);
      return false;
    }

    boolean ok = directory().checkCredentials(credentials);
    if (ok) {
      policy.recordSuccess(attempt);
      auditLoginSucceeded(credentials.username(), attempt.clientAddress());
    } else {
      policy.recordFailure(attempt);
    }
    return ok;
  }

  private static void auditLoginSucceeded(String username, String clientAddress) {
    JCustosAuditService sink = JCustosServiceResolver.securityAuditService();
    try {
      sink.publish(new LoginSucceeded(
          Instant.now(Clock.systemUTC()), username, clientAddress, null));
    } catch (RuntimeException ignored) {
      // never block a successful login because the audit sink failed
    }
  }

  @Override
  public MyUser loadSubject(Credentials credentials) {
    return directory().findByCredentials(credentials).orElse(null);
  }

  @Override
  public Class<MyUser> subjectType() {
    return MyUser.class;
  }

  private static DemoUserDirectory directory() {
    return DemoUserDirectoryProvider.directory();
  }

  /**
   * Best-effort: Vaadin exposes the current request only on the request
   * thread. Returns {@code null} when called outside of one.
   */
  /** JS-SEC-061: resolved through the registered ClientAddressResolver, never getRemoteAddr() directly. */
  private static String currentClientAddress() {
    return VaadinClientAddress.current().orElse(null);
  }
}