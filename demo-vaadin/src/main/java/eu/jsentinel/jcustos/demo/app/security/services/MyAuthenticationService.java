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
import eu.jsentinel.jcustos.demo.app.security.model.Credentials;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectory;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectoryProvider;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.net.vaadin.VaadinClientAddress;

import java.time.Clock;
import java.time.Instant;

/**
 * Checks credentials against the demo user directory and audits a successful check.
 * <p>
 * The login throttle is deliberately not consulted here. Since 00.84.00 the library
 * {@code LoginView} runs the complete {@code LoginAttemptPolicy} protocol around
 * {@link #checkCredentials(Credentials)} (JS-SEC-124): it asks before the call and reports
 * success, failure or "no verdict" afterwards. A second call from this service would
 * reserve and count every attempt twice.
 */
@JCustosAutoService(AuthenticationService.class)
public class MyAuthenticationService
    implements AuthenticationService<Credentials, MyUser>, HasLogger {

  @Override
  public boolean checkCredentials(Credentials credentials) {
    if (credentials == null) {
      return false;
    }
    boolean ok = directory().checkCredentials(credentials);
    if (ok) {
      auditLoginSucceeded(credentials.username(), currentClientAddress());
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