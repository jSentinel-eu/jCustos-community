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
package eu.jsentinel.jcustos.demo.restclient.security;

import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.autoservice.api.JCustosAutoService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.demo.restclient.backend.BackendClientProvider;
import eu.jsentinel.jcustos.demo.restclient.backend.Credentials;
import eu.jsentinel.jcustos.demo.restclient.backend.LoginResult;
import eu.jsentinel.jcustos.demo.restclient.backend.RemoteUser;
import eu.jsentinel.jcustos.net.vaadin.VaadinClientAddress;

import java.time.Clock;
import java.time.Instant;

/**
 * SPI-loaded {@link AuthenticationService} that delegates the credential
 * check to the demo-rest backend via {@link BackendClientProvider}.
 * <p>
 * On a successful login the returned token + {@link RemoteUser} are
 * stored in {@link ClientJCustosContext} so subsequent calls
 * ({@code loadSubject}, {@code SubjectStore.currentSubject(...)}) return
 * them without another round-trip.
 * <p>
 * Repeated failures are throttled locally, but not from here: since 00.84.00
 * the library {@code LoginView} runs the complete {@code LoginAttemptPolicy}
 * protocol around {@link #checkCredentials(Credentials)} (JS-SEC-124). A
 * locked-out attempt never reaches this service, so a brute-force attempt
 * still stops at the Vaadin layer before issuing yet another HTTP call
 * against the backend; a second policy call from here would reserve and count
 * every attempt twice.
 */
@JCustosAutoService(AuthenticationService.class)
public class RestBackedAuthenticationService
    implements AuthenticationService<Credentials, RemoteUser> {

  @Override
  public boolean checkCredentials(Credentials credentials) {
    if (credentials == null) {
      return false;
    }

    LoginResult result = BackendClientProvider.client().login(credentials);
    if (result instanceof LoginResult.Authenticated(String token, RemoteUser user)) {
      ClientJCustosContext.setActiveLogin(token, user);
      auditLoginSucceeded(user, currentClientAddress());
      return true;
    }
    return false;
  }

  private static void auditLoginSucceeded(RemoteUser user, String clientAddress) {
    JCustosAuditService sink = JCustosServiceResolver.securityAuditService();
    try {
      sink.publish(new LoginSucceeded(
          Instant.now(Clock.systemUTC()), user.subjectId(), clientAddress, null));
    } catch (RuntimeException ignored) {
      // never block a successful login because the audit sink failed
    }
  }

  @Override
  public RemoteUser loadSubject(Credentials credentials) {
    return ClientJCustosContext.user().orElse(null);
  }

  @Override
  public Class<RemoteUser> subjectType() {
    return RemoteUser.class;
  }

  /** JS-SEC-061: resolved through the registered ClientAddressResolver, never getRemoteAddr() directly. */
  private static String currentClientAddress() {
    return VaadinClientAddress.current().orElse(null);
  }
}
