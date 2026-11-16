package eu.jsentinel.jcustos.demo.skill.rest.security.services;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.autoservice.api.JCustosAutoService;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.Credentials;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.User;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.UserDirectoryProvider;

/**
 * REST-side AuthenticationService — same shape as the Vaadin skill.
 *
 * <p>The service only answers whether credentials are valid. Throttling
 * and the audit trail belong to the login flow that calls it — in this
 * application {@code AuthHandler.login}, which knows the client address
 * and the session — so the service neither consults the
 * {@code LoginAttemptPolicy} nor publishes {@code LoginSucceeded}; doing
 * both here would count and audit every attempt twice. A verification
 * shed under load surfaces as
 * {@code CredentialVerificationUnavailableException} (JS-SEC-126).
 */
@JCustosAutoService(AuthenticationService.class)
public class MyAuthenticationService
    implements AuthenticationService<Credentials, User>, HasLogger {

  @Override
  public boolean checkCredentials(Credentials credentials) {
    if (credentials == null) {
      return false;
    }
    return UserDirectoryProvider.directory().checkCredentials(credentials);
  }

  @Override
  public User loadSubject(Credentials credentials) {
    return UserDirectoryProvider.directory().findByCredentials(credentials).orElse(null);
  }

  @Override
  public Class<User> subjectType() {
    return User.class;
  }
}
