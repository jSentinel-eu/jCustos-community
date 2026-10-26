package eu.jsentinel.jcustos.demo.skill.vaadin.security.services;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.autoservice.api.JCustosAutoService;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.Credentials;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.User;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.net.vaadin.VaadinClientAddress;

import java.time.Clock;
import java.time.Instant;

/**
 * SPI-registered via {@link JCustosAutoService @JCustosAutoService}
 * — the annotation processor produces the matching
 * {@code META-INF/services/eu.jsentinel.jcustos.authentication.AuthenticationService}
 * entry at compile time. No hand-written service file required.
 *
 * <p>Consults the active {@link LoginAttemptPolicy} for throttling
 * before delegating to the user directory; records success / failure
 * back into the policy so brute-force protection works.
 */
@JCustosAutoService(AuthenticationService.class)
public class MyAuthenticationService
    implements AuthenticationService<Credentials, User>, HasLogger {

  @Override
  public boolean checkCredentials(Credentials credentials) {
    if (credentials == null) {
      return false;
    }

    LoginAttemptPolicy policy = JCustosServiceResolver.loginAttemptPolicy();
    LoginAttemptContext attempt = LoginAttemptContext.now(
        credentials.username(), currentClientAddress(), null);

    LoginAttemptDecision decision = policy.beforeAttempt(attempt);
    if (decision instanceof LoginAttemptDecision.LockedOut lockout) {
      logger().warn("Login throttled for username={} (remaining={}s, failedAttempts={})",
          credentials.username(), lockout.remaining().toSeconds(), lockout.failedAttempts());
      return false;
    }

    boolean ok = UserDirectoryProvider.directory().checkCredentials(credentials);
    if (ok) {
      policy.recordSuccess(attempt);
      auditLoginSucceeded(credentials.username(), attempt.clientAddress());
    } else {
      policy.recordFailure(attempt);
    }
    return ok;
  }

  @Override
  public User loadSubject(Credentials credentials) {
    return UserDirectoryProvider.directory().findByCredentials(credentials).orElse(null);
  }

  @Override
  public Class<User> subjectType() {
    return User.class;
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

  /** JS-SEC-061: resolved through the registered ClientAddressResolver, never getRemoteAddr() directly. */
  private static String currentClientAddress() {
    return VaadinClientAddress.current().orElse(null);
  }
}
