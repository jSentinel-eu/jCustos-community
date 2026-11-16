package eu.jsentinel.jcustos.demo.skill.standalone.security.bootstrap;

import eu.jsentinel.jcustos.bootstrap.PasswordPolicy;
import eu.jsentinel.jcustos.dx.bootstrap.AuditBootstrap;
import eu.jsentinel.jcustos.dx.bootstrap.CredentialBootstrap;
import eu.jsentinel.jcustos.dx.bootstrap.SessionBootstrap;

/**
 * Project-local SPI for additive bootstrap configuration.
 *
 * <p>Layer 1 (this skill) defines the contract; higher layers ship
 * implementations registered via
 * {@code META-INF/services/{@value #SERVICE_NAME}}.
 *
 * <p>{@link BootstrapBuilder#apply(Object)} loads every registered
 * implementation through {@link java.util.ServiceLoader}, sorts by
 * {@link #order()}, and invokes the three {@code contribute*} hooks
 * inside a single {@code .audit / .sessions / .credentials} call on
 * the fluent {@code StandaloneSecurity.bootstrap()} chain — multiple
 * layers can configure the same sub-aspect without overwriting each
 * other.
 */
public interface BootstrapExtension {

  String SERVICE_NAME = "eu.jsentinel.jcustos.demo.skill.standalone.security.bootstrap.BootstrapExtension";

  default void contributeAudit(AuditBootstrap a) {
  }

  default void contributeSessions(SessionBootstrap s) {
  }

  default void contributeCredentials(CredentialBootstrap c) {
  }

  /**
   * Adds checks to the password policy of the first administrator — the
   * account the bootstrap-token flow of the persistence layer creates.
   * Return {@code base} combined with further checks; the default keeps
   * {@code base}. Applied in {@link #order()} by
   * {@link BootstrapBuilder#initialAdminPasswordPolicy(PasswordPolicy)}.
   */
  default PasswordPolicy initialAdminPasswordPolicy(PasswordPolicy base) {
    return base;
  }

  default int order() {
    return 0;
  }
}
