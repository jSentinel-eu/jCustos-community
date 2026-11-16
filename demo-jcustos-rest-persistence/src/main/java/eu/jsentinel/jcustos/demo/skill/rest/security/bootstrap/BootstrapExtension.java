package eu.jsentinel.jcustos.demo.skill.rest.security.bootstrap;

import eu.jsentinel.jcustos.bootstrap.PasswordPolicy;
import eu.jsentinel.jcustos.dx.bootstrap.AuditBootstrap;
import eu.jsentinel.jcustos.dx.bootstrap.CredentialBootstrap;
import eu.jsentinel.jcustos.dx.bootstrap.SessionBootstrap;

/**
 * Project-local SPI for additive bootstrap configuration.
 *
 * <p>Layer-1 (this skill) defines the contract; higher layers
 * ({@code jcustos-rest-persistence}, {@code jcustos-rest-hardening},
 * future {@code -mfa} / {@code -multi-tenant} etc.) each ship one
 * implementation registered via
 * {@code META-INF/services/{@value #SERVICE_NAME}}.
 *
 * <p>{@link BootstrapBuilder#apply(Object)} loads every registered
 * implementation through {@link java.util.ServiceLoader}, sorts by
 * {@link #order()}, and invokes the three {@code contribute*} hooks
 * inside a single {@code .audit(...)} / {@code .sessions(...)}
 * / {@code .credentials(...)} call on the fluent
 * {@code RestSecurity.bootstrap()} chain — so multiple layers can
 * configure the same sub-aspect without overwriting each other.
 *
 * <p>All three hooks have an empty default — a layer overrides only
 * the sub-aspects it cares about.
 */
public interface BootstrapExtension {

  /** The SPI service-file name for this interface. */
  String SERVICE_NAME = "eu.jsentinel.jcustos.demo.skill.rest.security.bootstrap.BootstrapExtension";

  /** Adds audit-related configuration. */
  default void contributeAudit(AuditBootstrap a) {
  }

  /** Adds session-related configuration. */
  default void contributeSessions(SessionBootstrap s) {
  }

  /** Adds credential / hashing configuration. */
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

  /**
   * Order in which extensions are invoked. Layer 1 default: 0;
   * persistence: 10; hardening: 20.
   */
  default int order() {
    return 0;
  }
}
