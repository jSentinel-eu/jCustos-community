package eu.jsentinel.jcustos.demo.skill.standalone.security.bootstrap;

import eu.jsentinel.jcustos.dx.bootstrap.AuditBootstrap;
import eu.jsentinel.jcustos.dx.bootstrap.SessionBootstrap;

/**
 * Persistence-layer extension for the standalone CLI. Contributes
 * Eclipse-Store storeBacked audit + session stores.
 *
 * <p>The storage is opened when the bootstrap chain asks for it, not
 * when the class is loaded, so a test can install its own storage
 * first. The first-admin bootstrap ({@link BootstrapWiring}) is built by
 * {@code Main} after {@code install()}, when the credential pipeline is
 * known (JS-SEC-134).
 */
public final class PersistenceBootstrapExtension implements BootstrapExtension {

  @Override
  public void contributeAudit(AuditBootstrap a) {
    a.storeBacked(JCustosStorageProvider.framework().auditEventStore()).logging();
  }

  @Override
  public void contributeSessions(SessionBootstrap s) {
    s.storeBacked(JCustosStorageProvider.framework().sessionStore());
  }

  @Override
  public int order() {
    return 10;
  }
}
