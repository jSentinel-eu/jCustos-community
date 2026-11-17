package eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.credential.password.bouncycastle.BouncyCastleHashingServices;
import eu.jsentinel.jcustos.dx.bootstrap.CredentialBootstrap;
import eu.jsentinel.jcustos.dx.bootstrap.SessionBootstrap;
import eu.jsentinel.jcustos.session.JCustosVersionStore;
import eu.jsentinel.jcustos.session.ObservableJCustosVersionStore;

import java.util.Optional;

/**
 * Hardening-layer extension. Contributes:
 *
 * <ul>
 *   <li>Argon2id hashing via {@link BouncyCastleHashingServices#modern()}
 *       — replaces the layer-1 PBKDF2 default. Legacy PBKDF2 /
 *       bcrypt / scrypt envelopes still verify and auto-rehash on
 *       next successful login.</li>
 *   <li>Phase-4c drift detection via {@code SessionBootstrap.securityVersion}
 *       + {@code subjectIdResolver} — when both SPIs are SPI-registered
 *       (the hardening skill ships META-INF/services entries for the
 *       in-memory variants), revoking a role mid-session forces the
 *       affected user back to login on the next request.</li>
 *   <li>Since 00.84.00 the version store is registered wrapped in an
 *       {@link ObservableJCustosVersionStore} (R8, JS-SEC-167): the starter's
 *       {@code serviceInit(...)} then installs the bridge that ends the open
 *       session of a user at once when {@code VersionBumper} bumps the version -
 *       over {@code @Push}, without waiting for the user's next click.</li>
 * </ul>
 *
 * <p>Registered via
 * {@code META-INF/services/eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap.BootstrapExtension}.
 * {@link #order()} returns 20 so this runs after any persistence
 * extension — that way persistence's {@code storeBacked(...)}
 * session-store wire stays in effect while hardening adds the
 * version-store binding on top.
 */
public final class HardeningBootstrapExtension implements BootstrapExtension {

  @Override
  public void contributeCredentials(CredentialBootstrap c) {
    c.hashing(BouncyCastleHashingServices.modern());
  }

  @Override
  public void contributeSessions(SessionBootstrap s) {
    Optional<JCustosVersionStore> versionStore =
        JCustosServiceResolver.findJCustosVersionStore();
    Optional<SubjectIdResolver<Object>> resolver =
        JCustosServiceResolver.findSubjectIdResolver();
    // R8 (JS-SEC-167): every bump goes through the registered store, so wrapping it here
    // makes VersionBumper's increments observable; a store that is observable already is kept
    versionStore.map(HardeningBootstrapExtension::observable).ifPresent(s::securityVersion);
    resolver.ifPresent(s::subjectIdResolver);
  }

  @Override
  public int order() {
    return 20;
  }

  private static ObservableJCustosVersionStore observable(JCustosVersionStore store) {
    return store instanceof ObservableJCustosVersionStore observable
        ? observable
        : new ObservableJCustosVersionStore(store);
  }
}
