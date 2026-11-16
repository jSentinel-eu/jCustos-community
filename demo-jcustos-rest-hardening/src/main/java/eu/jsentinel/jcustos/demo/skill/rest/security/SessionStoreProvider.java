package eu.jsentinel.jcustos.demo.skill.rest.security;

import eu.jsentinel.jcustos.session.SessionStore;
import eu.jsentinel.jcustos.demo.skill.rest.security.bootstrap.JCustosStorageProvider;

/**
 * Replacement for the layer-1 in-memory provider — now delegates to
 * the Eclipse-Store-backed
 * {@link eu.jsentinel.jcustos.persistence.eclipsestore.EclipseStoreJCustosStorage}
 * via {@link JCustosStorageProvider}.
 */
public final class SessionStoreProvider {

  private SessionStoreProvider() {
  }

  public static SessionStore sessionStore() {
    return JCustosStorageProvider.framework().sessionStore();
  }
}
