package eu.jsentinel.jcustos.demo.skill.vaadin.security.services;

import eu.jsentinel.jcustos.session.InMemorySessionStore;
import eu.jsentinel.jcustos.session.SessionStore;

/**
 * Lazy singleton holder for the {@link SessionStore}. Records of
 * active sessions live here so the {@code /admin/sessions} view can
 * render them via the framework's {@code SessionManagementView}.
 *
 * <p>The records are kept under the reference of the session id, never
 * under the session cookie itself ({@link SessionReferenceStore},
 * JS-SEC-117). The bootstrap registers this store for the per-request
 * revocation check ({@code DefaultBootstrapExtension}).
 *
 * <p>Demo-only: in-memory, dropped on JVM exit. Swap in
 * {@code EclipseStoreSessionStore} (from
 * {@code jCustos-persistence-eclipsestore}) for a persistent
 * backend.
 */
public final class SessionStoreProvider {

  private static final SessionStore INSTANCE =
      new SessionReferenceStore(new InMemorySessionStore());

  private SessionStoreProvider() {
  }

  public static SessionStore sessionStore() {
    return INSTANCE;
  }
}
