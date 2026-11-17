/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.starter.profile;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.oidc.api.SessionRegistry;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer;
import eu.jsentinel.jcustos.session.JCustosVersionStore;
import eu.jsentinel.jcustos.session.ObservableJCustosVersionStore;
import eu.jsentinel.jcustos.session.vaadin.JCustosVersionEnforcerListener;
import eu.jsentinel.jcustos.session.vaadin.VaadinJCustosVersionChangeBridge;
import eu.jsentinel.jcustos.starter.errors.JCustosErrorHandler;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.SessionDestroyListener;

import java.lang.reflect.InvocationTargetException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * The one-call service initialisation of the Vaadin starter (JS-SEC-168, CWE-1188), reached
 * through {@link VaadinJCustosStarter#serviceInit(ServiceInitEvent, Class)}.
 * <p>
 * Until 00.84.00 every application wrote its own {@code VaadinServiceInitListener}s for the
 * parts of jCustos that need the service: the security-version check, the reference error
 * handler, the cleanup of the OIDC session registry. A part that was forgotten failed open -
 * a revoked role kept working, an exception message reached the browser - and nothing said so.
 * {@link #install(ServiceInitEvent, Class, Options)} wires each part whose prerequisite is
 * there and logs, once per service, what it installed and what it skipped:
 * <ol>
 *   <li>{@link Part#VERSION_ENFORCER} - when a {@link JCustosVersionStore} is registered
 *       ({@code JCustosServiceResolver.findJCustosVersionStore()}):
 *       {@link JCustosVersionEnforcerListener#register(ServiceInitEvent)} with a
 *       {@link JCustosVersionEnforcer} over that store and the registered audit service. A
 *       drifted session is refused on navigation, client message, push message and download
 *       and sent to {@code rerouteTarget}.</li>
 *   <li>{@link Part#VERSION_CHANGE_BRIDGE} - when that store is an
 *       {@link ObservableJCustosVersionStore}: {@link VaadinJCustosVersionChangeBridge} ends the
 *       open sessions of a subject at once when its version changes (R8, JS-SEC-167).</li>
 *   <li>{@link Part#ERROR_HANDLER} - unless {@link Options#withoutErrorHandler()}:
 *       {@link JCustosErrorHandler#install(ServiceInitEvent)} (JS-SEC-067).</li>
 *   <li>{@link Part#OIDC_SESSION_REGISTRY_CLEANUP} - when a registry was passed through
 *       {@link Options#withOidcSessionRegistry(SessionRegistry)} and
 *       {@code jCustos-identity-oidc-vaadin} is on the class path: its
 *       {@code VaadinSessionRegistryCleanup} as session-destroy listener (JS-SEC-078). The
 *       class is loaded by name, so the starter does not depend on the OIDC modules.</li>
 * </ol>
 * Call it from the application's {@code VaadinServiceInitListener}, after
 * {@code VaadinSecurity.bootstrap()...install()} - the bootstrap registers the version store
 * and the audit service the parts read - and once per service: every part registers
 * listeners on {@code event.getSource()}.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class VaadinJCustosServiceInit {

  /** The class the OIDC session-registry cleanup is loaded from, when the module is present. */
  static final String OIDC_SESSION_REGISTRY_CLEANUP_CLASS =
      "eu.jsentinel.jcustos.identity.oidc.vaadin.VaadinSessionRegistryCleanup";

  private VaadinJCustosServiceInit() {
    // utility
  }

  /**
   * A part {@link #install} can wire.
   *
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public enum Part {
    /** {@link JCustosVersionEnforcerListener}: drift refused on every request. */
    VERSION_ENFORCER,
    /** {@link VaadinJCustosVersionChangeBridge}: drift acted on at once (R8). */
    VERSION_CHANGE_BRIDGE,
    /** {@link JCustosErrorHandler} on every new session. */
    ERROR_HANDLER,
    /** {@code VaadinSessionRegistryCleanup} of the OIDC module. */
    OIDC_SESSION_REGISTRY_CLEANUP
  }

  /**
   * What the application adds to or removes from the defaults.
   *
   * @param errorHandler        whether {@link JCustosErrorHandler} is installed; default
   *                            {@code true}
   * @param oidcSessionRegistry the registry the application registers its OIDC sessions in,
   *                            or {@code null}; default {@code null}
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public record Options(boolean errorHandler, SessionRegistry oidcSessionRegistry) {

    /** @return the error handler, no OIDC session registry */
    public static Options defaults() {
      return new Options(true, null);
    }

    /**
     * For an application that sets its own session error handler.
     *
     * @return these options without {@link JCustosErrorHandler}
     */
    public Options withoutErrorHandler() {
      return new Options(false, oidcSessionRegistry);
    }

    /**
     * @param registry the registry the back-channel and front-channel logout read; non-null
     * @return these options with the cleanup of {@code registry}
     */
    public Options withOidcSessionRegistry(SessionRegistry registry) {
      return new Options(errorHandler, requireNonNull(registry, "registry must not be null"));
    }
  }

  /**
   * Wires every part whose prerequisite is there; see the class description.
   *
   * @param event         the service-init event; non-null
   * @param rerouteTarget where a drifted session is sent - typically the application's
   *                      {@code LoginView} subclass; non-null
   * @param options       additions and removals; non-null
   * @return the parts that were installed, unmodifiable
   */
  public static Set<Part> install(ServiceInitEvent event,
                                  Class<? extends Component> rerouteTarget,
                                  Options options) {
    requireNonNull(event, "event must not be null");
    requireNonNull(rerouteTarget, "rerouteTarget must not be null");
    requireNonNull(options, "options must not be null");
    Set<Part> installed = EnumSet.noneOf(Part.class);

    Optional<JCustosVersionStore> versionStore = JCustosServiceResolver.findJCustosVersionStore();
    if (versionStore.isPresent()) {
      JCustosVersionEnforcer enforcer = new JCustosVersionEnforcer(versionStore.get(),
          JCustosServiceResolver.securityAuditService());
      new JCustosVersionEnforcerListener(enforcer, rerouteTarget).register(event);
      installed.add(Part.VERSION_ENFORCER);
      if (versionStore.get() instanceof ObservableJCustosVersionStore observable) {
        new VaadinJCustosVersionChangeBridge(enforcer, rerouteTarget).register(event, observable);
        installed.add(Part.VERSION_CHANGE_BRIDGE);
      } else {
        HasLogger.staticLogger().info("starter/version-change-bridge-skipped: the registered "
            + "JCustosVersionStore is not an ObservableJCustosVersionStore; open sessions learn of "
            + "a version change with their next request");
      }
    } else {
      HasLogger.staticLogger().info("starter/version-enforcer-skipped: no JCustosVersionStore is "
          + "registered, so the security-version check is not installed");
    }

    if (options.errorHandler()) {
      JCustosErrorHandler.install(event);
      installed.add(Part.ERROR_HANDLER);
    }

    if (options.oidcSessionRegistry() != null
        && installSessionRegistryCleanup(event, options.oidcSessionRegistry(),
        OIDC_SESSION_REGISTRY_CLEANUP_CLASS)) {
      installed.add(Part.OIDC_SESSION_REGISTRY_CLEANUP);
    }

    HasLogger.staticLogger().info("starter/service-init: installed {}", installed);
    return Collections.unmodifiableSet(installed);
  }

  /**
   * Registers the OIDC module's cleanup for {@code registry}, loaded by {@code className}.
   *
   * @return {@code false} when the class is not on the class path or cannot be instantiated
   */
  static boolean installSessionRegistryCleanup(ServiceInitEvent event, SessionRegistry registry,
                                               String className) {
    SessionDestroyListener cleanup;
    try {
      Class<?> type = Class.forName(className);
      cleanup = (SessionDestroyListener) type.getConstructor(SessionRegistry.class).newInstance(registry);
    } catch (ClassNotFoundException absent) {
      HasLogger.staticLogger().warn("starter/oidc-cleanup-skipped: an OIDC session registry was "
          + "passed, but jCustos-identity-oidc-vaadin is not on the class path; its sessions are "
          + "not forgotten when Vaadin destroys them");
      return false;
    } catch (ReflectiveOperationException | ClassCastException | LinkageError unusable) {
      Throwable cause = unusable instanceof InvocationTargetException invocation
          && invocation.getCause() != null ? invocation.getCause() : unusable;
      HasLogger.staticLogger().warn("starter/oidc-cleanup-skipped: {} could not be created ({})",
          className, cause.getClass().getName());
      return false;
    }
    event.getSource().addSessionDestroyListener(cleanup);
    return true;
  }
}
