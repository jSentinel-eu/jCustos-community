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

import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinJCustosBootstrap;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.server.ServiceInitEvent;

import java.util.Set;

/**
 * Default profile for the Vaadin starter, and the starter's one-call service initialisation.
 * <p>
 * A profile is applied via
 * {@link eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinJCustosBootstrap#use(java.util.function.Consumer)}
 * before any user-provided overrides; the user always wins on conflicting configuration.
 *
 * <ul>
 *   <li>{@link DevelopmentDefaults} — mode {@code DEVELOPMENT}; incomplete configuration is
 *       reported as warnings. Nothing else is set.</li>
 *   <li>{@link ProductionDefaults} — mode {@code PRODUCTION}, {@code denyByDefault(true)} and,
 *       when it is unambiguous, the route of the registered {@code LoginView} as login route;
 *       configuration errors are reported on the runtime.</li>
 *   <li>{@link StrictDefaults} — as production, in mode {@code STRICT}; configuration errors
 *       raise {@code JCustosBootstrapException} at {@code install()}.</li>
 * </ul>
 * Until 00.84.00 every profile set the mode only, although this description promised more
 * (JS-SEC-168, CWE-1188). With the production and strict profiles an unannotated route is
 * denied; mark the public ones - home, login, setup - with {@code @PublicRoute}.
 * <p>
 * {@link #serviceInit(ServiceInitEvent, Class)} wires what needs the Vaadin service - the
 * security-version check, its proactive reaction, the reference error handler - in one call
 * from the application's {@code VaadinServiceInitListener}; see {@link VaadinJCustosServiceInit}.
 *
 * @since 00.72.00
 */
public sealed interface VaadinJCustosStarter
    extends java.util.function.Consumer<VaadinJCustosBootstrap>
    permits DevelopmentDefaults, ProductionDefaults, StrictDefaults {

  static VaadinJCustosStarter developmentDefaults() {
    return DevelopmentDefaults.INSTANCE;
  }

  static VaadinJCustosStarter productionDefaults() {
    return ProductionDefaults.INSTANCE;
  }

  static VaadinJCustosStarter strictDefaults() {
    return StrictDefaults.INSTANCE;
  }

  /**
   * Wires the starter's service parts with the default options: the security-version check
   * (when a version store is registered), its proactive reaction (when that store is an
   * {@code ObservableJCustosVersionStore}) and the reference error handler. Call it from the
   * application's {@code VaadinServiceInitListener}, after the bootstrap's {@code install()}:
   * <pre>
   *   public void serviceInit(ServiceInitEvent event) {
   *     VaadinSecurity.bootstrap().use(VaadinJCustosStarter.productionDefaults()) ... .install();
   *     VaadinJCustosStarter.serviceInit(event, MyLoginView.class);
   *   }
   * </pre>
   *
   * @param event         the service-init event; non-null
   * @param rerouteTarget where a session whose security version drifted is sent; non-null
   * @return the parts that were installed
   * @since 00.84.00
   */
  static Set<VaadinJCustosServiceInit.Part> serviceInit(ServiceInitEvent event,
                                                        Class<? extends Component> rerouteTarget) {
    return VaadinJCustosServiceInit.install(event, rerouteTarget, VaadinJCustosServiceInit.Options.defaults());
  }

  /**
   * As {@link #serviceInit(ServiceInitEvent, Class)}, with options - without the error
   * handler, or with the cleanup of an OIDC session registry.
   *
   * @param event         the service-init event; non-null
   * @param rerouteTarget where a session whose security version drifted is sent; non-null
   * @param options       additions and removals; non-null
   * @return the parts that were installed
   * @since 00.84.00
   */
  static Set<VaadinJCustosServiceInit.Part> serviceInit(ServiceInitEvent event,
                                                        Class<? extends Component> rerouteTarget,
                                                        VaadinJCustosServiceInit.Options options) {
    return VaadinJCustosServiceInit.install(event, rerouteTarget, options);
  }

  /** The mode this profile applies (or {@code null} for "do not override"). */
  JCustosBootstrapMode preferredMode();

  /** Hook for adapter-specific configuration. */
  default void applyTo(VaadinJCustosBootstrap bootstrap) {
    JCustosBootstrapMode mode = preferredMode();
    if (mode != null) {
      bootstrap.mode(mode);
    }
  }

  /**
   * {@link java.util.function.Consumer Consumer} bridge so the profile
   * can be passed to
   * {@link VaadinJCustosBootstrap#use(java.util.function.Consumer)}.
   */
  @Override
  default void accept(VaadinJCustosBootstrap bootstrap) {
    applyTo(bootstrap);
  }
}
