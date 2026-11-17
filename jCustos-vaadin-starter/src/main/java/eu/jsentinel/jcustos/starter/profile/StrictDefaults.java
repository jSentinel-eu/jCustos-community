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

/**
 * Strict profile: as {@link ProductionDefaults}, in mode {@code STRICT} - a configuration
 * error raises {@code JCustosBootstrapException} at {@code install()} (JS-SEC-168, CWE-1188).
 * <ul>
 *   <li>{@code denyByDefault(true)}: a route without a security annotation is denied unless
 *       it carries {@code @PublicRoute}. STRICT refuses to start without it
 *       ({@code authorization/allow-by-omission}, JS-SEC-085); until 00.84.00 the profile did
 *       not set it, so every STRICT application had to.</li>
 *   <li>{@code loginRoute(...)}: the route of the one registered {@code LoginView} when it is
 *       unambiguous; otherwise the login route stays as it is.</li>
 * </ul>
 * Apply the profile first; later builder calls override it.
 */
public final class StrictDefaults implements VaadinJCustosStarter {

  static final StrictDefaults INSTANCE = new StrictDefaults();

  private StrictDefaults() {
  }

  @Override
  public JCustosBootstrapMode preferredMode() {
    return JCustosBootstrapMode.STRICT;
  }

  @Override
  public void applyTo(VaadinJCustosBootstrap bootstrap) {
    VaadinJCustosStarter.super.applyTo(bootstrap);
    ProfileDefaults.applyFailClosed(bootstrap);
  }
}
