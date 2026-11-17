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
 * Production profile: mode {@code PRODUCTION}, deny-by-default, and the login route of the
 * application's {@code LoginView} when it is unambiguous (JS-SEC-168, CWE-1188).
 * <ul>
 *   <li>{@code PRODUCTION} reports an incomplete security configuration as errors on the
 *       runtime; the application still starts.</li>
 *   <li>{@code denyByDefault(true)}: a route without a security annotation is denied unless
 *       it carries {@code @PublicRoute}. Until 00.84.00 the profile set the mode only, and an
 *       unannotated route was public.</li>
 *   <li>{@code loginRoute(...)}: the route of the one registered {@code LoginView} - see
 *       {@code ProfileDefaults}. Without an unambiguous view the login route stays as it
 *       is.</li>
 * </ul>
 * Apply the profile first ({@code VaadinSecurity.bootstrap().use(productionDefaults())}); a
 * later {@code .denyByDefault(false)} or {@code .loginRoute(...)} overrides it.
 */
public final class ProductionDefaults implements VaadinJCustosStarter {

  static final ProductionDefaults INSTANCE = new ProductionDefaults();

  private ProductionDefaults() {
  }

  @Override
  public JCustosBootstrapMode preferredMode() {
    return JCustosBootstrapMode.PRODUCTION;
  }

  @Override
  public void applyTo(VaadinJCustosBootstrap bootstrap) {
    VaadinJCustosStarter.super.applyTo(bootstrap);
    ProfileDefaults.applyFailClosed(bootstrap);
  }
}
