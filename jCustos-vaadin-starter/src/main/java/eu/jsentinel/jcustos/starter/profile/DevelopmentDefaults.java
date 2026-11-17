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

/**
 * Development profile: mode {@code DEVELOPMENT} and nothing else. Missing services and an
 * incomplete security configuration are reported as warnings; deny-by-default and the login
 * route are left to the application. Switch to {@link ProductionDefaults} or
 * {@link StrictDefaults} before going to production.
 */
public final class DevelopmentDefaults implements VaadinJCustosStarter {

  static final DevelopmentDefaults INSTANCE = new DevelopmentDefaults();

  private DevelopmentDefaults() {
  }

  @Override
  public JCustosBootstrapMode preferredMode() {
    return JCustosBootstrapMode.DEVELOPMENT;
  }
}
