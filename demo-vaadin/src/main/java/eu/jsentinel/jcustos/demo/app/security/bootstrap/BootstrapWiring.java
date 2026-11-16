/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.jsentinel.jcustos.demo.app.security.bootstrap;

import eu.jsentinel.jcustos.bootstrap.BootstrapConfiguration;
import eu.jsentinel.jcustos.bootstrap.BootstrapConfigurationLoader;
import eu.jsentinel.jcustos.bootstrap.BootstrapMode;
import eu.jsentinel.jcustos.bootstrap.BootstrapStartup;
import eu.jsentinel.jcustos.bootstrap.BootstrapStateService;
import eu.jsentinel.jcustos.bootstrap.BootstrapTokenGenerator;
import eu.jsentinel.jcustos.bootstrap.BootstrapTokenOutput;
import eu.jsentinel.jcustos.bootstrap.BootstrapTokenStore;
import eu.jsentinel.jcustos.bootstrap.ConsoleBootstrapTokenOutput;
import eu.jsentinel.jcustos.bootstrap.FileBootstrapTokenOutput;
import eu.jsentinel.jcustos.bootstrap.FileBootstrapTokenStore;
import eu.jsentinel.jcustos.bootstrap.InMemoryBootstrapTokenStore;
import eu.jsentinel.jcustos.bootstrap.InitialAdminBootstrapService;
import eu.jsentinel.jcustos.bootstrap.MinimumLengthPasswordPolicy;
import eu.jsentinel.jcustos.demo.app.security.model.ConfiguredHashingService;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectory;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectoryProvider;

import java.nio.file.Path;

/**
 * Lazy holder for the bootstrap services used by {@code SetupView}.
 * Configuration is read by {@link BootstrapConfigurationLoader} (security-core)
 * — same sysprop / env-var keys as the REST demo.
 *
 * <p>This is the <em>standalone Vaadin demo</em> wiring: the setup view calls
 * {@link InitialAdminBootstrapService} <em>in-JVM</em>. In a target deployment
 * where the REST server is authoritative, the Vaadin UI would call the
 * {@code /api/bootstrap/admin} endpoint instead of using this wiring.
 *
 * <p>The administrator's password is hashed with
 * {@link ConfiguredHashingService} - the pipeline the bootstrap configured
 * and the user directory verifies with (JS-SEC-134). It used to be hashed
 * with {@code PasswordHashingServices.defaults()} while the directory
 * verified with the legacy {@code PasswordHasher}: the administrator the
 * setup created could never log in.
 */
public final class BootstrapWiring {

  /** Demo default — bootstrap is on so the Vaadin demo "just works" when no admin is provisioned. */
  public static final BootstrapMode DEFAULT_MODE = BootstrapMode.TRANSIENT_CONSOLE;
  public static final Path DEFAULT_TOKEN_FILE = Path.of("./data/bootstrap.token");

  private static volatile BootstrapWiring current;

  private final BootstrapStateService stateService;
  private final InitialAdminBootstrapService bootstrapService;

  private BootstrapWiring(BootstrapStateService state, InitialAdminBootstrapService service) {
    this.stateService = state;
    this.bootstrapService = service;
  }

  public BootstrapStateService stateService() {
    return stateService;
  }

  public InitialAdminBootstrapService bootstrapService() {
    return bootstrapService;
  }

  public static BootstrapWiring instance() {
    BootstrapWiring local = current;
    if (local != null) return local;
    synchronized (BootstrapWiring.class) {
      if (current == null) current = build();
      return current;
    }
  }

  private static BootstrapWiring build() {
    BootstrapConfiguration config = new BootstrapConfigurationLoader().load(
        DEFAULT_MODE, DEFAULT_TOKEN_FILE, BootstrapConfiguration.DEFAULT_VALIDITY);
    DemoUserDirectory directory = DemoUserDirectoryProvider.directory();
    if (config.mode() != BootstrapMode.DISABLED) {
      directory.enableBootstrapMode();
    }
    VaadinAdministratorAccountStore adminStore = new VaadinAdministratorAccountStore(directory);
    BootstrapStateService state = new BootstrapStateService(adminStore, config.mode());
    BootstrapTokenStore tokenStore = config.mode() == BootstrapMode.PERSISTENT_FILE
        ? new FileBootstrapTokenStore(config.tokenFilePath())
        : new InMemoryBootstrapTokenStore();
    BootstrapTokenOutput output = switch (config.mode()) {
      case PERSISTENT_FILE -> new FileBootstrapTokenOutput();
      case TRANSIENT_CONSOLE -> new ConsoleBootstrapTokenOutput("Open /setup to create the first administrator.");
      case DISABLED -> (token, configuration) -> {
        // no-op
      };
    };
    BootstrapStartup.initializeIfRequired(
        state, tokenStore, new BootstrapTokenGenerator(), output, config);
    InitialAdminBootstrapService service = new InitialAdminBootstrapService(
        state, tokenStore, adminStore,
        ConfiguredHashingService.INSTANCE,
        new MinimumLengthPasswordPolicy(8),
        config.tokenValidity(), java.time.Clock.systemUTC());
    return new BootstrapWiring(state, service);
  }
}