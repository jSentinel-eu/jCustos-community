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
package eu.jsentinel.jcustos.demo.app;

import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.demo.app.security.model.ConfiguredHashingService;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectoryProvider;
import eu.jsentinel.jcustos.demo.app.security.model.InMemoryDemoUserDirectory;

/**
 * Directory fixtures of the demo's tests. The directory the demo ships with holds no
 * account (JS-SEC-137). A test that needs the well-known demo accounts {@code user/user}
 * (id 2, USER) and {@code demo/demo} (id 3, NERD) switches them on here, explicitly,
 * through the constructor flag the development switch
 * {@value InMemoryDemoUserDirectory#INSECURE_DEMO_ACCOUNTS_PROPERTY} feeds - never by
 * changing the production default.
 */
public final class TestDirectories {

  private TestDirectories() {
  }

  /**
   * Installs a directory with the demo accounts, hashing through the configured
   * pipeline, as the one {@link DemoUserDirectoryProvider} hands out.
   *
   * @return the installed directory
   */
  public static InMemoryDemoUserDirectory installWithDemoAccounts() {
    InMemoryDemoUserDirectory directory = withDemoAccounts(ConfiguredHashingService.INSTANCE);
    DemoUserDirectoryProvider.setDirectory(directory);
    return directory;
  }

  /** A directory with the demo accounts, hashing through {@code hashing}. */
  public static InMemoryDemoUserDirectory withDemoAccounts(PasswordHashingService hashing) {
    return new InMemoryDemoUserDirectory(hashing, true);
  }
}
