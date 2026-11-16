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
package eu.jsentinel.jcustos.demo.app.security.model;

import java.util.Objects;

/**
 * Static accessor for the demo's {@link DemoUserDirectory} singleton.
 * <p>
 * Required because several consumers ({@code MyAuthenticationService},
 * {@code MyAuthorizationService}, {@code MyLoginListener}) are loaded via
 * Java SPI {@link java.util.ServiceLoader} and therefore cannot receive
 * the directory through constructor injection. UI views and the bootstrap
 * wiring use the same accessor for consistency.
 * <p>
 * Tests can replace the directory via {@link #setDirectory(DemoUserDirectory)}
 * before exercising the SPI. Calling {@link #reset()} restores the default
 * in-memory implementation, which holds no account unless
 * {@value InMemoryDemoUserDirectory#INSECURE_DEMO_ACCOUNTS_PROPERTY} is set
 * (JS-SEC-137).
 */
public final class DemoUserDirectoryProvider {

  private static volatile DemoUserDirectory directory = new InMemoryDemoUserDirectory();

  private DemoUserDirectoryProvider() {
  }

  public static DemoUserDirectory directory() {
    return directory;
  }

  /** Test seam — install a custom directory instance. */
  public static void setDirectory(DemoUserDirectory replacement) {
    directory = Objects.requireNonNull(replacement, "replacement");
  }

  /** Test seam — restore the default in-memory directory. */
  public static void reset() {
    directory = new InMemoryDemoUserDirectory();
  }
}
