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

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.demo.app.security.model.Credentials;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectory;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectoryProvider;
import eu.jsentinel.jcustos.demo.app.security.model.InMemoryDemoUserDirectory;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import com.vaadin.browserless.BrowserlessTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-137 (CWE-798, CWE-1188): the demo ships without accounts - the first
 * administrator comes from the bootstrap flow. The fixed-password demo accounts
 * {@code user/user} and {@code demo/demo} exist only behind the development switch
 * {@value InMemoryDemoUserDirectory#INSECURE_DEMO_ACCOUNTS_PROPERTY}, and the demo
 * refuses to start with that switch in any mode other than {@code DEVELOPMENT}. The
 * demo's own listener runs, as {@code ServiceLoader} would start it.
 */
@DisplayName("JS-SEC-137 — fixed-password demo accounts only behind the development switch")
class InsecureDemoAccountsBrowserlessTest extends BrowserlessTest {

  private static final String SWITCH = InMemoryDemoUserDirectory.INSECURE_DEMO_ACCOUNTS_PROPERTY;

  @BeforeEach
  void setUp() throws Exception {
    System.clearProperty(SWITCH);
    System.setProperty("security.bootstrap.mode", "TRANSIENT_CONSOLE");
    resetStartGuards();
    JCustosServiceResolver.resetAll();
  }

  @AfterEach
  void tearDown() throws Exception {
    System.clearProperty(SWITCH);
    System.clearProperty("security.bootstrap.mode");
    resetStartGuards();
    JCustosServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
  }

  @Test
  @DisplayName("without the switch the demo starts with no account and asks for the first administrator")
  void noFixedPasswordAccountWithoutTheSwitch() {
    assertFalse(InMemoryDemoUserDirectory.insecureDemoAccountsRequested(),
        "the switch must be off unless it is set explicitly");
    DemoUserDirectoryProvider.reset();

    new BootstrapServiceInitListener().serviceInit(null);

    DemoUserDirectory shipped = DemoUserDirectoryProvider.directory();
    assertEquals(0L, shipped.all().count(), "the shipped directory holds no account");
    assertTrue(shipped.findByCredentials(new Credentials("user", "user")).isEmpty());
    assertTrue(shipped.findByCredentials(new Credentials("demo", "demo")).isEmpty());
    assertTrue(BootstrapWiring.instance().stateService().bootstrapRequired(),
        "the first administrator comes from the setup flow");
  }

  @Test
  @DisplayName("with the switch in DEVELOPMENT mode the demo accounts exist")
  void switchCreatesTheAccountsInDevelopment() {
    System.setProperty(SWITCH, "true");
    DemoUserDirectoryProvider.reset();

    new BootstrapServiceInitListener().serviceInit(null);

    assertEquals(JCustosBootstrapMode.DEVELOPMENT, BootstrapServiceInitListener.MODE);
    DemoUserDirectory seeded = DemoUserDirectoryProvider.directory();
    assertTrue(seeded.findByCredentials(new Credentials("user", "user")).isPresent());
    assertTrue(seeded.findByCredentials(new Credentials("demo", "demo")).isPresent());
    assertFalse(seeded.hasAnyAdministrator(), "the administrator never comes from the switch");
  }

  @ParameterizedTest(name = "{0}")
  @EnumSource(value = JCustosBootstrapMode.class, mode = EnumSource.Mode.EXCLUDE, names = "DEVELOPMENT")
  @DisplayName("with the switch, a start in any other mode is refused before the setup token is issued")
  void switchIsRefusedOutsideDevelopment(JCustosBootstrapMode mode) throws Exception {
    System.setProperty(SWITCH, "true");

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> new BootstrapServiceInitListener(mode).serviceInit(null));

    assertTrue(refused.getMessage().contains(SWITCH) && refused.getMessage().contains(mode.name()),
        "the refusal must name the switch and the mode: " + refused.getMessage());
    assertNull(currentWiring(), "the bootstrap wiring and its token must not be created");
    assertFalse(dxBootstrapDone().get(), "the security bootstrap must not run");
  }

  private static void resetStartGuards() throws Exception {
    var wiring = BootstrapWiring.class.getDeclaredField("current");
    wiring.setAccessible(true);
    wiring.set(null, null);
    dxBootstrapDone().set(false);
  }

  private static Object currentWiring() throws Exception {
    var wiring = BootstrapWiring.class.getDeclaredField("current");
    wiring.setAccessible(true);
    return wiring.get(null);
  }

  private static AtomicBoolean dxBootstrapDone() throws Exception {
    var done = BootstrapServiceInitListener.class.getDeclaredField("DX_BOOTSTRAP_DONE");
    done.setAccessible(true);
    return (AtomicBoolean) done.get(null);
  }
}
