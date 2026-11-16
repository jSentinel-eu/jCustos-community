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
package eu.jsentinel.jcustos.demo.standalone;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-137: the demo keeps no password in clear text and has no fixed-password
 * account unless the development switch asks for it; JS-SEC-124: the CLI reports
 * a lockout.
 */
class DemoSecurityAlignmentTest {

  @BeforeAll
  static void seedDemoAccounts() {
    UserDirectory.instance().seedInsecureDemoAccounts();
  }

  @Test
  @DisplayName("JS-SEC-137: passwords are stored as hashes of the credential pipeline")
  void passwordsAreHashed() {
    String stored = UserDirectory.instance().storedPasswordHash("alice").orElseThrow();
    assertTrue(stored.startsWith("$pwh$"), "envelope expected");
    assertFalse(stored.contains("alice"), "no clear-text password in the store");
  }

  @Test
  @DisplayName("JS-SEC-137: the seed switch is off by default")
  void seedSwitchIsOffByDefault() {
    assertFalse(UserDirectory.insecureSeedAccountsRequested());
  }

  @Test
  @DisplayName("JS-SEC-124: repeated failures lock the account out in the CLI")
  void repeatedFailuresLockOut() throws Exception {
    String out = "";
    for (int i = 0; i < 6; i++) {
      ByteArrayOutputStream bytes = new ByteArrayOutputStream();
      try (PrintStream print = new PrintStream(bytes, true, StandardCharsets.UTF_8)) {
        new DemoApp(new BufferedReader(new StringReader("nobody-lockout\nguess-" + i + "\n")), print).run();
      }
      out = bytes.toString(StandardCharsets.UTF_8);
    }
    assertTrue(out.contains("Account locked. Try again in"), out);
  }
}
