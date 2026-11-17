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
package eu.jsentinel.jcustos.test;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.jwt.api.JwtValidator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ER29 (CWE-459): the scenario of the finding, driven through the JUnit engine. The first test
 * installs a JWT validator and leaves it behind; the second must not see it. Before the fix
 * {@link JCustosServiceResolver#resetAll()} kept the validator, so the second test saw whatever
 * the first had installed and the outcome depended on the execution order.
 */
@ExtendWith(JCustosTestExtension.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class JCustosTestExtensionOrderIndependenceTest {

  private static final JwtValidator LEFT_OVER = compactJwt -> {
    throw new AssertionError("this validator is never called");
  };

  @Test
  @Order(1)
  @DisplayName("ER29: a test installs a JwtValidator and does not clean up")
  void installsAValidatorAndLeavesIt() {
    JCustosServiceResolver.setJwtValidator(LEFT_OVER);
    assertSame(LEFT_OVER, JCustosServiceResolver.findJwtValidator().orElseThrow());
  }

  @Test
  @Order(2)
  @DisplayName("ER29: the next test starts without that JwtValidator")
  void nextTestStartsWithoutTheValidator() {
    assertTrue(JCustosServiceResolver.findJwtValidator().isEmpty(),
        "JCustosTestExtension must start every test without the validator of an earlier one");
  }
}
