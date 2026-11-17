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
package eu.jsentinel.jcustos.jwt.impl;

/*-
 * #%L
 * jCustos JWT — standardized JWT validation
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 * 
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * 
 * https://joinup.ec.europa.eu/software/page/eupl
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.authorization.api.JCustosContext;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.jwt.api.AlgorithmProfile;
import eu.jsentinel.jcustos.jwt.api.ClaimExpectations;
import eu.jsentinel.jcustos.jwt.api.ClockSkewPolicy;
import eu.jsentinel.jcustos.jwt.api.JwtValidator;
import eu.jsentinel.jcustos.jwt.api.JwtValidatorFactory;
import eu.jsentinel.jcustos.jwt.api.JwtValidatorSpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ER29 (CWE-459): {@code resetAll()} used to keep the installed JWT validator, so a validator a
 * bootstrap or test had installed kept validating tokens after the reset. Here the validator comes
 * from the real factory, discovered through {@link ServiceLoader} exactly as the {@code .jwt(...)}
 * bootstrap discovers it. No mocks, and nothing is fetched: building the validator does not
 * contact the JWKS endpoint.
 */
@DisplayName("ER29 — resetAll() forgets a validator built by the real JwtValidatorFactory (no mocks)")
class JwtValidatorResetTest {

  private static final URI JWKS = URI.create("https://idp.example/.well-known/jwks.json");

  @BeforeEach
  @AfterEach
  void resetDefault() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("the default context forgets the installed validator on JCustosServiceResolver.resetAll()")
  void resolverResetAllForgetsTheValidator() {
    JwtValidator validator = realValidator();
    JCustosServiceResolver.setJwtValidator(validator); // what a .jwt(...) bootstrap does
    assertSame(validator, JCustosServiceResolver.findJwtValidator().orElseThrow());

    JCustosServiceResolver.resetAll();

    assertTrue(JCustosServiceResolver.findJwtValidator().isEmpty(),
        "a validator installed before the reset must not validate tokens after it");
  }

  @Test
  @DisplayName("an isolated context forgets the installed validator on JCustosContext.resetAll()")
  void contextResetAllForgetsTheValidator() {
    JCustosContext context = JCustosContext.createIsolated();
    JwtValidator validator = realValidator();
    context.setJwtValidator(validator);
    assertSame(validator, context.findJwtValidator().orElseThrow());

    context.resetAll();

    assertTrue(context.findJwtValidator().isEmpty());
  }

  private static JwtValidator realValidator() {
    JwtValidatorFactory factory = ServiceLoader.load(JwtValidatorFactory.class).findFirst()
        .orElseThrow(() -> new AssertionError("no JwtValidatorFactory registered by jCustos-jwt"));
    assertInstanceOf(NimbusJwtValidatorFactory.class, factory);
    ClaimExpectations expectations = new ClaimExpectations(
        Optional.of("https://idp.example/"), Set.of("api.example"),
        true, false, false, false, ClockSkewPolicy.DEFAULT);
    return factory.create(
        new JwtValidatorSpec(JWKS, AlgorithmProfile.STRICT_MODERN.toAllowList(), expectations));
  }
}
