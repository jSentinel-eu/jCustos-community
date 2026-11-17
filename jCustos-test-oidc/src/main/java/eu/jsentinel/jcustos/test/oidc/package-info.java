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
/**
 * V00.79 OIDC test infrastructure: StubIdentityProvider, MockClock and integration-test helpers for exercising the OIDC RP end to end without mocks.
 *
 * <p><strong>Tests need {@code -Djcustos.dev=true}.</strong> The stub listens on
 * {@code http://127.0.0.1}; jCustos calls plain {@code http} only on a loopback host
 * and only with the system property {@code jcustos.dev=true}
 * ({@link eu.jsentinel.jcustos.net.EndpointSecurity}). Since 00.84.00 (JS-SEC-098)
 * this covers the JWKS endpoint, too, which up to 00.83.00 needed no flag. See
 * {@link eu.jsentinel.jcustos.test.oidc.StubIdentityProvider} for how to set it.
 *
 * @since 00.79.00
 */
package eu.jsentinel.jcustos.test.oidc;
