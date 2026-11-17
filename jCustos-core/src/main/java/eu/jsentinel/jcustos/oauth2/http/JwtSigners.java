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
package eu.jsentinel.jcustos.oauth2.http;

import eu.jsentinel.jcustos.jwt.api.JwtSigner;

import java.util.ServiceLoader;

/**
 * Resolves the {@link JwtSigner} SPI via {@link ServiceLoader} (V00.77) so the
 * form-{@code POST} signs a {@code private_key_jwt} assertion without ever
 * importing a JOSE library — the Nimbus-backed signer lives in
 * {@code jCustos-jwt}. Resolution is memoised; the absence of any provider is
 * an explicit, non-secret failure raised only when {@code private_key_jwt} is
 * actually used. Moved from {@code jCustos-oauth2} to {@code jCustos-core} in
 * 00.84.00 together with {@link OAuth2FormPost}.
 */
final class JwtSigners {

  private static final class Holder {
    private static final JwtSigner INSTANCE = ServiceLoader.load(JwtSigner.class)
        .findFirst()
        .orElse(null);
  }

  private JwtSigners() {
    throw new AssertionError("no instances");
  }

  /**
   * @return the registered {@link JwtSigner}
   * @throws IllegalStateException if no provider is on the classpath (add the
   *                               {@code jCustos-jwt} module)
   */
  public static JwtSigner require() {
    if (Holder.INSTANCE == null) {
      throw new IllegalStateException(
          "oauth2/no-jwt-signer: private_key_jwt requires a JwtSigner provider — "
              + "add the jCustos-jwt module to the classpath");
    }
    return Holder.INSTANCE;
  }
}
