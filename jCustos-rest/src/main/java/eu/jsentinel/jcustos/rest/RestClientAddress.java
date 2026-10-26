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
package eu.jsentinel.jcustos.rest;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.net.ClientAddressResolver;
import eu.jsentinel.jcustos.net.ClientRequestView;

import java.util.Objects;
import java.util.Optional;

/**
 * Client address of a {@link RestRequest}, resolved through the registered
 * {@link ClientAddressResolver} (JS-SEC-061, CWE-348). Handlers that key
 * throttles or audit lines on the client use this instead of reading a header
 * or {@link RestRequest#remoteAddress()} themselves.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class RestClientAddress {

  private RestClientAddress() {
  }

  /**
   * Resolves the client address. Never throws.
   *
   * @param request the request
   * @return the address, or empty when the transport exposes no peer or the resolver yields nothing
   */
  public static Optional<String> resolve(RestRequest request) {
    Objects.requireNonNull(request, "request");
    try {
      return JCustosServiceResolver.clientAddressResolver().resolve(view(request));
    } catch (RuntimeException resolverFailure) {
      return Optional.empty();
    }
  }

  /**
   * The transport-neutral view the resolver works on.
   *
   * @param request the request
   * @return peer address and headers of the request
   */
  public static ClientRequestView view(RestRequest request) {
    Objects.requireNonNull(request, "request");
    return ClientRequestView.of(request.remoteAddress(), request.headers());
  }
}
