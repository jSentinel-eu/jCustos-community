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
package eu.jsentinel.jcustos.net;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Decides which address identifies the client of a request (JS-SEC-061,
 * CWE-348). The result keys brute-force throttling and rate limiting and is
 * written to audit lines, so it must not be forgeable by the client.
 * <p>
 * Resolved through {@code JCustosServiceResolver.clientAddressResolver()}:
 * an SPI registration ({@code META-INF/services}) or
 * {@code JCustosServiceResolver.setClientAddressResolver(...)} wins; otherwise
 * {@link #remoteAddress()} applies, which trusts no header at all. Behind a
 * reverse proxy register {@link #trustedProxies(String...)} with the proxy
 * addresses so {@code X-Forwarded-For} is honoured from those peers only.
 * <p>
 * Implementations must not throw and must not perform name resolution.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public interface ClientAddressResolver {

  /**
   * Resolves the client address.
   *
   * @param request the request view
   * @return the address in canonical textual form, or empty when the transport
   *         exposes no usable peer address
   */
  Optional<String> resolve(ClientRequestView request);

  /**
   * The default: the connection peer, no header consulted.
   *
   * @return the shared default resolver
   */
  static ClientAddressResolver remoteAddress() {
    return DefaultClientAddressResolver.INSTANCE;
  }

  /**
   * Honours {@code X-Forwarded-For} appended by the given proxies.
   *
   * @param trustedPeers proxy addresses or CIDR ranges, for example
   *                     {@code "127.0.0.1"}, {@code "::1"}, {@code "10.0.0.0/8"}
   * @return a resolver that trusts exactly those peers
   * @throws IllegalArgumentException when a peer is not an IP literal or CIDR range,
   *                                  or when the collection is empty
   */
  static ClientAddressResolver trustedProxies(String... trustedPeers) {
    return trustedProxies(List.of(trustedPeers));
  }

  /**
   * Honours {@code X-Forwarded-For} appended by the given proxies.
   *
   * @param trustedPeers proxy addresses or CIDR ranges
   * @return a resolver that trusts exactly those peers
   * @throws IllegalArgumentException when a peer is not an IP literal or CIDR range,
   *                                  or when the collection is empty
   */
  static ClientAddressResolver trustedProxies(Collection<String> trustedPeers) {
    return new TrustedProxyClientAddressResolver(trustedPeers);
  }
}
