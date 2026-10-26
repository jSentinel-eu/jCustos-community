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

import java.net.InetAddress;
import java.util.Objects;
import java.util.Optional;

/**
 * The resolver the framework falls back to: the address of the connection peer,
 * no header consulted. Correct whenever clients connect directly, and the safe
 * choice when the deployment topology is unknown; behind a reverse proxy every
 * client appears as the proxy, which collapses throttling into one bucket but
 * lets nobody choose another client's bucket.
 * <p>
 * A peer address that parses as an IP literal is returned in canonical form
 * ({@code 203.0.113.5}, {@code 2001:db8::1}); anything else is passed through
 * trimmed, so transports that report hostnames keep working.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class DefaultClientAddressResolver implements ClientAddressResolver {

  /** Shared instance; the class is stateless. */
  public static final DefaultClientAddressResolver INSTANCE = new DefaultClientAddressResolver();

  /** Public for {@code ServiceLoader}; prefer {@link #INSTANCE}. */
  public DefaultClientAddressResolver() {
  }

  @Override
  public Optional<String> resolve(ClientRequestView request) {
    Objects.requireNonNull(request, "request");
    String remote = request.remoteAddress();
    if (remote == null || remote.isBlank()) {
      return Optional.empty();
    }
    Optional<InetAddress> literal = IpLiterals.parse(remote);
    return Optional.of(literal.map(InetAddress::getHostAddress).orElse(remote.trim()));
  }

  @Override
  public String toString() {
    return "DefaultClientAddressResolver[remote peer]";
  }
}
