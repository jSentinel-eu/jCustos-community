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
package eu.jsentinel.jcustos.net.vaadin;

import com.vaadin.flow.server.VaadinRequest;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.net.ClientAddressResolver;
import eu.jsentinel.jcustos.net.ClientRequestView;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Client address of a {@link VaadinRequest}, resolved through the registered
 * {@link ClientAddressResolver} (JS-SEC-061, CWE-348). Replaces direct calls to
 * {@code VaadinRequest.getRemoteAddr()} in login views and authentication
 * services, so a reverse-proxy deployment configures the trusted proxies once
 * and every throttle key and audit line follows.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class VaadinClientAddress {

  private VaadinClientAddress() {
  }

  /**
   * Resolves the client address of the current request. Never throws.
   *
   * @return the address, or empty when no request is bound or none can be resolved
   */
  public static Optional<String> current() {
    VaadinRequest request = VaadinRequest.getCurrent();
    return request == null ? Optional.empty() : resolve(request);
  }

  /**
   * Resolves the client address of the given request. Never throws.
   *
   * @param request the request
   * @return the address, or empty when none can be resolved
   */
  public static Optional<String> resolve(VaadinRequest request) {
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
  public static ClientRequestView view(VaadinRequest request) {
    Objects.requireNonNull(request, "request");
    return ClientRequestView.of(request.getRemoteAddr(), name -> {
      Enumeration<String> values = request.getHeaders(name);
      if (values == null) {
        String single = request.getHeader(name);
        return single == null ? List.of() : List.of(single);
      }
      List<String> list = new ArrayList<>();
      while (values.hasMoreElements()) {
        list.add(values.nextElement());
      }
      return list;
    });
  }
}
