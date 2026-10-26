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

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.function.Function;

/**
 * Transport-neutral view of an inbound request, reduced to what a
 * {@link ClientAddressResolver} needs: the address of the connection peer and
 * the request headers. Adapters (Vaadin, REST) build one per request; the
 * resolver never sees the transport type itself.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public interface ClientRequestView {

  /**
   * Address of the peer that opened the connection, as the transport reports it
   * ({@code getRemoteAddr()} in the servlet world).
   *
   * @return the peer address, or {@code null} when the transport does not expose it
   */
  String remoteAddress();

  /**
   * All values of a request header in wire order. Header names compare
   * case-insensitively.
   *
   * @param name header name
   * @return the values, or an empty list when the header is absent
   */
  List<String> headers(String name);

  /**
   * A view over a single-valued header map, as the REST adapter provides it.
   * Names compare case-insensitively; the map is copied.
   *
   * @param remoteAddress peer address, may be {@code null}
   * @param headers       headers, may be {@code null}
   * @return the view
   */
  static ClientRequestView of(String remoteAddress, Map<String, String> headers) {
    TreeMap<String, String> copy = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    if (headers != null) {
      headers.forEach((name, value) -> {
        if (name != null && value != null) {
          copy.put(name, value);
        }
      });
    }
    return of(remoteAddress, name -> {
      String value = copy.get(name);
      return value == null ? List.of() : List.of(value);
    });
  }

  /**
   * A view over a header lookup function, for transports that expose
   * multi-valued headers.
   *
   * @param remoteAddress peer address, may be {@code null}
   * @param headers       lookup by header name; may return {@code null} for "absent"
   * @return the view
   */
  static ClientRequestView of(String remoteAddress, Function<String, List<String>> headers) {
    Objects.requireNonNull(headers, "headers");
    return new ClientRequestView() {
      @Override
      public String remoteAddress() {
        return remoteAddress;
      }

      @Override
      public List<String> headers(String name) {
        if (name == null) {
          return List.of();
        }
        List<String> values = headers.apply(name);
        return values == null ? List.of() : values;
      }
    };
  }
}
