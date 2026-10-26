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

import java.util.Map;

/**
 * Minimal framework-independent REST request abstraction.
 */
public interface RestRequest {

  /**
   * HTTP method.
   *
   * @return method
   */
  String method();

  /**
   * Request path.
   *
   * @return path
   */
  String path();

  /**
   * Request headers.
   *
   * @return headers
   */
  Map<String, String> headers();

  /**
   * Query parameters.
   *
   * @return query parameters
   */
  Map<String, String> queryParameters();

  /**
   * Address of the peer that opened the connection, as the transport reports it
   * (JS-SEC-061, CWE-348). Adapters that know their transport override this;
   * the default keeps existing implementations compiling and means "unknown",
   * in which case no client address is recorded.
   *
   * @return the peer address, or {@code null} when the transport does not expose it
   * @since 00.84.00
   */
  default String remoteAddress() {
    return null;
  }
}
