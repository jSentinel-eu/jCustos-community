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

import java.util.List;
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
   * Request headers, one value per header name.
   *
   * <p><strong>Contract for adapters (JS-SEC-113, CWE-348).</strong> HTTP allows a
   * header to arrive on several lines. An adapter must not silently keep one of
   * them:
   * <ul>
   *   <li>A list-valued header that arrives on several lines
   *       ({@code X-Forwarded-For}, {@code Forwarded}, {@code Via}, {@code Accept},
   *       …) is joined in wire order with {@code ", "}, as RFC 9110 §5.3
   *       prescribes. Keeping only the first line hands the decision to the
   *       client: a reverse proxy that appends its own {@code X-Forwarded-For}
   *       line would be dropped and the client's forged line evaluated instead.</li>
   *   <li>A header that carries exactly one value per request
   *       ({@code Authorization}, {@code X-Api-Key}, {@code Cookie}) must not be
   *       joined. Rejecting a request that repeats one of them — with
   *       {@code 400 Bad Request}, before any filter runs — is the adapter's
   *       responsibility; {@link RestHeaderLines#rejectDuplicates(Map, RestResponse)}
   *       does it.</li>
   * </ul>
   * {@link RestHeaderLines#joined(Map)} builds a map that satisfies this contract
   * from the multi-valued header structure most transports expose.
   *
   * @return headers
   */
  Map<String, String> headers();

  /**
   * All values of a request header, one entry per header line, in wire order
   * (JS-SEC-113, CWE-348). The client-address resolution reads
   * {@code X-Forwarded-For} through this method, so that the line a trusted
   * proxy appended is seen even when the client sent a line of its own.
   *
   * <p>Adapters that know their transport override this and return every line.
   * The default derives the answer from {@link #headers()} and keeps existing
   * implementations compiling. It is <strong>lossy</strong>: it can only return
   * what the single-valued map still holds, which is correct if — and only if —
   * that map follows the joining contract of {@link #headers()}.
   *
   * @param name header name, compared case-insensitively
   * @return the values, or an empty list when the header is absent; never {@code null}
   * @since 00.84.00
   */
  default List<String> headerValues(String name) {
    if (name == null) {
      return List.of();
    }
    Map<String, String> headers = headers();
    if (headers == null) {
      return List.of();
    }
    String direct = headers.get(name);
    if (direct != null) {
      return List.of(direct);
    }
    for (Map.Entry<String, String> entry : headers.entrySet()) {
      if (name.equalsIgnoreCase(entry.getKey()) && entry.getValue() != null) {
        return List.of(entry.getValue());
      }
    }
    return List.of();
  }

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
