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
package eu.jsentinel.jcustos.propagation.oidc.strategy;

import eu.jsentinel.jcustos.util.BoundedHttpBody;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

/**
 * JS-SEC-036 (CWE-770): sends a token-endpoint request and reads the response body
 * bounded to {@link #MAX_BODY_BYTES}. The token-propagation strategies previously used
 * {@code BodyHandlers.ofString()}, which buffers the whole response into memory before
 * any inspection — a compromised/misbehaving OP token endpoint (or a TLS-terminating
 * proxy) could return a multi-gigabyte body and OOM the resource server. This reads via
 * {@code ofInputStream()} + {@code readNBytes(MAX + 1)} and rejects an oversized body
 * before it is fully materialized, matching the 1 MiB ceiling used by every other
 * OIDC/OAuth2 HTTP client. The returned {@link Response} mirrors {@code HttpResponse}'s
 * {@code statusCode()} / {@code body()} accessors so callers stay unchanged.
 */
final class BoundedTokenHttp {

  /** Cap on a token-endpoint response body (1 MiB). */
  static final int MAX_BODY_BYTES = 1 << 20;

  private BoundedTokenHttp() {
  }

  /** Sends {@code request} and reads the body bounded to {@link #MAX_BODY_BYTES}. */
  static Response send(HttpClient http, HttpRequest request) {
    HttpResponse<byte[]> response;
    try {
      // Materialising handler: send() returns only once the body is complete, so
      // the request timeout bounds the transfer. Reading the body afterwards
      // would leave a slow trickle unbounded in time (CWE-400).
      response = http.send(request, BoundedHttpBody.ofByteArray(MAX_BODY_BYTES + 1));
    } catch (Exception e) {
      throw new JCustosPropagationException(0,
          "Token endpoint call failed: " + e.getMessage(), e);
    }
    byte[] bytes = response.body();
    if (bytes.length > MAX_BODY_BYTES) {
      throw new JCustosPropagationException(response.statusCode(),
          "Token endpoint response exceeds " + MAX_BODY_BYTES + " bytes");
    }
    return new Response(response.statusCode(), new String(bytes, StandardCharsets.UTF_8));
  }

  /** Status + fully-read (bounded) body, mirroring {@code HttpResponse} accessors. */
  record Response(int statusCode, String body) {

    /**
     * Shows the length of the body, not the body (JS-SEC-127, CWE-532): a token-endpoint
     * response carries the exchanged tokens.
     *
     * @return a description without the body
     */
    @Override
    public String toString() {
      return "Response[statusCode=" + statusCode + ", body=<"
          + (body == null ? 0 : body.length()) + " chars>]";
    }
  }
}
