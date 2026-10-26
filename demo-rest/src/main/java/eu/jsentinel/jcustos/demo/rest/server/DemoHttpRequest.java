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
package eu.jsentinel.jcustos.demo.rest.server;

import eu.jsentinel.jcustos.rest.BodyRestRequest;

import java.nio.charset.StandardCharsets;
import java.util.Map;

/** Demo {@link BodyRestRequest} implementation backed by raw byte payloads. */
public final class DemoHttpRequest implements BodyRestRequest {

  private final String method;
  private final String path;
  private final Map<String, String> headers;
  private final Map<String, String> queryParameters;
  private final byte[] body;
  private final String remoteAddress;

  public DemoHttpRequest(
      String method,
      String path,
      Map<String, String> headers,
      Map<String, String> queryParameters,
      byte[] body) {
    this(method, path, headers, queryParameters, body, null);
  }

  /**
   * @param remoteAddress connection peer as the transport reports it, or {@code null}
   *                      (JS-SEC-061: the client address is resolved from it, never from a header)
   */
  public DemoHttpRequest(
      String method,
      String path,
      Map<String, String> headers,
      Map<String, String> queryParameters,
      byte[] body,
      String remoteAddress) {
    this.method = method;
    this.path = path;
    this.headers = Map.copyOf(headers);
    this.queryParameters = Map.copyOf(queryParameters);
    this.body = body == null ? new byte[0] : body.clone();
    this.remoteAddress = remoteAddress;
  }

  public DemoHttpRequest(
      String method,
      String path,
      Map<String, String> headers,
      Map<String, String> queryParameters,
      String body,
      String remoteAddress) {
    this(method, path, headers, queryParameters,
        body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8), remoteAddress);
  }

  /** Convenience for callers that already have a string body (UTF-8 assumed). */
  public DemoHttpRequest(
      String method,
      String path,
      Map<String, String> headers,
      Map<String, String> queryParameters,
      String body) {
    this(method, path, headers, queryParameters,
        body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8));
  }

  @Override
  public String method() {
    return method;
  }

  @Override
  public String path() {
    return path;
  }

  @Override
  public String remoteAddress() {
    return remoteAddress;
  }

  @Override
  public Map<String, String> headers() {
    return headers;
  }

  @Override
  public Map<String, String> queryParameters() {
    return queryParameters;
  }

  @Override
  public byte[] bodyBytes() {
    return body.clone();
  }
}
