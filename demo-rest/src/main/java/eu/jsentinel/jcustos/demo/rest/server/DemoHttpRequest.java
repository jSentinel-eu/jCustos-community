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
import eu.jsentinel.jcustos.rest.RestHeaderLines;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Demo {@link BodyRestRequest} implementation backed by raw byte payloads.
 * <p>
 * JS-SEC-113 (CWE-348, CWE-290): the request keeps every header line it was built from.
 * {@link #headers()} joins repeated lines in wire order with {@code ", "} and
 * {@link #headerValues(String)} returns each line, so the client-address resolution sees
 * the {@code X-Forwarded-For} line a trusted proxy appended even when the client sent one
 * of its own. {@link DemoHttpRouter} builds requests with
 * {@link #fromHeaderLines(String, String, Map, Map, byte[], String)} and refuses a request
 * that repeats a credential header before any filter runs.
 * <p>
 * JS-SEC-098: the same holds for query parameters. {@link #queryParameterValues()} returns
 * every value of a repeated parameter, so the OAuth2 callback handler sees a repeated
 * {@code state}, {@code code} or {@code iss}; {@link #queryParameters()} keeps the last value.
 * Until the exit review of 00.84.00 the request kept the lossy default of
 * {@code queryParameterValues()} (RF31).
 */
public final class DemoHttpRequest implements BodyRestRequest {

  private final String method;
  private final String path;
  private final Map<String, List<String>> headerLines;
  private final Map<String, String> headers;
  private final Map<String, String> queryParameters;
  private final Map<String, List<String>> queryParameterValues;
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
    this(singleLines(headers), method, path, singleLines(queryParameters), body, remoteAddress);
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

  private DemoHttpRequest(
      Map<String, List<String>> headerLines,
      String method,
      String path,
      Map<String, List<String>> queryLines,
      byte[] body,
      String remoteAddress) {
    this.method = method;
    this.path = path;
    this.headerLines = copyLines(headerLines);
    this.headers = Map.copyOf(RestHeaderLines.joined(this.headerLines));
    this.queryParameterValues = Map.copyOf(copyLines(queryLines));
    this.queryParameters = Map.copyOf(lastValues(this.queryParameterValues));
    this.body = body == null ? new byte[0] : body.clone();
    this.remoteAddress = remoteAddress;
  }

  /**
   * Builds a request from the header lines as the transport received them (JS-SEC-113).
   *
   * @param method          HTTP method
   * @param path            request path
   * @param headerLines     every header line, per name in wire order
   * @param queryLines      every value of every decoded query parameter, in wire order
   * @param body            raw body, or {@code null}
   * @param remoteAddress   connection peer, or {@code null}
   * @return the request
   */
  public static DemoHttpRequest fromHeaderLines(
      String method,
      String path,
      Map<String, List<String>> headerLines,
      Map<String, List<String>> queryLines,
      byte[] body,
      String remoteAddress) {
    return new DemoHttpRequest(headerLines, method, path, queryLines, body, remoteAddress);
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

  /** Every line of the header, in wire order (JS-SEC-113). */
  @Override
  public List<String> headerValues(String name) {
    return RestHeaderLines.values(headerLines, name);
  }

  @Override
  public Map<String, String> queryParameters() {
    return queryParameters;
  }

  /** Every value of every query parameter, in wire order (JS-SEC-098, RF31). */
  @Override
  public Map<String, List<String>> queryParameterValues() {
    return queryParameterValues;
  }

  @Override
  public byte[] bodyBytes() {
    return body.clone();
  }

  private static Map<String, List<String>> singleLines(Map<String, String> headers) {
    Map<String, List<String>> lines = new LinkedHashMap<>();
    headers.forEach((name, value) -> {
      if (name != null && value != null) {
        lines.put(name, List.of(value));
      }
    });
    return lines;
  }

  /** The single-valued view of query parameters: the last value of each. */
  private static Map<String, String> lastValues(Map<String, List<String>> lines) {
    Map<String, String> last = new LinkedHashMap<>();
    lines.forEach((name, values) -> {
      if (!values.isEmpty()) {
        last.put(name, values.getLast());
      }
    });
    return last;
  }

  private static Map<String, List<String>> copyLines(Map<String, List<String>> headerLines) {
    Map<String, List<String>> copy = new LinkedHashMap<>();
    if (headerLines != null) {
      headerLines.forEach((name, values) -> {
        if (name != null && values != null) {
          List<String> kept = new ArrayList<>();
          for (String value : values) {
            if (value != null) {
              kept.add(value);
            }
          }
          copy.put(name, List.copyOf(kept));
        }
      });
    }
    return copy;
  }
}
