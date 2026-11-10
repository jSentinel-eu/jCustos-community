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

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Helpers for adapters that bridge a transport with multi-valued headers
 * (JDK {@code HttpExchange}, servlet request, Netty, …) to {@link RestRequest}
 * (JS-SEC-113, CWE-348, CWE-290).
 *
 * <p>HTTP lets a header arrive on several lines. An adapter that reduces such
 * a header to its first line decides in favour of the client: the
 * {@code X-Forwarded-For} line a reverse proxy appended is dropped, the line
 * the client forged is kept. This class gives an adapter the three operations
 * it needs to honour the contract of {@link RestRequest#headers()}:
 *
 * <pre>
 * Map&lt;String, List&lt;String&gt;&gt; lines = exchange.getRequestHeaders();
 * if (RestHeaderLines.rejectDuplicates(lines, response)) {
 *   return;                                       // 400, no filter and no handler ran
 * }
 * Map&lt;String, String&gt; headers = RestHeaderLines.joined(lines);      // RestRequest.headers()
 * List&lt;String&gt; xff = RestHeaderLines.values(lines, name);           // RestRequest.headerValues(name)
 * </pre>
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class RestHeaderLines {

  /** {@code Authorization} request header. */
  public static final String AUTHORIZATION = "Authorization";

  /** {@code X-Api-Key} request header. */
  public static final String X_API_KEY = "X-Api-Key";

  /** {@code Cookie} request header. */
  public static final String COOKIE = "Cookie";

  /**
   * Headers that carry exactly one value per request and therefore must not
   * arrive on more than one line: {@code Authorization}, {@code X-Api-Key} and
   * {@code Cookie}. Two lines mean two components may each pick a different
   * credential — the classic set-up for a confused-deputy or smuggling attack.
   * (An HTTP/2 front end folds split {@code cookie} fields with {@code "; "}
   * before handing the request on, RFC 9113 §8.2.3; what reaches an adapter is
   * one line.)
   */
  public static final List<String> SINGLE_VALUE_HEADERS = List.of(AUTHORIZATION, X_API_KEY, COOKIE);

  /** Body written by {@link #rejectDuplicates}; generic on purpose. */
  public static final String DUPLICATE_HEADER_BODY = "Bad Request";

  /** Separator for joined list-header lines (RFC 9110 §5.3). */
  private static final String LIST_SEPARATOR = ", ";

  private RestHeaderLines() {
  }

  /**
   * All lines of a header in wire order. Names compare case-insensitively;
   * {@code null} lines are skipped.
   *
   * @param headerLines header lines as the transport exposes them; may be {@code null}
   * @param name        header name
   * @return the lines, or an empty list when the header is absent; never {@code null}
   */
  public static List<String> values(Map<String, List<String>> headerLines, String name) {
    if (headerLines == null || name == null) {
      return List.of();
    }
    List<String> values = new ArrayList<>();
    for (Map.Entry<String, List<String>> entry : headerLines.entrySet()) {
      if (name.equalsIgnoreCase(entry.getKey()) && entry.getValue() != null) {
        for (String line : entry.getValue()) {
          if (line != null) {
            values.add(line);
          }
        }
      }
    }
    return List.copyOf(values);
  }

  /**
   * The single-valued map {@link RestRequest#headers()} returns, built from
   * multi-valued header lines: the lines of every header are joined in wire
   * order with {@code ", "}, as RFC 9110 §5.3 prescribes for list-valued
   * headers. No line is dropped.
   *
   * <p>{@link #SINGLE_VALUE_HEADERS} are joined the same way. That is
   * deliberate: an adapter is expected to have rejected a repeated credential
   * header with {@link #rejectDuplicates(Map, RestResponse)} first; if it did
   * not, the joined value is one no credential check accepts, instead of the
   * first line winning silently.
   *
   * @param headerLines header lines as the transport exposes them; may be {@code null}
   * @return a new, mutable map in the iteration order of {@code headerLines}
   */
  public static Map<String, String> joined(Map<String, List<String>> headerLines) {
    Map<String, String> joined = new LinkedHashMap<>();
    if (headerLines == null) {
      return joined;
    }
    for (Map.Entry<String, List<String>> entry : headerLines.entrySet()) {
      if (entry.getKey() == null || entry.getValue() == null) {
        continue;
      }
      List<String> lines = new ArrayList<>();
      for (String line : entry.getValue()) {
        if (line != null) {
          lines.add(line);
        }
      }
      if (!lines.isEmpty()) {
        joined.put(entry.getKey(), String.join(LIST_SEPARATOR, lines));
      }
    }
    return joined;
  }

  /**
   * Finds a {@linkplain #SINGLE_VALUE_HEADERS single-value header} that arrived
   * on more than one line.
   *
   * @param headerLines header lines as the transport exposes them; may be {@code null}
   * @return the name of the first repeated single-value header, or empty
   */
  public static Optional<String> repeatedSingleValueHeader(Map<String, List<String>> headerLines) {
    return repeatedSingleValueHeader(headerLines, SINGLE_VALUE_HEADERS);
  }

  /**
   * Finds a header out of {@code singleValueHeaders} that arrived on more than
   * one line. For adapters whose application authenticates through further
   * single-value headers (a custom token header, say).
   *
   * @param headerLines        header lines as the transport exposes them; may be {@code null}
   * @param singleValueHeaders header names that must not repeat; non-null
   * @return the name of the first repeated header, or empty
   */
  public static Optional<String> repeatedSingleValueHeader(Map<String, List<String>> headerLines,
                                                           Collection<String> singleValueHeaders) {
    Objects.requireNonNull(singleValueHeaders, "singleValueHeaders");
    for (String name : singleValueHeaders) {
      if (values(headerLines, name).size() > 1) {
        return Optional.of(name);
      }
    }
    return Optional.empty();
  }

  /**
   * Rejects a request that repeats {@code Authorization}, {@code X-Api-Key} or
   * {@code Cookie}: writes {@code 400 Bad Request} with a generic body and
   * returns {@code true}. The adapter calls this before it builds the
   * {@link RestRequest} and must not run any filter or handler when the answer
   * is {@code true}.
   *
   * @param headerLines header lines as the transport exposes them; may be {@code null}
   * @param response    the response to write the refusal to; non-null
   * @return {@code true} when the request was rejected and the response is written
   */
  public static boolean rejectDuplicates(Map<String, List<String>> headerLines, RestResponse response) {
    Objects.requireNonNull(response, "response");
    if (repeatedSingleValueHeader(headerLines).isEmpty()) {
      return false;
    }
    return reject(response);
  }

  /**
   * The same check for an already built request, through
   * {@link RestRequest#headerValues(String)}. It only sees what the adapter's
   * {@code headerValues} reports: an adapter that kept the default (derived
   * from the single-valued map) cannot be checked this way and has to use
   * {@link #rejectDuplicates(Map, RestResponse)} on the raw lines.
   *
   * @param request  the request; non-null
   * @param response the response to write the refusal to; non-null
   * @return {@code true} when the request was rejected and the response is written
   */
  public static boolean rejectDuplicates(RestRequest request, RestResponse response) {
    Objects.requireNonNull(request, "request");
    Objects.requireNonNull(response, "response");
    if (!isRepeated(request, SINGLE_VALUE_HEADERS)) {
      return false;
    }
    return reject(response);
  }

  /**
   * Whether the request carries {@code name} on more than one line, as far as
   * {@link RestRequest#headerValues(String)} reports it. Never throws.
   *
   * @param request the request; may be {@code null}
   * @param name    header name
   * @return {@code true} when more than one line was received
   */
  public static boolean isRepeated(RestRequest request, String name) {
    if (request == null || name == null) {
      return false;
    }
    List<String> values = request.headerValues(name);
    return values != null && values.size() > 1;
  }

  private static boolean isRepeated(RestRequest request, Collection<String> names) {
    for (String name : names) {
      if (isRepeated(request, name)) {
        return true;
      }
    }
    return false;
  }

  private static boolean reject(RestResponse response) {
    // JS-SEC-113 (CWE-348, CWE-290): two lines of a credential header are never legitimate;
    // refuse instead of letting each component pick the line it likes. Generic body - the
    // refusal does not say which header tripped it.
    response.status(HttpStatus.BAD_REQUEST.code());
    response.body(DUPLICATE_HEADER_BODY);
    return true;
  }
}
