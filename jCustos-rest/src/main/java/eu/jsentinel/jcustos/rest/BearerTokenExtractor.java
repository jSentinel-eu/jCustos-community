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

import java.util.Locale;
import java.util.Optional;

/**
 * Extracts a bearer token from the {@code Authorization} header. Never
 * logs the token value.
 *
 * <p>JS-SEC-113 (CWE-290): a request that carries {@code Authorization} on more
 * than one line yields no token. Which of two credentials is "the" credential
 * is not a question to answer by position; the request is treated as
 * unauthenticated. Adapters reject such a request with {@code 400} beforehand
 * ({@link RestHeaderLines#rejectDuplicates}); this is the fail-closed backstop.
 */
public final class BearerTokenExtractor {

  private static final String AUTHORIZATION = RestHeaderLines.AUTHORIZATION;
  private static final String BEARER = "bearer";

  /**
   * Returns the trimmed bearer token, or empty if missing / wrong scheme / blank /
   * sent on more than one {@code Authorization} line.
   */
  public Optional<String> extract(RestRequest request) {
    // JS-SEC-113 (CWE-290): an ambiguous credential is no credential.
    if (RestHeaderLines.isRepeated(request, AUTHORIZATION)) {
      return Optional.empty();
    }
    return RestHeaders.first(request, AUTHORIZATION).flatMap(BearerTokenExtractor::parse);
  }

  private static Optional<String> parse(String header) {
    String trimmed = header.trim();
    int firstSpace = trimmed.indexOf(' ');
    if (firstSpace < 0) return Optional.empty();
    String scheme = trimmed.substring(0, firstSpace);
    if (!BEARER.equals(scheme.toLowerCase(Locale.ROOT))) return Optional.empty();
    String token = trimmed.substring(firstSpace + 1).trim();
    return token.isEmpty() ? Optional.empty() : Optional.of(token);
  }
}
