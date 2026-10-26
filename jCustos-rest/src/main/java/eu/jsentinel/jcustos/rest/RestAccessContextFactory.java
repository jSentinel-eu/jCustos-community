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

import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Creates neutral access contexts from REST requests.
 */
public final class RestAccessContextFactory {

  /**
   * Attribute key under which the resolved client address is recorded
   * (JS-SEC-061); absent when the transport exposes no peer address.
   *
   * @since 00.84.00
   */
  public static final String CLIENT_ADDRESS_ATTRIBUTE = "clientAddress";

  /**
   * Creates an access context from a REST request.
   *
   * @param request    request
   * @param subject    authenticated subject
   * @param operation  operation name
   * @param attributes additional attributes
   * @return access context
   */
  public AccessContext create(
      RestRequest request,
      Optional<JCustosSubject> subject,
      String operation,
      Map<String, Object> attributes) {
    Map<String, Object> contextAttributes = new LinkedHashMap<>(
        attributes == null ? Map.of() : attributes);
    // JS-SEC-031 (CWE-117): the request path is attacker-controlled and flows into the
    // audit route (and any consumer of resourceName). Neutralize CR/LF/control chars AND the
    // space delimiter at the adapter boundary (JS-SEC-045: the shared LogFieldScrubber, so this
    // adapter cannot drift from the audit sink) so it cannot forge a downstream log line or field.
    String safePath = LogFieldScrubber.scrub(request.path());
    contextAttributes.put("method", request.method());
    contextAttributes.put("path", safePath);
    contextAttributes.put("queryParameters", Map.copyOf(request.queryParameters()));
    // JS-SEC-061 (CWE-348): the client address comes from the registered ClientAddressResolver,
    // so behind a reverse proxy it is the trusted proxy's X-Forwarded-For entry and never a
    // header the client chose. Scrubbed like the path because it reaches audit lines.
    RestClientAddress.resolve(request)
        .ifPresent(address -> contextAttributes.put(
            CLIENT_ADDRESS_ATTRIBUTE, LogFieldScrubber.scrub(address)));
    return new AccessContext(
        subject,
        "rest-endpoint",
        safePath,
        operation,
        contextAttributes);
  }

}
