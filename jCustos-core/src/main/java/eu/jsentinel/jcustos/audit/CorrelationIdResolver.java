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
package eu.jsentinel.jcustos.audit;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.net.ClientRequestView;

/**
 * Decides the correlation id of a request (R5, JS-SEC-066, CWE-778): the id
 * that ties the audit records of the request to the lines a reverse proxy and
 * the application logged for it.
 * <p>
 * Resolved through {@code JCustosServiceResolver.correlationIdResolver()}: an
 * SPI registration ({@code META-INF/services}) or
 * {@code JCustosServiceResolver.setCorrelationIdResolver(...)} wins;
 * otherwise {@link TrustedPeerCorrelationIdResolver} applies, which takes
 * {@code X-Request-ID} only from a peer the registered
 * {@code ClientAddressResolver} trusts and generates a UUID for every other
 * request. The web adapters call the resolver once per request, through
 * {@link AuditCorrelation#openFor(ClientRequestView)}.
 * <p>
 * A client must never choose its own correlation id: an id taken from a
 * request header lets it attribute its requests to someone else's log lines.
 * Implementations must not throw and must return an id that passes
 * {@link AuditEnvelope#isValidCorrelationId(String)}; a failure or a malformed
 * result is replaced by a server-side UUID and reported.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public interface CorrelationIdResolver {

  /**
   * Resolves the correlation id of a request.
   *
   * @param request the request view: peer address and header lines
   * @return a well-formed correlation id, never {@code null}
   */
  String resolve(ClientRequestView request);
}
