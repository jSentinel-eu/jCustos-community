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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.net.ClientAddressResolver;
import eu.jsentinel.jcustos.net.ClientRequestView;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * The default {@link CorrelationIdResolver} (R5, JS-SEC-066, CWE-778): takes
 * the correlation id from a request header — {@value #X_REQUEST_ID} unless
 * configured otherwise — only when the connection peer is a trusted proxy,
 * and generates a server-side UUID for every other request.
 * <p>
 * Which peers are trusted is the decision of the
 * {@link ClientAddressResolver} ({@link ClientAddressResolver#trustsPeer}):
 * the proxies registered through {@code ClientAddressResolver.trustedProxies(...)}
 * for {@code X-Forwarded-For} are the proxies whose request id is honoured.
 * With the default {@code ClientAddressResolver}, which trusts no peer, every
 * request gets a UUID. The proxy has to set the header itself and replace a
 * value the client sent — for Caddy
 * {@code header_up X-Request-ID {http.request.uuid}}.
 * <p>
 * Even from a trusted peer the header is taken only when it arrived on exactly
 * one line and passes {@link AuditEnvelope#isValidCorrelationId(String)}; a
 * repeated, over-long or malformed value yields a UUID and a warning once per
 * resolver instance. The value is never logged.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class TrustedPeerCorrelationIdResolver implements CorrelationIdResolver, HasLogger {

  /** The header read by default; Caddy fills it from {@code {http.request.uuid}}. */
  public static final String X_REQUEST_ID = "X-Request-ID";

  private final Supplier<? extends ClientAddressResolver> peers;
  private final String headerName;
  private final AtomicBoolean rejectedHeaderWarned = new AtomicBoolean();

  /**
   * Trusts the peers of the {@code ClientAddressResolver} registered with
   * {@link JCustosServiceResolver} at the time of each request, and reads
   * {@value #X_REQUEST_ID}. Public for {@code ServiceLoader}.
   */
  public TrustedPeerCorrelationIdResolver() {
    this(JCustosServiceResolver::clientAddressResolver, X_REQUEST_ID);
  }

  /**
   * Trusts the peers of {@code peers} and reads {@value #X_REQUEST_ID}.
   *
   * @param peers the resolver whose trusted proxies may supply the id
   */
  public TrustedPeerCorrelationIdResolver(ClientAddressResolver peers) {
    this(peers, X_REQUEST_ID);
  }

  /**
   * Trusts the peers of {@code peers} and reads {@code headerName}.
   *
   * @param peers      the resolver whose trusted proxies may supply the id
   * @param headerName the request header carrying the proxy's request id
   */
  public TrustedPeerCorrelationIdResolver(ClientAddressResolver peers, String headerName) {
    this(fixed(peers), headerName);
  }

  /**
   * Trusts the peers of whatever {@code ClientAddressResolver} {@code peers}
   * supplies at the time of each request, and reads {@code headerName}. The
   * security context uses this form so its default follows a client-address
   * resolver registered later.
   *
   * @param peers      supplier of the resolver whose trusted proxies may supply the id
   * @param headerName the request header carrying the proxy's request id
   */
  public TrustedPeerCorrelationIdResolver(Supplier<? extends ClientAddressResolver> peers,
                                          String headerName) {
    this.peers = Objects.requireNonNull(peers, "peers");
    Objects.requireNonNull(headerName, "headerName");
    if (headerName.isBlank()) {
      throw new IllegalArgumentException("headerName must not be blank");
    }
    this.headerName = headerName;
  }

  private static Supplier<ClientAddressResolver> fixed(ClientAddressResolver peers) {
    Objects.requireNonNull(peers, "peers");
    return () -> peers;
  }

  @Override
  public String resolve(ClientRequestView request) {
    Objects.requireNonNull(request, "request");
    if (!trustsPeer(request)) {
      return AuditCorrelation.newId();
    }
    List<String> lines = request.headers(headerName);
    if (lines.isEmpty()) {
      return AuditCorrelation.newId();
    }
    String value = lines.getFirst();
    if (lines.size() != 1 || !AuditEnvelope.isValidCorrelationId(value)) {
      if (rejectedHeaderWarned.compareAndSet(false, true)) {
        logger().warn("audit/correlation-header-rejected: a trusted proxy sent {} {} times or "
            + "with a value that is not 1 to {} characters from [A-Za-z0-9._:-]; such requests "
            + "get a server-side UUID (reported once per resolver)",
            headerName, lines.size(), AuditEnvelope.MAX_CORRELATION_ID_LENGTH);
      }
      return AuditCorrelation.newId();
    }
    return value;
  }

  private boolean trustsPeer(ClientRequestView request) {
    try {
      ClientAddressResolver resolver = peers.get();
      return resolver != null && resolver.trustsPeer(request);
    } catch (RuntimeException resolverFailure) {
      // fail closed: a peer that cannot be judged is not trusted
      return false;
    }
  }

  /**
   * The header this resolver reads.
   *
   * @return the header name
   */
  public String headerName() {
    return headerName;
  }

  @Override
  public String toString() {
    return "TrustedPeerCorrelationIdResolver[" + headerName + "]";
  }
}
