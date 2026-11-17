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
package eu.jsentinel.jcustos.net;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.net.InetAddress;
import java.net.URI;
import java.util.Locale;
import java.util.Objects;

/**
 * The one transport rule for every endpoint jCustos calls on its own: token, PAR, revocation,
 * introspection and device endpoints, discovery and UserInfo, JWKS, the HIBP range API and the
 * token endpoints of the propagation strategies (JS-SEC-098, CWE-319, CWE-1041).
 *
 * <p>Up to 00.83.00 six copies of this check existed with two different rules: the JWKS client
 * and the HIBP checker accepted plain {@code http} to {@code localhost}, {@code 127.0.0.1} and
 * {@code ::1} at any time, the OAuth2 clients and the propagation strategies only with
 * {@code -Djcustos.dev=true} and only for {@code localhost} and {@code 127.0.0.1}. Since 00.84.00
 * all of them call {@link #requireHttps(URI, String)}:
 *
 * <ul>
 *   <li>{@code https} with a host is accepted;</li>
 *   <li>{@code http} is accepted only when the system property {@value #DEV_MODE_PROPERTY} is
 *       {@code true} <em>and</em> the host is a loopback host;</li>
 *   <li>everything else is refused with an {@link IllegalArgumentException} whose message starts
 *       with the caller's error code.</li>
 * </ul>
 *
 * <p>A loopback host is recognised from the text of the URI alone, without name resolution, so
 * that neither a resolver nor a hosts file can widen the rule: the name {@code localhost} (in
 * any case), an IPv4 literal in {@code 127.0.0.0/8} and the IPv6 literal {@code ::1} (written as
 * {@code [::1]} in a URI). Names that merely start with {@code localhost} or with a loopback
 * address ({@code localhost.example}, {@code 127.0.0.1.example}) are not loopback hosts.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class EndpointSecurity {

  /**
   * The system property that admits plain {@code http} to a loopback host — for local
   * development and for tests against a stub on {@code 127.0.0.1}. Read on every check, so a test
   * can set and clear it.
   */
  public static final String DEV_MODE_PROPERTY = "jcustos.dev";

  private static final String HTTPS = "https";
  private static final String HTTP = "http";
  private static final String LOCALHOST = "localhost";

  private EndpointSecurity() {
  }

  /**
   * Returns {@code endpoint} if jCustos may call it, and throws otherwise.
   *
   * @param endpoint  the endpoint, non-null
   * @param errorCode the stable error code of the caller (for example
   *                  {@code jwks/uri-not-https}); it starts the exception message
   * @return {@code endpoint}, unchanged
   * @throws IllegalArgumentException if the endpoint is neither {@code https} with a host nor,
   *                                  with {@value #DEV_MODE_PROPERTY}{@code =true}, {@code http}
   *                                  to a loopback host
   */
  public static URI requireHttps(URI endpoint, String errorCode) {
    Objects.requireNonNull(endpoint, "endpoint");
    Objects.requireNonNull(errorCode, "errorCode");
    String scheme = endpoint.getScheme();
    String host = endpoint.getHost();
    if (HTTPS.equalsIgnoreCase(scheme) && host != null && !host.isEmpty()) {
      return endpoint;
    }
    if (HTTP.equalsIgnoreCase(scheme) && isLoopbackHost(host) && devModeEnabled()) {
      return endpoint;
    }
    // Scheme and host only: the path or the query of a misconfigured URI may carry a credential.
    throw new IllegalArgumentException(errorCode + ": the endpoint must use https:// (got: "
        + scheme + "://" + host + "); plain http is accepted only for a loopback host with -D"
        + DEV_MODE_PROPERTY + "=true");
  }

  /**
   * Whether {@code host} names the loopback interface, decided from the text alone (no name
   * resolution): {@code localhost} in any case, an IPv4 literal in {@code 127.0.0.0/8} or the
   * IPv6 literal {@code ::1}, with or without brackets.
   *
   * @param host the host part of a URI, may be {@code null}
   * @return {@code true} for a loopback host
   */
  public static boolean isLoopbackHost(String host) {
    if (host == null || host.isEmpty()) {
      return false;
    }
    if (LOCALHOST.equals(host.toLowerCase(Locale.ROOT))) {
      return true;
    }
    // A URI host carries no port: IpLiterals also accepts "address:port" and "[address]:port",
    // which must not pass as a host here.
    if (host.startsWith("[")) {
      if (!host.endsWith("]")) {
        return false;
      }
    } else if (host.indexOf(':') >= 0 && host.indexOf(':') == host.lastIndexOf(':')) {
      return false;
    }
    return IpLiterals.parse(host).map(InetAddress::isLoopbackAddress).orElse(false);
  }

  /**
   * Whether the development carve-out is switched on ({@value #DEV_MODE_PROPERTY}{@code =true}).
   *
   * @return the current value of the system property
   */
  public static boolean devModeEnabled() {
    return Boolean.getBoolean(DEV_MODE_PROPERTY);
  }
}
