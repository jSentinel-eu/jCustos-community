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
package eu.jsentinel.jcustos.identity.oidc.rest;

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.identity.oidc.RpInitiatedLogoutInitiator;
import eu.jsentinel.jcustos.oidc.api.LogoutInitiator;
import eu.jsentinel.jcustos.oidc.api.LogoutRequest;
import eu.jsentinel.jcustos.rest.RestHandler;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestResponse;

import java.net.URI;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * The REST-side OIDC RP-initiated-logout handler (V00.78). Builds the
 * {@code end_session_endpoint} redirect via {@link LogoutInitiator} and replies
 * {@code 302} with a {@code Location} header. The current session's
 * {@code id_token_hint} is supplied by a consumer-provided resolver (the handler
 * does not read tokens from the request itself), and the local session teardown is
 * the consumer's responsibility before/around this redirect.
 *
 * <p><strong>Logout CSRF (JS-SEC-147, CWE-352).</strong> A logout changes state: it ends the
 * local session and, through the {@code id_token_hint}, usually the single-sign-on session
 * at the provider without a further question. Until 00.84.00 the handler answered every
 * method, so a foreign page could log a user out with a plain link or an image tag. It now
 * <ul>
 *   <li>accepts {@code POST} only and answers everything else with
 *       {@code 405 Method Not Allowed} and {@code Allow: POST};</li>
 *   <li>refuses a request whose {@code Origin} header names another origin with
 *       {@code 403 Forbidden}. Without configured origins the header is compared with the
 *       request's own {@code Host}; behind a proxy that rewrites {@code Host}, name the
 *       public origins with {@link #withAllowedOrigins(Set)}. A request without an
 *       {@code Origin} header passes - browsers send it with every cross-origin
 *       {@code POST}, non-browser clients need not.</li>
 * </ul>
 * Map the route as {@code POST} and trigger it from a form or {@code fetch} of the
 * application itself.
 *
 * <p><strong>Where the provider may send the user afterwards (JS-SEC-089, CWE-601).</strong>
 * Until 00.84.00 the two-argument constructor silently forwarded any
 * {@code post_logout_redirect_uri}. It now uses {@code new RpInitiatedLogoutInitiator()},
 * which has no allowlist, refuses every {@code post_logout_redirect_uri} and logs
 * {@code oidc/logout-redirect-unvalidated} once per JVM. A handler whose resolver supplies a
 * {@code post_logout_redirect_uri} is built with an initiator that names the targets:
 * <pre>{@code
 *   new OidcLogoutHandler(endSessionEndpoint,
 *       new RpInitiatedLogoutInitiator(
 *           PostLogoutRedirectValidator.allowOnly(URI.create("https://app.example/signed-out"))),
 *       OidcLogoutHandler.hintFrom(idTokenHint, URI.create("https://app.example/signed-out")));
 * }</pre>
 * A refused target is an {@link IllegalArgumentException} from {@link #handle}; no
 * {@code Location} is set.
 */
public final class OidcLogoutHandler implements RestHandler {

  /** Resolves the OIDC logout parameters for the current request (id_token_hint, …). */
  @FunctionalInterface
  public interface LogoutRequestResolver {
    LogoutRequest resolve(RestRequest request);
  }

  private static final String METHOD_POST = "POST";
  private static final String HEADER_ALLOW = "Allow";
  private static final String HEADER_LOCATION = "Location";
  private static final String HEADER_ORIGIN = "Origin";
  private static final String HEADER_HOST = "Host";

  private final URI endSessionEndpoint;
  private final LogoutInitiator initiator;
  private final LogoutRequestResolver resolver;
  /** Normalised {@code scheme://host[:port]} values; empty means "same host as the request". */
  private final Set<String> allowedOrigins;

  /**
   * A handler whose initiator has no redirect allowlist (JS-SEC-089, CWE-601): every
   * {@code post_logout_redirect_uri} the resolver supplies is refused, and
   * {@code oidc/logout-redirect-unvalidated} is logged once per JVM. Until 00.84.00 this
   * constructor forwarded any target. Use it for resolvers that supply no
   * {@code post_logout_redirect_uri}; otherwise use
   * {@link #OidcLogoutHandler(URI, LogoutInitiator, LogoutRequestResolver)} with
   * {@code new RpInitiatedLogoutInitiator(PostLogoutRedirectValidator.allowOnly(...))}.
   *
   * @param endSessionEndpoint the provider's {@code end_session_endpoint}, from discovery
   * @param resolver           resolves the logout parameters of the current request
   */
  public OidcLogoutHandler(URI endSessionEndpoint, LogoutRequestResolver resolver) {
    this(endSessionEndpoint, new RpInitiatedLogoutInitiator(), resolver);
  }

  /**
   * @param endSessionEndpoint the provider's {@code end_session_endpoint}, from discovery
   * @param initiator          builds the end-session URL and decides which
   *                           {@code post_logout_redirect_uri} may be sent - for instance
   *                           {@code new RpInitiatedLogoutInitiator(
   *                           PostLogoutRedirectValidator.allowOnly(...))} (JS-SEC-089)
   * @param resolver           resolves the logout parameters of the current request
   */
  public OidcLogoutHandler(URI endSessionEndpoint, LogoutInitiator initiator,
      LogoutRequestResolver resolver) {
    this(endSessionEndpoint, initiator, resolver, Set.of());
  }

  private OidcLogoutHandler(URI endSessionEndpoint, LogoutInitiator initiator,
      LogoutRequestResolver resolver, Set<String> allowedOrigins) {
    this.endSessionEndpoint = Objects.requireNonNull(endSessionEndpoint, "endSessionEndpoint");
    this.initiator = Objects.requireNonNull(initiator, "initiator");
    this.resolver = Objects.requireNonNull(resolver, "resolver");
    this.allowedOrigins = allowedOrigins;
  }

  /**
   * Returns a handler that accepts a logout only from the given origins (JS-SEC-147,
   * CWE-352). Use it when the application is reached through a proxy, so the {@code Host}
   * header the handler sees is not the host of the page that sends the request.
   *
   * @param origins the origins of the application as the browser sees them, for example
   *                {@code https://app.example}; scheme and host are compared
   *                case-insensitively, a default port may be left out; non-null, not empty
   * @return a new handler; this one is unchanged
   * @since 00.84.00
   */
  public OidcLogoutHandler withAllowedOrigins(Set<String> origins) {
    Objects.requireNonNull(origins, "origins");
    Set<String> normalised = origins.stream()
        .map(origin -> normaliseOrigin(origin).orElseThrow(() -> new IllegalArgumentException(
            "not an origin (scheme://host[:port]): " + origin)))
        .collect(Collectors.toUnmodifiableSet());
    if (normalised.isEmpty()) {
      throw new IllegalArgumentException("origins must not be empty");
    }
    return new OidcLogoutHandler(endSessionEndpoint, initiator, resolver, normalised);
  }

  @Override
  public void handle(RestRequest request, RestResponse response) {
    // JS-SEC-147 (CWE-352): a logout is a state change - never on GET, HEAD or a link.
    if (!METHOD_POST.equalsIgnoreCase(request.method())) {
      response.status(HttpStatus.METHOD_NOT_ALLOWED.code());
      response.header(HEADER_ALLOW, METHOD_POST);
      return;
    }
    // JS-SEC-147 (CWE-352): a cross-origin POST carries the foreign Origin.
    if (!originAccepted(request)) {
      response.status(HttpStatus.FORBIDDEN.code());
      return;
    }
    LogoutRequest logout = resolver.resolve(request);
    URI redirect = initiator.buildLogoutUri(endSessionEndpoint, logout);
    response.status(HttpStatus.FOUND.code());
    response.header(HEADER_LOCATION, redirect.toString());
  }

  private boolean originAccepted(RestRequest request) {
    String origin = header(request, HEADER_ORIGIN);
    if (origin == null || origin.isBlank()) {
      return true;
    }
    Optional<String> normalised = normaliseOrigin(origin);
    if (normalised.isEmpty()) {
      // "null" (sandboxed frame, redirect chain) and anything unparsable
      return false;
    }
    if (!allowedOrigins.isEmpty()) {
      return allowedOrigins.contains(normalised.get());
    }
    String host = header(request, HEADER_HOST);
    if (host == null || host.isBlank()) {
      return false;
    }
    // the scheme of the request is not part of the abstraction; host and port decide
    String originAuthority = normalised.get().substring(normalised.get().indexOf("://") + 3);
    String requestHost = host.trim().toLowerCase(Locale.ROOT);
    return originAuthority.equals(requestHost)
        || originAuthority.equals(withoutDefaultPort(requestHost));
  }

  /** Header lookup that does not depend on how the adapter spells header names. */
  private static String header(RestRequest request, String name) {
    Map<String, String> headers = request.headers();
    if (headers == null) {
      return null;
    }
    for (Map.Entry<String, String> entry : headers.entrySet()) {
      if (name.equalsIgnoreCase(entry.getKey())) {
        return entry.getValue();
      }
    }
    return null;
  }

  /** @return {@code scheme://host[:port]} in lower case without a default port, if it is an origin */
  private static Optional<String> normaliseOrigin(String origin) {
    if (origin == null) {
      return Optional.empty();
    }
    try {
      URI uri = URI.create(origin.trim());
      String scheme = uri.getScheme();
      String host = uri.getHost();
      if (scheme == null || host == null) {
        return Optional.empty();
      }
      scheme = scheme.toLowerCase(Locale.ROOT);
      host = host.toLowerCase(Locale.ROOT);
      int port = uri.getPort();
      boolean defaultPort = port == -1
          || ("https".equals(scheme) && port == 443)
          || ("http".equals(scheme) && port == 80);
      return Optional.of(scheme + "://" + host + (defaultPort ? "" : ":" + port));
    } catch (IllegalArgumentException notAUri) {
      return Optional.empty();
    }
  }

  private static String withoutDefaultPort(String host) {
    if (host.endsWith(":443")) {
      return host.substring(0, host.length() - 4);
    }
    if (host.endsWith(":80")) {
      return host.substring(0, host.length() - 3);
    }
    return host;
  }

  /**
   * Convenience resolver: a constant id_token_hint source from the request.
   *
   * @param idTokenHint           reads the {@code id_token_hint} from the request
   * @param postLogoutRedirectUri the target after logout, or {@code null} for none; it must be
   *                              allowed by the handler's initiator (JS-SEC-089), which the
   *                              two-argument constructor's initiator never does
   * @return the resolver
   */
  public static LogoutRequestResolver hintFrom(Function<RestRequest, String> idTokenHint,
      URI postLogoutRedirectUri) {
    Objects.requireNonNull(idTokenHint, "idTokenHint");
    return request -> new LogoutRequest(idTokenHint.apply(request),
        Optional.ofNullable(postLogoutRedirectUri), Optional.empty());
  }
}
