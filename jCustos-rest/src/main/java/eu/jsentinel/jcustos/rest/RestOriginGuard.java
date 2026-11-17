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

import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Refuses state-changing REST requests that a browser sent on behalf of another origin
 * (cross-site request forgery, CWE-352): an opt-in guard for applications whose REST
 * endpoints authenticate with a cookie the browser attaches by itself.
 *
 * <p><strong>What it checks.</strong> Requests with a safe method ({@link #SAFE_METHODS}:
 * {@code GET}, {@code HEAD}, {@code OPTIONS}, {@code TRACE}) pass unchecked. Every other
 * method - {@code POST}, {@code PUT}, {@code PATCH}, {@code DELETE} and any method the guard
 * does not know - is decided from the two headers a browser sets itself and a page cannot
 * forge:
 * <ol>
 *   <li>{@code Sec-Fetch-Site: same-origin} or {@code none} (one header line) - the browser
 *       vouches for the initiator: the request passes.</li>
 *   <li>Otherwise the {@code Origin} header decides. It must name the application's own origin
 *       or one of the {@linkplain #withAllowedOrigins(Set) allowed origins}, compared exactly
 *       on scheme, host and port after normalisation (lower case, default port left out) - no
 *       prefix or suffix matching, so {@code https://app.example.attacker.example} is not
 *       {@code https://app.example}. The opaque origin {@code null} (sandboxed frames, some
 *       redirects, {@code Referrer-Policy: no-referrer}), a value with a path, user
 *       information, query or fragment, and a header that arrives on several lines are
 *       refused.</li>
 *   <li>Without {@code Origin}: a request that carries {@code Sec-Fetch-Site} with any other
 *       value is refused - a browser that sends fetch metadata sends {@code Origin} with every
 *       such request, so the missing header cannot be trusted. A request with neither header
 *       comes from a client that is not a browser (curl, a server, a mobile app) and passes by
 *       default; {@link MissingHeaders#REFUSE} refuses it as well.</li>
 * </ol>
 * The application's own origin is taken from the {@code Host} header, because
 * {@link RestRequest} does not carry the request's scheme: host and port decide, a default
 * port ({@code 80}, {@code 443}) in {@code Host} counts as no port, and the {@code Origin} must
 * be an {@code http} or {@code https} origin. Behind a reverse proxy that rewrites {@code Host},
 * name the public origins with {@link #withAllowedOrigins(Set)}; the allowlist then
 * <em>replaces</em> the comparison with {@code Host}, so list the application's own public
 * origin as well.
 *
 * <p><strong>What a refusal looks like.</strong> {@code 403} rendered by the decision mapper
 * published to {@link RestDecisionContext} (falling back to {@link HttpStatusDecisionMapper}),
 * so a configured error-body strategy applies, and an {@link AccessDenied} audit event with the
 * reason {@value #REASON_ORIGIN_MISMATCH} and the request path, inside the request's
 * correlation scope ({@link RestAuditCorrelation}). The handler does not run.
 *
 * <p><strong>How it runs.</strong> The guard is the outermost filter: the router runs
 * {@link #allow(RestRequest, RestResponse)} (or wraps the handler with
 * {@link #guard(RestRequest, RestResponse, RestHandler)}) before any other filter, handler or
 * login code, for every route. {@link #install(RestOriginGuard)} - which the DX bootstrap's
 * {@code .originGuard(...)} calls - makes a guard process-wide, and the router reads it through
 * {@link #installed()}:
 * <pre>{@code
 * if (RestOriginGuard.installed().map(guard -> !guard.allow(request, response)).orElse(false)) {
 *   return;                      // 403 written and audited; no filter and no handler ran
 * }
 * }</pre>
 * The three jCustos REST filters ({@link RestAuthenticationFilter}, {@link RestAuthorizationFilter},
 * {@link RestJCustosVersionFilter}) run the installed guard as well, before their own checks, so a
 * route behind one of them is protected even when the router forgets the step; a route that
 * passes neither the router step nor a jCustos filter is not protected.
 *
 * <p><strong>What it does not cover.</strong> Bearer tokens and API keys are not sent by the
 * browser on its own and need no CSRF protection; the guard does not make them safer. State
 * changes behind a safe method ({@code GET} that deletes) are not checked - such an endpoint is
 * the bug. Clients that are no browser are not authenticated by the guard: a request without
 * {@code Origin} and {@code Sec-Fetch-Site} passes unless {@link MissingHeaders#REFUSE} is set.
 * Vaadin needs no guard: its UIDL requests carry Vaadin's own CSRF token. See
 * {@code docs/security/csrf.md}.
 *
 * <p>{@code OidcLogoutHandler} (JS-SEC-147) delegates its {@code Origin} comparison to
 * {@link #originAccepted(RestRequest)}, which applies step 2 alone.
 *
 * <p>Instances are immutable and thread-safe.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class RestOriginGuard {

  /** Audit reason, and reason of the {@code Forbidden} decision, of a refused request: {@value}. */
  public static final String REASON_ORIGIN_MISMATCH = "csrf:origin-mismatch";

  /** Fetch-metadata request header (W3C Fetch Metadata Request Headers): {@value}. */
  public static final String SEC_FETCH_SITE = "Sec-Fetch-Site";

  /** {@code Origin} request header (RFC 6454 §7): {@value}. */
  public static final String ORIGIN = "Origin";

  /** {@code Host} request header (RFC 9110 §7.2): {@value}. */
  public static final String HOST = "Host";

  /** {@code Sec-Fetch-Site} value of a request the page's own origin started: {@value}. */
  public static final String SITE_SAME_ORIGIN = "same-origin";

  /** {@code Sec-Fetch-Site} value of a request the user started (address bar, bookmark): {@value}. */
  public static final String SITE_NONE = "none";

  /**
   * Methods the guard never checks: the safe methods of RFC 9110 §9.2.1, compared
   * case-insensitively. Every other method is checked, the unknown ones included.
   */
  public static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS", "TRACE");

  private static final String SCHEME_HTTP = "http";
  private static final String SCHEME_HTTPS = "https";
  private static final int DEFAULT_HTTP_PORT = 80;
  private static final int DEFAULT_HTTPS_PORT = 443;
  private static final int NO_PORT = -1;
  private static final String ROOT_PATH = "/";
  private static final String SCHEME_SEPARATOR = "://";

  /** The guard installed process-wide, or {@code null}. */
  private static final AtomicReference<RestOriginGuard> INSTALLED = new AtomicReference<>();

  /**
   * What the guard does with a state-changing request that carries neither
   * {@code Sec-Fetch-Site} nor {@code Origin}. Every current browser sends at least one of the
   * two with such a request; the request comes from another kind of client.
   */
  public enum MissingHeaders {
    /** Let it pass (the default): non-browser clients keep working. */
    ALLOW,
    /** Refuse it like a foreign origin: for APIs that only browsers call. */
    REFUSE
  }

  /** Normalised {@code scheme://host[:port]} values; empty means "the origin of {@code Host}". */
  private final Set<String> allowedOrigins;
  private final MissingHeaders missingHeaders;

  private RestOriginGuard(Set<String> allowedOrigins, MissingHeaders missingHeaders) {
    this.allowedOrigins = allowedOrigins;
    this.missingHeaders = missingHeaders;
  }

  /**
   * A guard that accepts the application's own origin, taken from the {@code Host} header, and
   * lets requests without {@code Origin} and {@code Sec-Fetch-Site} pass.
   *
   * @return the guard
   */
  public static RestOriginGuard sameOrigin() {
    return new RestOriginGuard(Set.of(), MissingHeaders.ALLOW);
  }

  /**
   * Returns a guard that accepts exactly the given origins instead of the origin of the
   * {@code Host} header: for an application behind a proxy that rewrites {@code Host}, or one
   * that is called from the pages of other origins with a cookie (credentialed CORS). List the
   * application's own public origin, too.
   *
   * @param origins the origins as the browser sends them, for example
   *                {@code https://app.example}; scheme and host are compared case-insensitively,
   *                a default port and a trailing {@code /} may be written; non-null, not empty
   * @return a new guard with this guard's {@link MissingHeaders} setting; this one is unchanged
   * @throws IllegalArgumentException when the set is empty or a value is not an origin
   *                                  ({@code scheme://host[:port]}, no path, query or user
   *                                  information; {@code null} and {@code *} are no origins)
   */
  public RestOriginGuard withAllowedOrigins(Set<String> origins) {
    Objects.requireNonNull(origins, "origins");
    Set<String> normalised = new LinkedHashSet<>();
    for (String origin : origins) {
      normalised.add(parseOrigin(origin, true)
          .orElseThrow(() -> new IllegalArgumentException(
              "not an origin (scheme://host[:port]): " + origin))
          .serialised());
    }
    if (normalised.isEmpty()) {
      throw new IllegalArgumentException("origins must not be empty");
    }
    return new RestOriginGuard(Set.copyOf(normalised), missingHeaders);
  }

  /**
   * Returns a guard that treats requests without {@code Origin} and {@code Sec-Fetch-Site} as
   * {@code policy} says.
   *
   * @param policy {@link MissingHeaders#ALLOW} (the default) or {@link MissingHeaders#REFUSE}
   * @return a new guard with this guard's origins; this one is unchanged
   */
  public RestOriginGuard withMissingHeaders(MissingHeaders policy) {
    return new RestOriginGuard(allowedOrigins, Objects.requireNonNull(policy, "policy"));
  }

  /**
   * @return the normalised allowed origins; empty when the origin of {@code Host} is accepted
   */
  public Set<String> allowedOrigins() {
    return allowedOrigins;
  }

  /** @return what happens to a request without {@code Origin} and {@code Sec-Fetch-Site} */
  public MissingHeaders missingHeaders() {
    return missingHeaders;
  }

  // ── decision ───────────────────────────────────────────────────

  /**
   * Whether the request may proceed. Has no side effects: no response is written and nothing
   * is audited.
   *
   * @param request the request; non-null
   * @return {@code true} for a safe method, a request the browser marks as same-origin or
   *         user-initiated, a request from an accepted origin, and - with
   *         {@link MissingHeaders#ALLOW} - a request without either header
   */
  public boolean accepts(RestRequest request) {
    Objects.requireNonNull(request, "request");
    if (isSafe(request.method())) {
      return true;
    }
    List<String> fetchSite = lines(request, SEC_FETCH_SITE);
    if (fetchSite.size() == 1) {
      String site = fetchSite.getFirst().trim().toLowerCase(Locale.ROOT);
      if (SITE_SAME_ORIGIN.equals(site) || SITE_NONE.equals(site)) {
        return true;
      }
    }
    List<String> origins = lines(request, ORIGIN);
    if (origins.isEmpty()) {
      // A browser that marks a request as foreign sends Origin with it; without one there is
      // nothing to verify. Neither header at all: not a browser.
      return fetchSite.isEmpty() && missingHeaders == MissingHeaders.ALLOW;
    }
    return origins.size() == 1 && originMatches(origins.getFirst(), request);
  }

  /**
   * The {@code Origin} comparison alone, without method, {@code Sec-Fetch-Site} and
   * {@link MissingHeaders} (the check {@code OidcLogoutHandler} has run since JS-SEC-147): a
   * request without an {@code Origin} header is accepted, otherwise it must name the own or an
   * allowed origin as described in the class documentation.
   *
   * @param request the request; non-null
   * @return whether the {@code Origin} header, if any, names an accepted origin
   */
  public boolean originAccepted(RestRequest request) {
    Objects.requireNonNull(request, "request");
    List<String> origins = lines(request, ORIGIN);
    if (origins.isEmpty()) {
      return true;
    }
    return origins.size() == 1 && originMatches(origins.getFirst(), request);
  }

  // ── filter ─────────────────────────────────────────────────────

  /**
   * Runs the guard as a filter. On a refusal it writes {@code 403} through the published
   * decision mapper, publishes an {@link AccessDenied} with reason
   * {@value #REASON_ORIGIN_MISMATCH} inside the request's correlation scope and returns
   * {@code false}; the caller must not run the handler. A failing audit sink does not change the
   * decision.
   *
   * @param request  the request; non-null
   * @param response the response a refusal is written to; non-null
   * @return {@code true} when the request may proceed, {@code false} when it was refused
   */
  public boolean allow(RestRequest request, RestResponse response) {
    Objects.requireNonNull(request, "request");
    Objects.requireNonNull(response, "response");
    return RestAuditCorrelation.call(request, () -> !refuse(request, response, null, null));
  }

  /**
   * Runs {@code handler} when {@link #allow(RestRequest, RestResponse)} lets the request pass.
   *
   * @param request  the request; non-null
   * @param response the response; non-null
   * @param handler  the protected handler; non-null
   */
  public void guard(RestRequest request, RestResponse response, RestHandler handler) {
    Objects.requireNonNull(handler, "handler");
    if (allow(request, response)) {
      handler.handle(request, response);
    }
  }

  // ── process-wide installation ──────────────────────────────────

  /**
   * Installs {@code guard} for the process, replacing a guard installed before. The DX
   * bootstrap's {@code .originGuard(...)} calls this.
   *
   * @param guard the guard; non-null
   */
  public static void install(RestOriginGuard guard) {
    INSTALLED.set(Objects.requireNonNull(guard, "guard"));
  }

  /** @return the guard installed for the process, if any */
  public static Optional<RestOriginGuard> installed() {
    return Optional.ofNullable(INSTALLED.get());
  }

  /** Removes the installed guard. Intended for tests and redeploys. */
  public static void reset() {
    INSTALLED.set(null);
  }

  /**
   * Runs the installed guard, if any, for a jCustos filter that is already inside the request's
   * correlation scope.
   *
   * @param request      the request
   * @param response     the response a refusal is written to
   * @param mapper       the filter's own mapper, or {@code null} for the published one
   * @param auditService the filter's own audit service, or {@code null} for the resolver's
   * @return {@code true} when the request was refused and the response written
   */
  static boolean refuseIfCrossOrigin(RestRequest request, RestResponse response,
                                     RestDecisionMapping mapper, JCustosAuditService auditService) {
    RestOriginGuard guard = INSTALLED.get();
    return guard != null && guard.refuse(request, response, mapper, auditService);
  }

  private boolean refuse(RestRequest request, RestResponse response,
                         RestDecisionMapping mapper, JCustosAuditService auditService) {
    if (accepts(request)) {
      return false;
    }
    audit(request, auditService);
    // The mapper renders the refusal, it does not decide it: the caller stops in any case.
    (mapper != null ? mapper : RestDecisionContext.mapperOrDefault())
        .apply(AuthorizationDecision.forbidden(REASON_ORIGIN_MISMATCH), response);
    return true;
  }

  private static void audit(RestRequest request, JCustosAuditService auditService) {
    try {
      JCustosAuditService sink = auditService != null
          ? auditService
          : JCustosServiceResolver.securityAuditService();
      // No subject is resolved: the guard runs before any credential is looked at.
      sink.publish(new AccessDenied(
          Instant.now(Clock.systemUTC()), null, request.path(), REASON_ORIGIN_MISMATCH));
    } catch (RuntimeException auditFailure) {
      // never let a forged request through because the audit sink failed - but say so
      RestSessionRevocation.auditFailed(AccessDenied.class, auditFailure);
    }
  }

  // ── origin comparison ──────────────────────────────────────────

  private boolean originMatches(String value, RestRequest request) {
    Optional<WebOrigin> origin = parseOrigin(value, false);
    if (origin.isEmpty()) {
      // "null" (sandboxed frame, redirect chain, no-referrer) and anything that is no origin
      return false;
    }
    if (!allowedOrigins.isEmpty()) {
      return allowedOrigins.contains(origin.get().serialised());
    }
    List<String> hosts = lines(request, HOST);
    if (hosts.size() != 1) {
      return false;
    }
    Optional<RequestHost> host = parseHost(hosts.getFirst());
    return host.isPresent() && origin.get().isHttp() && origin.get().sameAuthority(host.get());
  }

  /**
   * Parses an origin: {@code scheme://host[:port]}, nothing else. With {@code rootPathAllowed} a
   * trailing {@code /} is tolerated, for configured values.
   */
  private static Optional<WebOrigin> parseOrigin(String value, boolean rootPathAllowed) {
    if (value == null) {
      return Optional.empty();
    }
    URI uri;
    try {
      uri = new URI(value.trim());
    } catch (URISyntaxException notAUri) {
      return Optional.empty();
    }
    String path = uri.getRawPath();
    boolean pathOk = path == null || path.isEmpty() || (rootPathAllowed && ROOT_PATH.equals(path));
    if (uri.getScheme() == null || uri.getHost() == null || uri.getRawUserInfo() != null
        || uri.getRawQuery() != null || uri.getRawFragment() != null || !pathOk) {
      return Optional.empty();
    }
    String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
    int port = uri.getPort();
    if (isDefaultPort(scheme, port)) {
      port = NO_PORT;
    }
    return Optional.of(new WebOrigin(scheme, uri.getHost().toLowerCase(Locale.ROOT), port));
  }

  /** Parses a {@code Host} header value: {@code host[:port]}, nothing else. */
  private static Optional<RequestHost> parseHost(String value) {
    String trimmed = value.trim();
    URI uri;
    try {
      uri = new URI(SCHEME_HTTP + SCHEME_SEPARATOR + trimmed);
    } catch (URISyntaxException notAHost) {
      return Optional.empty();
    }
    String path = uri.getRawPath();
    if (uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawQuery() != null
        || uri.getRawFragment() != null || (path != null && !path.isEmpty())) {
      return Optional.empty();
    }
    return Optional.of(new RequestHost(uri.getHost().toLowerCase(Locale.ROOT), uri.getPort()));
  }

  private static boolean isDefaultPort(String scheme, int port) {
    return port == NO_PORT
        || (SCHEME_HTTPS.equals(scheme) && port == DEFAULT_HTTPS_PORT)
        || (SCHEME_HTTP.equals(scheme) && port == DEFAULT_HTTP_PORT);
  }

  private static boolean isSafe(String method) {
    if (method == null) {
      return false;
    }
    for (String safe : SAFE_METHODS) {
      if (safe.equalsIgnoreCase(method.trim())) {
        return true;
      }
    }
    return false;
  }

  /**
   * Every non-blank line of a header, as the adapter reports it; never {@code null}. When
   * {@link RestRequest#headerValues(String)} reports nothing, the single-valued
   * {@link RestRequest#headers()} is asked as well, so an adapter whose two views disagree
   * cannot hide an {@code Origin} from the guard.
   */
  private static List<String> lines(RestRequest request, String name) {
    List<String> values = request.headerValues(name);
    if (values == null || values.isEmpty()) {
      values = singleValued(request, name);
    }
    List<String> lines = new ArrayList<>(values.size());
    for (String value : values) {
      if (value != null && !value.isBlank()) {
        lines.add(value);
      }
    }
    return lines;
  }

  private static List<String> singleValued(RestRequest request, String name) {
    Map<String, String> headers = request.headers();
    if (headers == null) {
      return List.of();
    }
    for (Map.Entry<String, String> entry : headers.entrySet()) {
      if (name.equalsIgnoreCase(entry.getKey()) && entry.getValue() != null) {
        return List.of(entry.getValue());
      }
    }
    return List.of();
  }

  @Override
  public String toString() {
    return "RestOriginGuard[allowedOrigins="
        + (allowedOrigins.isEmpty() ? "(origin of Host)" : allowedOrigins)
        + ", missingHeaders=" + missingHeaders + "]";
  }

  /** A parsed origin; {@code port} is {@link #NO_PORT} for the scheme's default port. */
  private record WebOrigin(String scheme, String host, int port) {

    String serialised() {
      return scheme + SCHEME_SEPARATOR + host + (port == NO_PORT ? "" : ":" + port);
    }

    boolean isHttp() {
      return SCHEME_HTTP.equals(scheme) || SCHEME_HTTPS.equals(scheme);
    }

    /**
     * Host and port against the {@code Host} header. The request's scheme is unknown, so a
     * default port in {@code Host} counts as no port.
     */
    boolean sameAuthority(RequestHost requestHost) {
      if (!host.equals(requestHost.host())) {
        return false;
      }
      int hostPort = requestHost.port();
      return port == hostPort
          || (port == NO_PORT && (hostPort == DEFAULT_HTTP_PORT || hostPort == DEFAULT_HTTPS_PORT));
    }
  }

  /** The parsed {@code Host} header; {@code port} is {@link #NO_PORT} when none is given. */
  private record RequestHost(String host, int port) {
  }
}
