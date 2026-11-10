package eu.jsentinel.jcustos.oidc.api;

import static java.util.Objects.requireNonNull;

import java.net.URI;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * Decides whether a {@code post_logout_redirect_uri} may be sent to the
 * provider (CWE-601).
 *
 * <p>The specification puts this check on the provider: it matches the URI
 * against the ones registered for the client. That is true and remains the
 * primary defence — but it is a check the relying party neither performs nor
 * observes. If the URI reaching the logout request came from the current HTTP
 * request, an attacker controls where the user lands afterwards, and the
 * relying party has handed that decision away without looking at it.
 *
 * <p>Validating here is defence in depth: cheap, local, and it turns a silent
 * dependency on someone else's configuration into an explicit statement of
 * where logout may lead.
 *
 * @since 00.82.00
 */
@FunctionalInterface
public interface PostLogoutRedirectValidator {

  /**
   * @param candidate the URI a caller wants to use, never {@code null}
   * @return {@code true} when the redirect may be requested
   */
  boolean isAllowed(URI candidate);

  /**
   * Accepts every URI — the behaviour of releases before 00.82.00, kept as the
   * default so existing callers are unaffected.
   *
   * <p>Choose this only when the provider's registered-URI check is known to be
   * strict, or when the redirect target is a constant in your own code rather
   * than something derived from a request.
   *
   * @return a validator that permits anything
   */
  static PostLogoutRedirectValidator permitAll() {
    return candidate -> true;
  }

  /**
   * Accepts only URIs whose scheme, host, port and path match one of the given
   * URIs exactly.
   *
   * <p>Comparison is exact rather than prefix-based on purpose. A prefix check
   * on {@code https://app.example.com} also accepts
   * {@code https://app.example.com.attacker.test}, which is the classic way an
   * allowlist ends up permitting the very thing it was written to stop. Query
   * strings and fragments are ignored — they carry no authority.
   *
   * <p>JS-SEC-119 (CWE-601, CWE-20) — what "exactly" means since 00.84.00:
   * <ul>
   *   <li>An {@code http}/{@code https} URI needs a host Java can parse. A name
   *       such as {@code my_app.example.com} (underscore) leaves
   *       {@link URI#getHost()} {@code null}; the comparison used to fall back
   *       to an empty host and thereby matched <em>every</em> other
   *       unparsable host with the same scheme and path. Such an entry is now
   *       refused here with an {@link IllegalArgumentException}, and a
   *       candidate without a parsable host is never allowed.</li>
   *   <li>A URI with user information ({@code https://anything@app.example.com/})
   *       is refused as an entry and never allowed as a candidate — the part
   *       before the {@code @} exists to mislead the reader about the host.</li>
   *   <li>The default port equals no port: {@code https://app.example.com:443/bye}
   *       matches the entry {@code https://app.example.com/bye}, and
   *       {@code :80} likewise for {@code http}.</li>
   *   <li>For other schemes (native-app redirects) a URI without a parsable
   *       host is compared on its raw authority, and an opaque URI on its
   *       scheme-specific part, so that nothing that decides the target drops
   *       out of the comparison.</li>
   * </ul>
   *
   * @param allowed the permitted redirect targets, at least one
   * @return a validator restricted to those targets
   * @throws IllegalArgumentException when no URI is given, or an entry is an
   *         {@code http}/{@code https} URI without a parsable host, or an
   *         entry carries user information
   */
  static PostLogoutRedirectValidator allowOnly(URI... allowed) {
    requireNonNull(allowed, "allowed must not be null");
    if (allowed.length == 0) {
      throw new IllegalArgumentException(
          "allowOnly requires at least one URI — an empty allowlist rejects every logout redirect; "
              + "use permitAll() if that is what you mean");
    }
    Set<String> permitted = new LinkedHashSet<>();
    for (URI uri : allowed) {
      requireNonNull(uri, "allowed must not contain null");
      // JS-SEC-119 (CWE-601, CWE-20): an entry that cannot be compared on its host is a
      // configuration error, not an entry with an empty host.
      permitted.add(normalize(uri).orElseThrow(() -> new IllegalArgumentException(
          "allowOnly cannot compare '" + uri + "' exactly: an http/https entry needs a host "
              + "java.net.URI can parse (letters, digits, '-' and '.'; no underscore) and no entry "
              + "may carry user information ('user@host')")));
    }
    // JS-SEC-119: a candidate that cannot be normalised (no parsable host, user information)
    // is never allowed - it used to match every entry that was equally unparsable.
    return candidate -> candidate != null
        && normalize(candidate).map(permitted::contains).orElse(false);
  }

  /**
   * Scheme, host, port and path — the parts that decide where a browser goes.
   * Empty when the URI cannot be compared on those parts (JS-SEC-119).
   */
  private static Optional<String> normalize(URI uri) {
    String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
    if (uri.isOpaque()) {
      // e.g. a native-app scheme without slashes: everything after the scheme decides
      return Optional.of(scheme + ":" + uri.getRawSchemeSpecificPart());
    }
    boolean web = "http".equals(scheme) || "https".equals(scheme);
    String rawAuthority = uri.getRawAuthority();
    if (uri.getRawUserInfo() != null || (rawAuthority != null && rawAuthority.indexOf('@') >= 0)) {
      return Optional.empty();
    }
    String host;
    if (uri.getHost() != null) {
      host = uri.getHost().toLowerCase(Locale.ROOT);
    } else if (web) {
      return Optional.empty();
    } else {
      // registry-based or absent authority of a non-web scheme: compare it as written
      host = rawAuthority == null ? "" : rawAuthority.toLowerCase(Locale.ROOT);
    }
    int port = uri.getPort();
    if (("https".equals(scheme) && port == 443) || ("http".equals(scheme) && port == 80)) {
      port = -1;
    }
    String path = uri.getPath() == null || uri.getPath().isEmpty() ? "/" : uri.getPath();
    return Optional.of(scheme + "://" + host + ":" + port + path);
  }
}
