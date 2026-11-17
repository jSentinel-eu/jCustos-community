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
package eu.jsentinel.jcustos.identity.oidc;

/*-
 * #%L
 * jCustos OIDC — Relying-Party identity layer
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.oidc.api.LogoutInitiator;
import eu.jsentinel.jcustos.oidc.api.LogoutRequest;
import eu.jsentinel.jcustos.oidc.api.PostLogoutRedirectValidator;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Builds the OIDC RP-Initiated Logout 1.0 redirect URL (V00.78): the
 * {@code end_session_endpoint} with {@code id_token_hint} +
 * {@code post_logout_redirect_uri} + {@code state}, all percent-encoded. Pure URL
 * construction — no network call. The {@code end_session_endpoint} comes from
 * discovery / trusted configuration, never from user input.
 *
 * <p>The {@code post_logout_redirect_uri} is a different matter. The provider
 * matches it against its registered set, which is the primary defence — but
 * that check happens somewhere this code cannot see, and if the URI came from
 * the incoming request, an attacker chooses where the user lands after logout
 * (CWE-601). Pass a {@link PostLogoutRedirectValidator} to state locally where
 * logout may lead:
 * <pre>{@code
 *   new RpInitiatedLogoutInitiator(
 *       PostLogoutRedirectValidator.allowOnly(URI.create("https://app.example/signed-out")))
 * }</pre>
 *
 * <p><strong>Without an allowlist nothing is forwarded (JS-SEC-089, CWE-601).</strong> Until
 * 00.84.00 the no-argument constructor forwarded whatever it was given, and both OIDC logout
 * adapters used it, so the provider's registration was the only check. The no-argument
 * constructor now refuses every {@code post_logout_redirect_uri} with the same
 * {@link IllegalArgumentException} an allowlist raises for a target it does not contain, and
 * announces the first such refusal in a JVM with the WARN {@value #UNVALIDATED_REDIRECT_WARNING}.
 * A {@link LogoutRequest} without a {@code post_logout_redirect_uri} is not affected: the
 * provider ends its session and shows its own page, and nothing is logged. Until the exit
 * review of 00.84.00 the WARN was written at construction, also for the configurations it
 * calls correct - a resolver or a view that names no target (RF32).
 */
public final class RpInitiatedLogoutInitiator implements LogoutInitiator {

  /**
   * Code of the WARN an initiator of the no-argument constructor writes once per JVM, when it
   * refuses its first {@code post_logout_redirect_uri}: it has no allowlist.
   *
   * @since 00.84.00
   */
  public static final String UNVALIDATED_REDIRECT_WARNING = "oidc/logout-redirect-unvalidated";

  /** JS-SEC-089: the validator of the no-argument constructor - no target is allowed. */
  private static final PostLogoutRedirectValidator NO_ALLOWLIST = candidate -> false;

  private static final AtomicBoolean UNVALIDATED_REDIRECT_WARNED = new AtomicBoolean(false);
  private static final AtomicInteger UNVALIDATED_REDIRECT_WARNINGS = new AtomicInteger();

  private final PostLogoutRedirectValidator redirectValidator;

  /**
   * An initiator without an allowlist: {@link #buildLogoutUri} refuses every
   * {@code post_logout_redirect_uri} with an {@link IllegalArgumentException} and builds a
   * logout request without one as before (JS-SEC-089, CWE-601). The first refused target in a
   * JVM logs the WARN {@value #UNVALIDATED_REDIRECT_WARNING}; an initiator that is only asked
   * for logouts without a target logs nothing.
   *
   * <p>Until 00.84.00 this constructor forwarded any redirect URI. To keep a redirect target,
   * use {@link #RpInitiatedLogoutInitiator(PostLogoutRedirectValidator)} with
   * {@link PostLogoutRedirectValidator#allowOnly(URI...)}.
   */
  public RpInitiatedLogoutInitiator() {
    this(NO_ALLOWLIST);
  }

  /**
   * @param redirectValidator decides which {@code post_logout_redirect_uri}
   *                          values may be sent, never {@code null}
   * @since 00.82.00
   */
  public RpInitiatedLogoutInitiator(PostLogoutRedirectValidator redirectValidator) {
    this.redirectValidator =
        Objects.requireNonNull(redirectValidator, "redirectValidator must not be null");
  }

  @Override
  public URI buildLogoutUri(URI endSessionEndpoint, LogoutRequest request) {
    Objects.requireNonNull(endSessionEndpoint, "endSessionEndpoint");
    Objects.requireNonNull(request, "request");
    StringBuilder query = new StringBuilder();
    append(query, "id_token_hint", request.idTokenHint());
    request.postLogoutRedirectUri().ifPresent(uri -> {
      if (!redirectValidator.isAllowed(uri)) {
        if (redirectValidator == NO_ALLOWLIST) {
          warnUnvalidatedRedirectOnce();
        }
        // Refuse rather than drop it: a rejected URI means either an attack or a
        // misconfigured allowlist, and silently logging the user out to the
        // provider's default page would hide both. A missing allowlist is the
        // second case (JS-SEC-089). The target may come from the request and the
        // message ends up in logs: java.net.URI admits format characters such as
        // U+202E, so the text is scrubbed (CWE-117).
        throw new IllegalArgumentException(
            "post_logout_redirect_uri is not allowed: "
                + LogFieldScrubber.scrubMessage(uri.toString())
                + (redirectValidator == NO_ALLOWLIST
                    ? " — no allowlist is configured; build the initiator with "
                        + "PostLogoutRedirectValidator.allowOnly(...) if this target is intended"
                    : " — add it to the validator's allowlist if this target is intended"));
      }
      append(query, "post_logout_redirect_uri", uri.toString());
    });
    request.state().ifPresent(state -> append(query, "state", state));

    String separator = endSessionEndpoint.getRawQuery() == null ? "?" : "&";
    return URI.create(endSessionEndpoint + separator + query);
  }

  /**
   * JS-SEC-089 (CWE-601), RF32: a logout without a redirect allowlist is possible, a refused
   * target is never silent - once per JVM, because a view builds an initiator per logout.
   */
  private static void warnUnvalidatedRedirectOnce() {
    if (UNVALIDATED_REDIRECT_WARNED.compareAndSet(false, true)) {
      UNVALIDATED_REDIRECT_WARNINGS.incrementAndGet();
      HasLogger.staticLogger().warn("{}: RpInitiatedLogoutInitiator was built without a "
          + "PostLogoutRedirectValidator and refused a post_logout_redirect_uri; every such "
          + "target is refused until an allowlist is configured. Use new "
          + "RpInitiatedLogoutInitiator(PostLogoutRedirectValidator.allowOnly(...)) with the "
          + "targets registered at the provider (AbstractOidcLogoutView.initiator(), "
          + "OidcLogoutHandler with an initiator).",
          UNVALIDATED_REDIRECT_WARNING);
    }
  }

  /**
   * Diagnostics hook: how often the {@value #UNVALIDATED_REDIRECT_WARNING} warning was written.
   *
   * @return the number of warnings since start-up or the last re-arm
   */
  static int unvalidatedRedirectWarnings() {
    return UNVALIDATED_REDIRECT_WARNINGS.get();
  }

  /** Test hook: re-arms the one-time {@value #UNVALIDATED_REDIRECT_WARNING} warning. */
  static void resetUnvalidatedRedirectWarning() {
    UNVALIDATED_REDIRECT_WARNED.set(false);
    UNVALIDATED_REDIRECT_WARNINGS.set(0);
  }

  private static void append(StringBuilder query, String key, String value) {
    if (query.length() > 0) {
      query.append('&');
    }
    query.append(URLEncoder.encode(key, StandardCharsets.UTF_8))
        .append('=')
        .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
  }
}
