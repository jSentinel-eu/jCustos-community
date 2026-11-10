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
package eu.jsentinel.jcustos.oauth2.rest;

/*-
 * #%L
 * jCustos OAuth2 — REST callback adapter
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.rest.RestHeaderLines;
import eu.jsentinel.jcustos.rest.RestRequest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Objects;

/**
 * Binds the OAuth2 callback {@code state} to the user-agent that started the
 * flow (V00.81, BL01 / CWE-352). The process-global {@code JdkInMemoryStateStore}
 * only proves a {@code state} was <em>issued</em> — not that this callback comes
 * from the browser that requested it. Without a binding, any caller presenting a
 * stolen (still-unconsumed) {@code state} completes the login (login-CSRF /
 * session fixation).
 *
 * <p>{@link OAuth2CallbackHandler} evaluates the binding <em>before</em> driving
 * the flow: a non-matching callback is rejected fail-closed with a generic
 * {@code 400} and the single-use {@code state} stays unconsumed, so the
 * legitimate browser can still complete its flow.
 *
 * <p>The shipped implementation is {@link #hostCookie()}: at
 * {@code startRequest(...)} time the application emits the
 * {@code Set-Cookie} header produced by {@link #hostCookieHeader(String)}
 * alongside the redirect to the authorization endpoint; on the callback the
 * cookie value must equal the {@code state} query parameter (compared in
 * constant time). The {@code __Host-} prefix pins the cookie to this origin,
 * {@code Secure; HttpOnly; SameSite=Lax; Path=/}.
 *
 * <p>JS-SEC-120 (CWE-352, CWE-565): the prefix is what makes the binding hold —
 * a browser refuses a {@code __Host-} cookie that a sibling subdomain tries to
 * set for the parent domain. Cookie names without the prefix are therefore
 * rejected, and a callback that carries the binding cookie more than once (or
 * several {@code Cookie} header lines) does not match: with two candidates the
 * binding would be whichever one an attacker managed to plant first.
 *
 * @since 00.81.00
 */
@ExperimentalJCustosApi
@FunctionalInterface
public interface CallbackStateBinding {

  /**
   * Cookie-name prefix every binding cookie must carry (JS-SEC-120). The
   * browser accepts a {@code __Host-} cookie only with {@code Secure},
   * {@code Path=/} and without a {@code Domain} attribute, which pins it to
   * the exact origin.
   *
   * @since 00.84.00
   */
  String HOST_COOKIE_PREFIX = "__Host-";

  /** Default cookie carrying the state binding. */
  String DEFAULT_COOKIE_NAME = HOST_COOKIE_PREFIX + "JCustosOAuth2State";

  /** Cookie attributes for the binding cookie (5-minute lifetime, origin-pinned). */
  String COOKIE_ATTRIBUTES = "; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300";

  /**
   * Decides whether the callback carrying {@code state} belongs to the
   * user-agent issuing {@code request}.
   *
   * @param state   the non-blank {@code state} query parameter
   * @param request the callback request
   * @return {@code true} when the callback is bound to this user-agent
   */
  boolean matches(String state, RestRequest request);

  /**
   * The {@code __Host-} cookie binding with the {@link #DEFAULT_COOKIE_NAME}.
   *
   * @return fail-closed cookie binding
   */
  static CallbackStateBinding hostCookie() {
    return hostCookie(DEFAULT_COOKIE_NAME);
  }

  /**
   * The {@code __Host-} cookie binding with a custom cookie name. The callback
   * matches only when the named cookie is present exactly once and its value
   * equals the {@code state} parameter (constant-time comparison).
   *
   * @param cookieName cookie name; must start with {@link #HOST_COOKIE_PREFIX}
   *                   and must not be {@code null} or blank
   * @return fail-closed cookie binding
   * @throws IllegalArgumentException when the name is blank, contains
   *         characters illegal in a cookie name, or lacks the {@code __Host-}
   *         prefix (JS-SEC-120)
   */
  static CallbackStateBinding hostCookie(String cookieName) {
    requireHostCookieName(cookieName);
    return (state, request) -> {
      String cookieValue = cookieValue(request, cookieName);
      if (cookieValue == null || cookieValue.isBlank()) {
        return false;
      }
      return MessageDigest.isEqual(
          cookieValue.getBytes(StandardCharsets.UTF_8),
          state.getBytes(StandardCharsets.UTF_8));
    };
  }

  /**
   * No binding — every callback with a valid {@code state} passes. Only for
   * integrations that already bind {@code state} to the caller themselves
   * (e.g. in the {@code TokenSink} or a wrapping filter).
   *
   * <p>JS-SEC-120: this is never a default. A handler gets it only when the
   * application asks for it by name — through this factory or
   * {@link OAuth2CallbackHandler#withoutUserAgentBinding} — and
   * {@link OAuth2CallbackHandler} logs the open login-CSRF surface
   * ({@code oauth2/state-unbound}) whenever it is constructed with it.
   *
   * @return permissive binding
   */
  static CallbackStateBinding unbound() {
    return UnboundCallbackStateBinding.INSTANCE;
  }

  /**
   * Builds the {@code Set-Cookie} header value the application emits at
   * {@code startRequest(...)} time, using the {@link #DEFAULT_COOKIE_NAME}.
   *
   * @param state the state key returned by {@code startRequest(...)}
   * @return {@code Set-Cookie} header value
   */
  static String hostCookieHeader(String state) {
    return hostCookieHeader(DEFAULT_COOKIE_NAME, state);
  }

  /**
   * Builds the {@code Set-Cookie} header value for a custom cookie name.
   * Rejects control characters in {@code state} (header-injection guard).
   *
   * @param cookieName cookie name; must start with {@link #HOST_COOKIE_PREFIX}
   *                   and must not be {@code null} or blank
   * @param state      the state key returned by {@code startRequest(...)}
   * @return {@code Set-Cookie} header value
   * @throws IllegalArgumentException when the name lacks the {@code __Host-}
   *         prefix (JS-SEC-120) or name or state contain illegal characters
   */
  static String hostCookieHeader(String cookieName, String state) {
    requireHostCookieName(cookieName);
    Objects.requireNonNull(state, "state");
    for (int i = 0; i < state.length(); i++) {
      char c = state.charAt(i);
      if (c < 0x20 || c == 0x7F || c == ';' || c == ',') {
        throw new IllegalArgumentException("state contains characters illegal in a cookie value");
      }
    }
    return cookieName + "=" + state + COOKIE_ATTRIBUTES;
  }

  /**
   * Validates a binding-cookie name: non-blank, legal cookie-name characters
   * and the {@code __Host-} prefix followed by at least one character.
   */
  private static void requireHostCookieName(String cookieName) {
    Objects.requireNonNull(cookieName, "cookieName");
    if (cookieName.isBlank()) {
      throw new IllegalArgumentException("cookieName must not be blank");
    }
    // RF-a (exit review): the NAME feeds the Set-Cookie header too — a control
    // character or separator in it would be header injection just like in the
    // value, so both sides get the same guard.
    for (int i = 0; i < cookieName.length(); i++) {
      char c = cookieName.charAt(i);
      if (c < 0x21 || c == 0x7F || c == ';' || c == ',' || c == '=') {
        throw new IllegalArgumentException("cookieName contains characters illegal in a cookie name");
      }
    }
    // JS-SEC-120 (CWE-352, CWE-565): without the prefix the browser guarantees neither the host
    // binding nor Path=/ - a sibling subdomain could plant the cookie for the parent domain and
    // satisfy the binding with the attacker's own state (login CSRF).
    if (!cookieName.startsWith(HOST_COOKIE_PREFIX) || cookieName.length() == HOST_COOKIE_PREFIX.length()) {
      throw new IllegalArgumentException(
          "cookieName must start with '" + HOST_COOKIE_PREFIX + "' followed by a name: "
              + "only a __Host- cookie binds the callback to this origin");
    }
  }

  /**
   * The value of the binding cookie, or {@code null} when the request does not
   * carry it exactly once.
   */
  private static String cookieValue(RestRequest request, String cookieName) {
    // adapters differ in header-name casing; headerValues compares case-insensitively
    List<String> cookieLines = request.headerValues(RestHeaderLines.COOKIE);
    // JS-SEC-120 / JS-SEC-113: no Cookie header, or more than one line of it - a user-agent
    // sends exactly one. Several lines are no basis for a binding decision.
    if (cookieLines == null || cookieLines.size() != 1 || cookieLines.get(0) == null) {
      return null;
    }
    String prefix = cookieName + "=";
    String found = null;
    for (String part : cookieLines.get(0).split(";")) {
      String candidate = part.trim();
      if (candidate.startsWith(prefix)) {
        if (found != null) {
          // JS-SEC-120 (CWE-565): two cookies of the binding name. Taking the first one is the
          // known weakness of double-submit cookies - a planted cookie would win. Fail closed.
          return null;
        }
        found = candidate.substring(prefix.length());
      }
    }
    return found;
  }
}
