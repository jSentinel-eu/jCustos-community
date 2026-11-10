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
package eu.jsentinel.jcustos.oauth2;

/*-
 * #%L
 * jCustos OAuth2 — RP flows (token endpoint, auth-code, refresh, device)
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
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.oauth2.api.AuthorizationCodeFlow;
import eu.jsentinel.jcustos.oauth2.api.CallbackResult;
import eu.jsentinel.jcustos.oauth2.api.OAuth2ClientConfig;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oauth2.api.PkceChallenge;
import eu.jsentinel.jcustos.oauth2.api.PkceVerifier;
import eu.jsentinel.jcustos.oauth2.api.StateEntry;
import eu.jsentinel.jcustos.oauth2.api.StateStore;
import eu.jsentinel.jcustos.oauth2.api.TokenEndpointClient;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

/**
 * The {@link AuthorizationCodeFlow} HTTP implementation (V00.77). Generates a
 * high-entropy single-use {@code state} and a PKCE (S256) verifier, binds them
 * in the {@link StateStore}, and builds the authorization redirect; on the
 * callback it consumes the state single-use and exchanges the code (with the
 * stored verifier) via the {@link TokenEndpointClient}.
 *
 * <p><strong>JS-SEC-150 (CWE-346) — issuer binding of the response (RFC 9207):</strong> when the
 * configuration names an {@linkplain OAuth2ClientConfig#expectedIssuer() expected issuer}, every
 * authorisation request is bound to it (the issuer is recorded in the {@link StateEntry}) and
 * {@link #handleCallback} rejects
 * <ul>
 *   <li>a response whose {@code iss} parameter names another issuer,</li>
 *   <li>a response without {@code iss} when the configuration requires the parameter
 *       ({@link OAuth2ClientConfig#issuerParameterRequired()}, set from the discovery flag
 *       {@code authorization_response_iss_parameter_supported}),</li>
 *   <li>a response whose {@code state} was bound to another issuer.</li>
 * </ul>
 * The first two are decided <em>before</em> the state is consumed, all three before the code is
 * sent anywhere. Without the binding a client that talks to several authorisation servers through
 * one redirect URI can be led to send the code — and the PKCE verifier — of an honest server to
 * the token endpoint of a malicious one (mix-up attack). Give every authorisation server its own
 * redirect URI in addition; the parameter is the defence for servers that announce it.
 *
 * @since 00.77.00
 */
public final class HttpAuthorizationCodeFlow implements AuthorizationCodeFlow, HasLogger {

  /** {@link OAuth2Error.StateInvalid} detail: the response names another issuer (JS-SEC-150). */
  static final String ISSUER_MISMATCH = "oauth2/issuer-mismatch";
  /** {@link OAuth2Error.StateInvalid} detail: the required {@code iss} is missing (JS-SEC-150). */
  static final String ISSUER_MISSING = "oauth2/issuer-missing";
  /** Shortest interval between two WARN lines about a rejected response issuer. */
  private static final Duration ISSUER_WARN_INTERVAL = Duration.ofMinutes(1);

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

  private final OAuth2ClientConfig config;
  private final TokenEndpointClient tokenEndpoint;
  private final StateStore stateStore;
  private final Supplier<Instant> clock;
  private final AtomicLong lastIssuerWarning = new AtomicLong(Long.MIN_VALUE / 2);

  public HttpAuthorizationCodeFlow(OAuth2ClientConfig config, TokenEndpointClient tokenEndpoint,
      StateStore stateStore) {
    this(config, tokenEndpoint, stateStore, Instant::now);
  }

  public HttpAuthorizationCodeFlow(OAuth2ClientConfig config, TokenEndpointClient tokenEndpoint,
      StateStore stateStore, Supplier<Instant> clock) {
    this.config = Objects.requireNonNull(config, "config");
    this.tokenEndpoint = Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
    this.stateStore = Objects.requireNonNull(stateStore, "stateStore");
    this.clock = Objects.requireNonNull(clock, "clock");
    if (config.authorizationEndpoint().isEmpty()) {
      throw new IllegalStateException("oauth2/missing-authorization-endpoint");
    }
    if (config.redirectUri().isEmpty()) {
      throw new IllegalStateException("oauth2/missing-redirect-uri");
    }
  }

  @Override
  public AuthorizationRequest startRequest(StartRequestParams params) {
    Objects.requireNonNull(params, "params");
    String state = randomToken();
    PkceVerifier verifier = PkceVerifier.generate();
    PkceChallenge challenge = verifier.challenge();

    // JS-SEC-150 (CWE-346): bind the request to the issuer it is sent to, so that the callback
    // can tell which authorisation server the state belongs to.
    Map<String, String> extra = config.expectedIssuer()
        .map(issuer -> Map.of(StateEntry.EXTRA_EXPECTED_ISSUER, issuer))
        .orElse(Map.of());
    stateStore.bind(state,
        new StateEntry(verifier.value(), params.nonce(), params.resumeTarget(), extra, clock.get()),
        config.stateTtl());

    Set<String> scopes = new LinkedHashSet<>(config.scopes());
    scopes.addAll(params.additionalScopes());

    StringBuilder query = new StringBuilder();
    append(query, "response_type", "code");
    append(query, "client_id", config.clientId());
    append(query, "redirect_uri", config.redirectUri().orElseThrow().toString());
    if (!scopes.isEmpty()) {
      append(query, "scope", String.join(" ", scopes));
    }
    append(query, "state", state);
    append(query, "code_challenge", challenge.codeChallenge());
    append(query, "code_challenge_method", challenge.method());
    params.nonce().ifPresent(n -> append(query, "nonce", n));
    for (Map.Entry<String, String> e : params.additionalParams().entrySet()) {
      append(query, e.getKey(), e.getValue());
    }

    URI authEndpoint = config.authorizationEndpoint().orElseThrow();
    String sep = authEndpoint.getRawQuery() == null ? "?" : "&";
    return new AuthorizationRequest(URI.create(authEndpoint + sep + query), state);
  }

  @Override
  public Result<CallbackResult, OAuth2Error> handleCallback(CallbackParams params) {
    Objects.requireNonNull(params, "params");
    // JS-SEC-150 (CWE-346, RFC 9207 §2.4): decide on the issuer of the response FIRST — before the
    // error branch (an error must not be attributed to the intended server either), before the
    // single-use state is consumed (the legitimate response still wins) and before the code and
    // the PKCE verifier are sent to a token endpoint.
    Optional<OAuth2Error> issuerError = checkResponseIssuer(params.iss());
    if (issuerError.isPresent()) {
      return Result.failure(issuerError.get());
    }
    if (params.error().isPresent()) {
      return Result.failure(new OAuth2Error.AuthorizationDenied(params.error().get()));
    }
    var entry = stateStore.consume(params.state());
    if (entry.isEmpty()) {
      return Result.failure(new OAuth2Error.StateInvalid("unknown, consumed, or expired state"));
    }
    // JS-SEC-150 (CWE-346): the state itself knows the issuer its request was sent to. A state
    // bound to another issuer than this flow's — or than the response names — belongs to another
    // authorisation server; its code must not reach this flow's token endpoint.
    Optional<String> boundIssuer = entry.get().expectedIssuer();
    if (boundIssuer.isPresent()
        && (config.expectedIssuer().filter(expected -> !expected.equals(boundIssuer.get())).isPresent()
            || params.iss().filter(iss -> !iss.equals(boundIssuer.get())).isPresent())) {
      warnThrottled(ISSUER_MISMATCH,
          "the state was bound to another issuer than the one of this callback; no code exchange");
      return Result.failure(new OAuth2Error.StateInvalid(
          ISSUER_MISMATCH + ": state is bound to another issuer"));
    }
    if (params.code().isEmpty()) {
      return Result.failure(new OAuth2Error.StateInvalid("callback carried neither code nor error"));
    }
    // JS-SEC-059: the single-use state was just consumed, so this is the only point the stored
    // nonce + resumeTarget can be recovered — surface them alongside the tokens so the caller can
    // bind the id_token to the nonce (IdTokenExpectations.of(iss, aud, nonce)).
    StateEntry state = entry.get();
    return tokenEndpoint.exchangeCode(
            params.code().get(),
            config.redirectUri().orElseThrow(),
            PkceVerifier.of(state.pkceVerifier()))
        .map(tokens -> new CallbackResult(tokens, state.nonce(), state.resumeTarget()));
  }

  /**
   * JS-SEC-150 (CWE-346, RFC 9207 §2.4): compares the {@code iss} of the authorisation response
   * with the configured issuer by simple string comparison. Reported through the existing
   * {@link OAuth2Error.StateInvalid} variant — the response does not belong to the request this
   * client made — so the stable sealed {@link OAuth2Error} does not grow; the detail starts with
   * {@link #ISSUER_MISMATCH} or {@link #ISSUER_MISSING}. The received value is attacker-chosen
   * and is neither logged nor echoed.
   */
  private Optional<OAuth2Error> checkResponseIssuer(Optional<String> responseIssuer) {
    if (config.expectedIssuer().isEmpty()) {
      return Optional.empty();
    }
    if (responseIssuer.isEmpty()) {
      if (!config.issuerParameterRequired()) {
        return Optional.empty();
      }
      warnThrottled(ISSUER_MISSING, "the authorisation response carries no iss although the issuer "
          + "announces it; callback rejected, state not consumed");
      return Optional.of(new OAuth2Error.StateInvalid(
          ISSUER_MISSING + ": authorisation response carries no iss parameter"));
    }
    if (!config.expectedIssuer().get().equals(responseIssuer.get())) {
      warnThrottled(ISSUER_MISMATCH, "the authorisation response names another issuer than the "
          + "configured one; callback rejected, state not consumed");
      return Optional.of(new OAuth2Error.StateInvalid(
          ISSUER_MISMATCH + ": authorisation response names another issuer"));
    }
    return Optional.empty();
  }

  /**
   * The callback is reachable anonymously, so a rejected response must not become a way to flood
   * the log: at most one WARN per {@link #ISSUER_WARN_INTERVAL}, DEBUG in between.
   */
  private void warnThrottled(String code, String message) {
    long now = clock.get().getEpochSecond();
    long last = lastIssuerWarning.get();
    if (now - last >= ISSUER_WARN_INTERVAL.toSeconds() && lastIssuerWarning.compareAndSet(last, now)) {
      logger().warn("{}: {}", code, message);
    } else {
      logger().debug("{}: {}", code, message);
    }
  }

  private static String randomToken() {
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    return B64URL.encodeToString(bytes);
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
