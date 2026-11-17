/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.propagation.oidc.strategy;

import eu.jsentinel.jcustos.credential.propagation.HeaderValue;
import eu.jsentinel.jcustos.credential.propagation.OutboundCall;
import eu.jsentinel.jcustos.credential.propagation.OutboundTokenStrategy;
import eu.jsentinel.jcustos.credential.propagation.TokenCredential;
import eu.jsentinel.jcustos.net.EndpointSecurity;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.http.OAuth2FormPost;
import eu.jsentinel.jcustos.propagation.oidc.cache.InMemoryTokenExchangeCache;
import eu.jsentinel.jcustos.propagation.oidc.cache.TokenExchangeCache;
import com.svenruppert.dependencies.core.logger.HasLogger;

import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * RFC 8693 OAuth 2.0 Token Exchange strategy. Exchanges the inbound
 * bearer token for a token minted for the downstream audience.
 *
 * <p>HTTPS-only by default; the constructor accepts plain {@code http} to a
 * loopback host when the system property {@code jcustos.dev=true} is set
 * (development carve-out, {@link EndpointSecurity}). With a client id and a
 * secret the client authenticates with {@code client_secret_post}, with an id
 * only as a public client; since 00.84.00 the request goes through the shared
 * {@link OAuth2FormPost} of {@code jCustos-core} (JS-SEC-098).
 *
 * <p>Hard-fails on 4xx / 5xx via {@link JCustosPropagationException}
 * — there is no silent fallback to the no-header path.
 *
 * @since 00.74.00
 */
public final class TokenExchangeStrategy implements OutboundTokenStrategy, HasLogger {

  private static final String AUTHORIZATION = "Authorization";

  /** Stable lookup key. */
  public static final String NAME = "exchange";

  private static final String CODE = "propagation/endpoint-not-https";

  private final URI tokenEndpoint;
  private final Optional<ClientAuthentication> clientAuth;
  private final HttpClient http;
  private final TokenExchangeCache cache;

  /** Convenience: default {@link HttpClient} + {@link InMemoryTokenExchangeCache}. */
  public TokenExchangeStrategy(URI tokenEndpoint, String clientId, String clientSecret) {
    this(tokenEndpoint, clientId, clientSecret, HttpClient.newHttpClient(),
        new InMemoryTokenExchangeCache());
  }

  public TokenExchangeStrategy(URI tokenEndpoint, String clientId, String clientSecret,
                               HttpClient http, TokenExchangeCache cache) {
    if (tokenEndpoint == null) throw new IllegalArgumentException("tokenEndpoint");
    // JS-SEC-098: the one https rule of jCustos (loopback http only with -Djcustos.dev=true).
    this.tokenEndpoint = EndpointSecurity.requireHttps(tokenEndpoint, CODE);
    this.clientAuth = BoundedTokenHttp.clientAuthentication(clientId, clientSecret);
    this.http = http;
    this.cache = cache;
  }

  @Override
  public String name() {
    return NAME;
  }

  @Override
  public Optional<HeaderValue> resolve(OutboundCall call, Optional<TokenCredential> inbound) {
    // JS-SEC-044 (CWE-522): a Class-A RefreshToken / ApiKey must never be sent to the token endpoint
    // as an RFC 8693 subject_token — it would leak (mislabeled as an access_token) via the outbound
    // call. Defer to the single shared decision on TokenCredential, matching PassThroughStrategy.
    if (inbound.isEmpty() || !inbound.get().isForwardableAsSubjectToken()) {
      return Optional.empty();
    }
    String subject = inbound.get().value();
    String key = cacheKey(subject, call.declaredAudience());
    Optional<TokenExchangeCache.CachedEntry> cached = cache.get(key);
    if (cached.isPresent()) {
      return Optional.of(new HeaderValue(AUTHORIZATION, "Bearer " + cached.get().accessToken()));
    }
    // JS-SEC-036 (CWE-770), JS-SEC-098: the shared form-POST bounds the response body.
    OAuth2FormPost.Outcome response = BoundedTokenHttp.post(http, tokenEndpoint,
        form(subject, call.declaredAudience()), clientAuth);
    if (!BoundedTokenHttp.isSuccess(response)) {
      // R010: never put the token-endpoint body in the exception message — OAuth
      // error bodies carry error_description and on a misconfig can echo grant
      // material, and this exception propagates into logs. The thrown message
      // carries only the status code; the body is logged truncated at DEBUG.
      logger().debug("Token endpoint returned HTTP {} (body truncated): {}",
          response.status(), truncateBody(response.body()));
      throw new JCustosPropagationException(response.status(),
          "Token endpoint returned HTTP " + response.status());
    }
    BoundedTokenHttp.MintedToken minted = BoundedTokenHttp.mintedToken(response);
    cache.put(key, new TokenExchangeCache.CachedEntry(
        minted.accessToken(), Instant.now().plusSeconds(minted.expiresInSeconds())));
    return Optional.of(new HeaderValue(AUTHORIZATION, "Bearer " + minted.accessToken()));
  }

  /**
   * R023: the cache must never be keyed on the raw inbound bearer token — that
   * places a live credential verbatim in the cache map (heap dumps / diagnostics
   * leak it). Key on a SHA-256 digest of the token instead: a stable,
   * non-reversible identifier. The raw token is still used for the actual
   * exchange request body, never as a stored key.
   */
  private static String cacheKey(String subjectToken, String audience) {
    return sha256Hex(subjectToken) + "|" + audience;
  }

  private static String sha256Hex(String value) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256")
          .digest(value.getBytes(StandardCharsets.UTF_8));
      StringBuilder sb = new StringBuilder(digest.length * 2);
      for (byte b : digest) {
        sb.append(Character.forDigit((b >> 4) & 0xF, 16))
            .append(Character.forDigit(b & 0xF, 16));
      }
      return sb.toString();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is required but unavailable", e);
    }
  }

  /** Caps a diagnostic body so a large/hostile error response can't flood the log. */
  private static String truncateBody(String body) {
    if (body == null) {
      return "";
    }
    return body.length() <= 256 ? body : body.substring(0, 256) + "…(truncated)";
  }

  /** The grant fields; the client authentication adds {@code client_id} / {@code client_secret}. */
  private static Map<String, String> form(String subject, String audience) {
    Map<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
    form.put("subject_token", subject);
    form.put("subject_token_type", "urn:ietf:params:oauth:token-type:access_token");
    if (!audience.isEmpty()) form.put("audience", audience);
    return form;
  }
}
