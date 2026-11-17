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
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * RFC 6749 §4.4 Client Credentials strategy. Ignores the inbound
 * token — this is service-to-service authentication.
 *
 * <p>Same HTTPS discipline and hard-fail-on-non-2xx contract as
 * {@link TokenExchangeStrategy}. With a client id and a secret the client
 * authenticates with {@code client_secret_post}, with an id only as a public
 * client; since 00.84.00 the request goes through the shared
 * {@link OAuth2FormPost} of {@code jCustos-core} (JS-SEC-098).
 *
 * @since 00.74.00
 */
public final class ClientCredentialsStrategy implements OutboundTokenStrategy, HasLogger {

  private static final String AUTHORIZATION = "Authorization";

  /** Default lookup key. */
  public static final String NAME = "service";

  private static final String CODE = "propagation/endpoint-not-https";

  private final URI tokenEndpoint;
  private final String clientId;
  private final Optional<ClientAuthentication> clientAuth;
  private final HttpClient http;
  private final TokenExchangeCache cache;
  private final String name;

  public static ClientCredentialsStrategy forClient(URI tokenEndpoint,
                                                    String clientId,
                                                    String clientSecret) {
    return new ClientCredentialsStrategy(tokenEndpoint, clientId, clientSecret,
        HttpClient.newHttpClient(), new InMemoryTokenExchangeCache(), NAME);
  }

  public ClientCredentialsStrategy(URI tokenEndpoint, String clientId, String clientSecret,
                                   HttpClient http, TokenExchangeCache cache, String name) {
    if (tokenEndpoint == null) throw new IllegalArgumentException("tokenEndpoint");
    // JS-SEC-098: the one https rule of jCustos (loopback http only with -Djcustos.dev=true).
    this.tokenEndpoint = EndpointSecurity.requireHttps(tokenEndpoint, CODE);
    this.clientId = clientId;
    this.clientAuth = BoundedTokenHttp.clientAuthentication(clientId, clientSecret);
    this.http = http;
    this.cache = cache;
    this.name = (name == null || name.isEmpty()) ? NAME : name;
  }

  @Override
  public String name() {
    return name;
  }

  @Override
  public Optional<HeaderValue> resolve(OutboundCall call, Optional<TokenCredential> inbound) {
    // JS-SEC-014 (CWE-269): include the requested scope in the cache key so a
    // narrower-scope call never receives a broader-scope token minted earlier.
    String key = clientId + "|" + call.declaredAudience()
        + "|" + call.hints().getOrDefault("scope", "");
    Optional<TokenExchangeCache.CachedEntry> cached = cache.get(key);
    if (cached.isPresent()) {
      return Optional.of(new HeaderValue(AUTHORIZATION, "Bearer " + cached.get().accessToken()));
    }
    // JS-SEC-036 (CWE-770), JS-SEC-098: the shared form-POST bounds the response body.
    OAuth2FormPost.Outcome response = BoundedTokenHttp.post(http, tokenEndpoint, form(call), clientAuth);
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

  /** Caps a diagnostic body so a large/hostile error response can't flood the log. */
  private static String truncateBody(String body) {
    if (body == null) {
      return "";
    }
    return body.length() <= 256 ? body : body.substring(0, 256) + "…(truncated)";
  }

  /** The grant fields; the client authentication adds {@code client_id} / {@code client_secret}. */
  private static Map<String, String> form(OutboundCall call) {
    Map<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", "client_credentials");
    if (!call.declaredAudience().isEmpty()) form.put("audience", call.declaredAudience());
    String scope = call.hints().getOrDefault("scope", "");
    if (!scope.isEmpty()) form.put("scope", scope);
    return form;
  }
}
