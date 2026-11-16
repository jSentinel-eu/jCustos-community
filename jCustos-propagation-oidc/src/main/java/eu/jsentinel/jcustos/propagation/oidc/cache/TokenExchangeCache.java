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
package eu.jsentinel.jcustos.propagation.oidc.cache;


import java.time.Instant;
import java.util.Optional;

/**
 * V00.74 cache for exchanged / minted tokens. Keyed by the inbound
 * subject token + downstream audience (token exchange) or by client id
 * + audience (client credentials).
 *
 * <p>{@link #NONE} disables caching — every {@code resolve(...)} call
 * goes to the IDP. Useful for development; surfaces as
 * {@code propagation/cache-explicitly-disabled} INFO in the
 * diagnostics report.
 *
 * @since 00.74.00
 */
public interface TokenExchangeCache {

  /** No-op cache — every resolve goes to the IDP. */
  TokenExchangeCache NONE = new TokenExchangeCache() {
    @Override
    public Optional<CachedEntry> get(String key) {
      return Optional.empty();
    }

    @Override
    public void put(String key, CachedEntry value) {
    }

    @Override
    public void clear() {
    }
  };

  /** @return the cached value if present and not expired */
  Optional<CachedEntry> get(String key);

  /** Store {@code value} under {@code key}. */
  void put(String key, CachedEntry value);

  /** Drop all entries. */
  void clear();

  /** Cached token-endpoint response. */
  record CachedEntry(String accessToken, Instant expiresAt) {

    /**
     * Masks the access token (JS-SEC-127, CWE-532).
     *
     * @return a description with the expiry only
     */
    @Override
    public String toString() {
      return "CachedEntry[accessToken=***, expiresAt=" + expiresAt + "]";
    }
  }
}
