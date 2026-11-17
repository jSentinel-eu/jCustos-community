package eu.jsentinel.jcustos.jwt.impl;

/*-
 * #%L
 * jCustos JWT — standardized JWT validation
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

import eu.jsentinel.jcustos.util.BoundedHttpBody;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.jwt.api.JoseLimits;
import eu.jsentinel.jcustos.jwt.api.JwksClient;
import eu.jsentinel.jcustos.jwt.api.JwksRefreshResult;
import eu.jsentinel.jcustos.jwt.api.JwsAlgorithm;
import eu.jsentinel.jcustos.net.EndpointSecurity;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * {@link JwksClient} that fetches a JWKS document over HTTP with a disciplined
 * cache (Konzept §9, §16): TTL from {@code Cache-Control: max-age} (default
 * 5 min), a single synchronous refresh on a {@code kid} miss with single-flight
 * stampede protection, a 30-second negative cache on endpoint failures, and a
 * post-miss refresh throttle (JS-SEC-001 / CWE-770): when a refresh does not
 * resolve the sought {@code kid} — a genuinely unknown kid, reachable before
 * signature verification — a short window is opened so a stream of distinct
 * unknown kids cannot force one network refresh each. A hot rotation whose kid
 * arrives outside an open throttle window resolves on the next refresh; a
 * rotation that coincides with a window just opened by a prior unknown-kid probe
 * may be delayed up to {@code REFRESH_MIN_INTERVAL} and then loaded — a bounded,
 * self-limiting availability tradeoff, not a correctness or security issue.
 *
 * <p>HTTPS is enforced at construction (JS-SEC-018 / CWE-319): the {@code jwks_uri}
 * must use {@code https://} — the JWKS is the public-key trust root, so cleartext
 * transport invites key substitution and token forgery. Since 00.84.00 the rule is
 * the one of every other endpoint of jCustos ({@link EndpointSecurity}, JS-SEC-098):
 * plain {@code http://} to a loopback host ({@code localhost}, {@code 127.0.0.0/8},
 * {@code [::1]}) only with {@code -Djcustos.dev=true}. Up to 00.83.00 this client
 * accepted loopback {@code http} without the flag; a test against a JWKS stub on
 * {@code 127.0.0.1} now sets it. The DX bootstrap keeps its own STRICT
 * {@code jwks/uri-not-https} rule for defense in depth.
 *
 * <p><strong>JS-SEC-149 — bounded trust in a stale key set (CWE-672):</strong> while a refresh
 * fails the client keeps serving the keys it already holds, so that a short outage of the issuer
 * does not reject every token. That grace is bounded: once the last <em>successful</em> fetch is
 * older than the maximum staleness (24 hours by default, see {@link #DEFAULT_MAX_STALE}) the key
 * set is dropped, {@link #findKey} returns empty (the validator reports {@code jwt/unknown-kid})
 * and {@code jwks/stale-keys-dropped} is logged once. Without the bound a key the issuer had
 * withdrawn stayed trusted for as long as the endpoint answered with an error — a state an
 * attacker holding the withdrawn key has every reason to prolong. The next successful fetch
 * restores normal operation.
 *
 * <p><strong>JS-SEC-149 — key hygiene (CWE-326):</strong> a key is taken from the document only if
 * it may verify signatures: a key with a {@code use} other than {@code sig}, or with
 * {@code key_ops} that do not contain {@code verify}, is skipped (an encryption key must never
 * become a signature key — a decryption oracle on it would be a signing oracle), and so is an RSA
 * key below {@link JoseLimits#MIN_RSA_MODULUS_BITS} bits. A key that declares an {@code alg} is
 * served only for a token whose header names that very algorithm.
 *
 * @since 00.76.00
 */
public final class HttpJwksClient implements JwksClient, HasLogger {

  private static final Duration DEFAULT_TTL = Duration.ofMinutes(5);
  /** JS-SEC-033 (CWE-613): upper clamp on an endpoint-advertised Cache-Control max-age. */
  private static final Duration MAX_TTL = Duration.ofHours(24);
  private static final Duration NEGATIVE_TTL = Duration.ofSeconds(30);
  /** JS-SEC-001: min interval before another unknown-kid miss may force a refresh. */
  private static final Duration REFRESH_MIN_INTERVAL = Duration.ofSeconds(20);
  private static final Pattern MAX_AGE = Pattern.compile("max-age\\s*=\\s*(\\d+)");
  private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(10);
  /** RF01: a JWKS document is a few KB; a larger body is a hostile / MITM'd endpoint. */
  private static final int MAX_JWKS_BYTES = 1 << 20;
  /**
   * JS-SEC-149 (CWE-672): how long the last successfully fetched key set stays trusted while
   * refreshes fail — the default of {@link #HttpJwksClient(URI, HttpClient, Supplier, Duration)}.
   *
   * @since 00.84.00
   */
  public static final Duration DEFAULT_MAX_STALE = Duration.ofHours(24);

  private final URI jwksUri;
  private final HttpClient httpClient;
  private final Supplier<Instant> clock;
  private final Duration maxStale;

  private final ReentrantLock lock = new ReentrantLock();
  private volatile State state = new State(Map.of(), Instant.EPOCH, Instant.EPOCH, Instant.EPOCH);
  private CompletableFuture<JwksRefreshResult> inFlight;

  public HttpJwksClient(URI jwksUri) {
    this(jwksUri, HttpClient.newBuilder().connectTimeout(HTTP_TIMEOUT).build(), Instant::now);
  }

  public HttpJwksClient(URI jwksUri, HttpClient httpClient, Supplier<Instant> clock) {
    this(jwksUri, httpClient, clock, DEFAULT_MAX_STALE);
  }

  /**
   * @param jwksUri    the JWKS endpoint (https, or http on loopback with {@code -Djcustos.dev=true})
   * @param httpClient the HTTP client
   * @param clock      the clock
   * @param maxStale   JS-SEC-149 (CWE-672): how long the last successfully fetched key set stays
   *                   trusted while refreshes fail; after that the keys are dropped. Must be
   *                   positive. A value below the cache lifetime also caps the cache lifetime.
   * @since 00.84.00
   */
  public HttpJwksClient(URI jwksUri, HttpClient httpClient, Supplier<Instant> clock, Duration maxStale) {
    // JS-SEC-018 (CWE-319), JS-SEC-098: the one https rule of jCustos.
    this.jwksUri = EndpointSecurity.requireHttps(Objects.requireNonNull(jwksUri, "jwksUri"),
        "jwks/uri-not-https");
    this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.maxStale = Objects.requireNonNull(maxStale, "maxStale");
    if (maxStale.isZero() || maxStale.isNegative()) {
      throw new IllegalArgumentException("jwks/max-stale-not-positive: maxStale must be positive");
    }
  }

  @Override
  public Optional<PublicKey> findKey(String kid, JwsAlgorithm alg) {
    // R10 (V00.76.10): a JWS whose header omits `kid` cannot select a key from a
    // keyed JWKS set. The cache maps are immutable (Map.of()/Map.copyOf), and
    // Map#get(null) throws NPE on them — so a kid-less token arriving during the
    // negative-cache or post-refresh window (lines below) would throw an
    // unhandled NPE that escapes validate() instead of returning empty. Guard
    // here and honour the contract ("empty if no key is known").
    if (kid == null) {
      return Optional.empty();
    }
    State snapshot = state;
    Instant now = clock.get();
    boolean fresh = now.isBefore(snapshot.expiry);
    if (fresh && snapshot.keys.containsKey(kid)) {
      return select(snapshot, kid, alg);
    }
    // stale, or a kid miss (hot rotation): refresh once — unless we are inside a
    // negative-cache window, in which case serve whatever we still hold, but only
    // for as long as the last successful fetch is recent enough (JS-SEC-149).
    if (now.isBefore(snapshot.negativeUntil)) {
      return select(withinMaxStale(now), kid, alg);
    }
    refreshOnce();
    State refreshed = withinMaxStale(clock.get());
    if (!refreshed.keys.containsKey(kid)) {
      // JS-SEC-001 (CWE-770): the refresh did not resolve this kid — it is
      // genuinely unknown, not a hot rotation. Open a short throttle window so a
      // stream of distinct unknown kids cannot each force a network refresh.
      openUnknownKidThrottle();
    }
    return select(refreshed, kid, alg);
  }

  /**
   * JS-SEC-149 (CWE-326): a key that declares a JWK {@code alg} is bound to that algorithm; it is
   * not served for a token whose header names another one (RFC 7517 §4.4).
   */
  private static Optional<PublicKey> select(State snapshot, String kid, JwsAlgorithm alg) {
    CachedKey cached = snapshot.keys.get(kid);
    if (cached == null) {
      return Optional.empty();
    }
    if (cached.alg().isPresent() && (alg == null || !cached.alg().get().equals(alg.name()))) {
      return Optional.empty();
    }
    return Optional.of(cached.key());
  }

  /**
   * JS-SEC-149 (CWE-672): returns the current state, after dropping its keys when the last
   * successful fetch is older than {@link #maxStale}. Only reached on the paths that serve keys
   * <em>without</em> a successful refresh — the negative-cache window and a failed refresh — so a
   * client that was merely idle is not affected: its next lookup refreshes first.
   */
  private State withinMaxStale(Instant now) {
    State current = state;
    if (current.keys.isEmpty() || !now.isAfter(current.lastSuccess.plus(maxStale))) {
      return current;
    }
    lock.lock();
    try {
      State s = state;
      if (s.keys.isEmpty() || !now.isAfter(s.lastSuccess.plus(maxStale))) {
        return s;
      }
      // Logged once per drop: the key set is empty afterwards, so the guard above holds until
      // the next successful fetch.
      logger().warn("jwks/stale-keys-dropped: no successful refresh since {} (limit {}); "
          + "{} key(s) are no longer trusted", s.lastSuccess, maxStale, s.keys.size());
      State dropped = new State(Map.of(), Instant.EPOCH, s.negativeUntil, s.lastSuccess);
      this.state = dropped;
      return dropped;
    } finally {
      lock.unlock();
    }
  }

  /** Opens (or extends) the unknown-kid refresh-throttle window (JS-SEC-001). */
  private void openUnknownKidThrottle() {
    Instant until = clock.get().plus(REFRESH_MIN_INTERVAL);
    lock.lock();
    try {
      State s = state;
      Instant neg = s.negativeUntil.isAfter(until) ? s.negativeUntil : until;
      this.state = new State(s.keys, s.expiry, neg, s.lastSuccess);
    } finally {
      lock.unlock();
    }
  }

  @Override
  public JwksRefreshResult refreshOnce() {
    CompletableFuture<JwksRefreshResult> mine;
    boolean lead = false;
    lock.lock();
    try {
      if (inFlight == null) {
        inFlight = new CompletableFuture<>();
        lead = true;
      }
      mine = inFlight;
    } finally {
      lock.unlock();
    }

    if (!lead) {
      // a refresh is already running — wait on the leader (stampede protection).
      return mine.join();
    }

    FetchOutcome outcome = fetch();
    lock.lock();
    try {
      apply(outcome);
      inFlight = null;
    } finally {
      lock.unlock();
    }
    mine.complete(outcome.result());
    return outcome.result();
  }

  private FetchOutcome fetch() {
    Instant now = clock.get();
    try {
      HttpRequest request = HttpRequest.newBuilder(jwksUri).timeout(HTTP_TIMEOUT).GET().build();
      HttpResponse<byte[]> response =
          httpClient.send(request, BoundedHttpBody.ofByteArray(MAX_JWKS_BYTES + 1));
      int status = response.statusCode();
      if (status < HttpStatus.OK.code() || status >= HttpStatus.MULTIPLE_CHOICES.code()) {
        logger().warn("jwks/refresh-non-2xx: status={}", status);
        return new FetchOutcome(new JwksRefreshResult(0, now, NEGATIVE_TTL,
            Optional.of("Non2xxResponse")), null);
      }
      // RF01: read at most MAX_JWKS_BYTES + 1; a larger body is rejected before parsing
      // (the 10s timeout caps time, not size).
      byte[] bytes = response.body();
      if (bytes.length > MAX_JWKS_BYTES) {
        logger().warn("jwks/refresh-oversized: body exceeds {} bytes", MAX_JWKS_BYTES);
        return new FetchOutcome(new JwksRefreshResult(0, now, NEGATIVE_TTL,
            Optional.of("OversizedBody")), null);
      }
      Map<String, CachedKey> keys = parse(new String(bytes, StandardCharsets.UTF_8));
      return new FetchOutcome(
          new JwksRefreshResult(keys.size(), now, ttlFrom(response), Optional.empty()), keys);
    } catch (RuntimeException | IOException | ParseException e) {
      logger().warn("jwks/refresh-failed: {}", e.getClass().getSimpleName());
      return new FetchOutcome(
          new JwksRefreshResult(0, now, NEGATIVE_TTL, Optional.of(e.getClass().getSimpleName())), null);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return new FetchOutcome(
          new JwksRefreshResult(0, now, NEGATIVE_TTL, Optional.of(e.getClass().getSimpleName())), null);
    }
  }

  /** Updates the cached state from a refresh outcome. Must hold {@link #lock}. */
  private void apply(FetchOutcome outcome) {
    Instant now = outcome.result().fetchedAt();
    if (outcome.keys() != null) {
      // JS-SEC-149 (CWE-672): remember when the keys were last confirmed by the issuer, and never
      // treat them as fresh for longer than they may be served stale.
      Duration ttl = outcome.result().ttl().compareTo(maxStale) > 0 ? maxStale : outcome.result().ttl();
      this.state = new State(outcome.keys(), now.plus(ttl), Instant.EPOCH, now);
    } else {
      // keep the old keys (bounded by maxStale, see withinMaxStale), open a negative-cache
      // window so we do not hammer the IDP.
      this.state = new State(state.keys, state.expiry, now.plus(NEGATIVE_TTL), state.lastSuccess);
    }
  }

  private Map<String, CachedKey> parse(String body) throws ParseException {
    JWKSet set = JWKSet.parse(body);
    Map<String, CachedKey> keys = new LinkedHashMap<>();
    for (JWK jwk : set.getKeys()) {
      if (jwk.getKeyID() == null || !(jwk instanceof AsymmetricJWK asym)) {
        continue;
      }
      // JS-SEC-149 (CWE-326): only a key that may verify signatures is a verification key. A key
      // published for encryption (use=enc) or without the verify operation is skipped.
      if (!maySignatureVerify(jwk)) {
        logger().debug("jwks/non-verification-key-skipped: use or key_ops exclude signature verification");
        continue;
      }
      try {
        PublicKey publicKey = asym.toPublicKey();
        // JS-SEC-149 (CWE-326): an RSA key below the floor can be factored; the limit is the one
        // the DPoP path applies to proof keys (JS-SEC-029).
        if (publicKey instanceof RSAPublicKey rsa
            && rsa.getModulus().bitLength() < JoseLimits.MIN_RSA_MODULUS_BITS) {
          logger().warn("jwks/weak-rsa-key-skipped: modulus of {} bits is below the minimum of {}",
              rsa.getModulus().bitLength(), JoseLimits.MIN_RSA_MODULUS_BITS);
          continue;
        }
        Optional<String> declaredAlg =
            Optional.ofNullable(jwk.getAlgorithm()).map(com.nimbusds.jose.Algorithm::getName);
        keys.put(jwk.getKeyID(), new CachedKey(publicKey, declaredAlg));
      } catch (com.nimbusds.jose.JOSEException ignored) {
        // skip a key we cannot materialise as a JDK PublicKey
      }
    }
    return Map.copyOf(keys);
  }

  private static boolean maySignatureVerify(JWK jwk) {
    if (jwk.getKeyUse() != null && !KeyUse.SIGNATURE.equals(jwk.getKeyUse())) {
      return false;
    }
    return jwk.getKeyOperations() == null || jwk.getKeyOperations().contains(KeyOperation.VERIFY);
  }

  private static Duration ttlFrom(HttpResponse<?> response) {
    Optional<String> cacheControl = response.headers().firstValue("Cache-Control");
    if (cacheControl.isPresent()) {
      Matcher m = MAX_AGE.matcher(cacheControl.get());
      if (m.find()) {
        try {
          long seconds = Long.parseLong(m.group(1));
          if (seconds > 0) {
            // JS-SEC-033 (CWE-613): clamp an endpoint-controlled max-age to a sane
            // maximum so a hostile/misconfigured IdP cannot pin a (possibly revoked)
            // key set far into the future — this bounds the revocation-propagation window.
            return Duration.ofSeconds(Math.min(seconds, MAX_TTL.toSeconds()));
          }
        } catch (NumberFormatException ignored) {
          // fall through to the default
        }
      }
    }
    return DEFAULT_TTL;
  }

  /**
   * Immutable cache snapshot for lock-free reads. {@code lastSuccess} is the instant of the last
   * successful fetch (JS-SEC-149) — the anchor of the maximum-staleness bound.
   */
  private record State(Map<String, CachedKey> keys, Instant expiry, Instant negativeUntil,
                       Instant lastSuccess) {
  }

  /** A verification key and the JWK {@code alg} it declares, if any (JS-SEC-149). */
  private record CachedKey(PublicKey key, Optional<String> alg) {
  }

  /** A fetch outcome: the result plus the parsed keys (null on failure). */
  private record FetchOutcome(JwksRefreshResult result, Map<String, CachedKey> keys) {
  }
}
