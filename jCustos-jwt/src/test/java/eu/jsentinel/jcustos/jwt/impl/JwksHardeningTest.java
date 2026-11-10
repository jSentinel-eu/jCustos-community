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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.sun.net.httpserver.HttpServer;
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.jwt.api.AlgorithmProfile;
import eu.jsentinel.jcustos.jwt.api.ClaimExpectations;
import eu.jsentinel.jcustos.jwt.api.ClockSkewPolicy;
import eu.jsentinel.jcustos.jwt.api.JwksClient;
import eu.jsentinel.jcustos.jwt.api.JwksRefreshResult;
import eu.jsentinel.jcustos.jwt.api.JwsAlgorithm;
import eu.jsentinel.jcustos.jwt.api.JwtValidationError;
import eu.jsentinel.jcustos.jwt.api.ValidatedJwt;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * JS-SEC-149 (CWE-672, CWE-326, CWE-476): the JWKS client bounds its trust in a stale key set
 * and takes only verification keys of sufficient strength; the validator keeps its
 * {@code Result} contract for a signed token with a JSON {@code null} claim. No mocks: a real
 * JDK {@link HttpServer} on loopback, freshly generated RSA keys, the real
 * {@link NimbusJwtValidator}.
 */
@DisplayName("JWT / JWKS hardening — stale keys, key hygiene, null claims (JS-SEC-149)")
class JwksHardeningTest {

  private static final Instant T0 = Instant.parse("2026-11-10T12:00:00Z");

  private HttpServer server;
  private final AtomicInteger status = new AtomicInteger(200);
  private final AtomicReference<String> body = new AtomicReference<>("{\"keys\":[]}");
  private final AtomicReference<Instant> clock = new AtomicReference<>(T0);
  private String jwksUrl;

  @BeforeEach
  void start() throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/jwks", exchange -> {
      byte[] payload = body.get().getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(status.get(), payload.length);
      try (var out = exchange.getResponseBody()) {
        out.write(payload);
      }
      exchange.close();
    });
    server.start();
    jwksUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks";
  }

  @AfterEach
  void stop() {
    server.stop(0);
  }

  private static RSAKey rsa(String kid) throws Exception {
    return new RSAKeyGenerator(2048).keyID(kid).generate();
  }

  private static String jwks(JWK... keys) {
    return new JWKSet(List.of(keys).stream().map(JWK::toPublicJWK).toList()).toString();
  }

  private HttpJwksClient jwksClient() {
    return new HttpJwksClient(URI.create(jwksUrl), HttpClient.newHttpClient(), clock::get);
  }

  private NimbusJwtValidator validator(JwksClient keys, Supplier<Instant> validatorClock) {
    ClaimExpectations expectations = new ClaimExpectations(
        Optional.empty(), Set.of(), false, false, false, false, ClockSkewPolicy.DEFAULT);
    return new NimbusJwtValidator(
        AlgorithmProfile.STRICT_MODERN.toAllowList(), keys, expectations, validatorClock);
  }

  /** Signs a raw JSON payload, so the test controls the exact claims document. */
  private static String sign(RSAKey key, JWSAlgorithm alg, String jsonPayload) throws Exception {
    JWSObject jws = new JWSObject(
        new JWSHeader.Builder(alg).keyID(key.getKeyID()).build(), new Payload(jsonPayload));
    jws.sign(new RSASSASigner(key.toRSAPrivateKey(), true));
    return jws.serialize();
  }

  private static String token(RSAKey key) throws Exception {
    return sign(key, JWSAlgorithm.RS256, "{\"iss\":\"https://idp.example\",\"sub\":\"u1\"}");
  }

  private static JwtValidationError errorOf(Result<ValidatedJwt, JwtValidationError> result) {
    return result.fold(ok -> null, e -> e);
  }

  // ── (a) bounded trust in a stale key set ────────────────────────────────────────

  @Test
  @DisplayName("stale keys: after 25 h of failing refreshes the withdrawn key is no longer trusted; a 200 restores it")
  void staleKeysAreDroppedAfterMaxStale() throws Exception {
    RSAKey key = rsa("k1");
    body.set(jwks(key));
    NimbusJwtValidator validator = validator(jwksClient(), clock::get);
    String token = token(key);

    assertTrue(validator.validate(token).isSuccess(), "first fetch succeeds, the token validates");

    // the issuer withdraws the key; the relying party only ever sees 503 from now on
    status.set(503);
    body.set("unavailable");

    // a short outage is bridged: one hour later the last good key set is still served
    clock.set(T0.plus(Duration.ofHours(1)));
    assertTrue(validator.validate(token).isSuccess(), "within the grace period the old key is served");

    // ...but not for ever: 25 h after the last SUCCESSFUL fetch the key set is dropped
    clock.set(T0.plus(Duration.ofHours(25)));
    assertInstanceOf(JwtValidationError.UnknownKid.class, errorOf(validator.validate(token)));
    // and it stays dropped inside the negative-cache window that the failed refresh opened
    clock.set(T0.plus(Duration.ofHours(25)).plusSeconds(5));
    assertInstanceOf(JwtValidationError.UnknownKid.class, errorOf(validator.validate(token)));

    // the endpoint recovers: after the negative-cache window the keys are fetched and trusted again
    status.set(200);
    body.set(jwks(key));
    clock.set(T0.plus(Duration.ofHours(25)).plusSeconds(60));
    assertTrue(validator.validate(token).isSuccess(), "a successful fetch restores validation");
  }

  @Test
  @DisplayName("stale keys: the limit is configurable and must be positive")
  void maxStaleIsConfigurable() throws Exception {
    RSAKey key = rsa("k1");
    body.set(jwks(key));
    HttpJwksClient client = new HttpJwksClient(
        URI.create(jwksUrl), HttpClient.newHttpClient(), clock::get, Duration.ofMinutes(30));
    assertTrue(client.findKey("k1", JwsAlgorithm.RS256).isPresent());

    status.set(503);
    clock.set(T0.plus(Duration.ofMinutes(20)));
    assertTrue(client.findKey("k1", JwsAlgorithm.RS256).isPresent(), "20 min < 30 min: still served");
    clock.set(T0.plus(Duration.ofMinutes(31)));
    assertTrue(client.findKey("k1", JwsAlgorithm.RS256).isEmpty(), "31 min > 30 min: dropped");

    assertThrows(IllegalArgumentException.class, () -> new HttpJwksClient(
        URI.create(jwksUrl), HttpClient.newHttpClient(), clock::get, Duration.ZERO));
    assertEquals(Duration.ofHours(24), HttpJwksClient.DEFAULT_MAX_STALE);
  }

  @Test
  @DisplayName("stale keys: an idle client is not affected — its next lookup refreshes first")
  void idleClientRefreshesInsteadOfDropping() throws Exception {
    RSAKey key = rsa("k1");
    body.set(jwks(key));
    HttpJwksClient client = jwksClient();
    assertTrue(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    clock.set(T0.plus(Duration.ofDays(3)));
    assertTrue(client.findKey("k1", JwsAlgorithm.RS256).isPresent(),
        "the endpoint answers 200, so the keys are simply fetched again");
  }

  // ── (b) key hygiene ─────────────────────────────────────────────────────────────

  @Test
  @DisplayName("key hygiene: a token signed with a use=enc key is not verified with it (UnknownKid)")
  void encryptionKeyIsNotAVerificationKey() throws Exception {
    RSAKey sig = new RSAKeyGenerator(2048).keyID("sig").keyUse(KeyUse.SIGNATURE).generate();
    RSAKey enc = new RSAKeyGenerator(2048).keyID("enc").keyUse(KeyUse.ENCRYPTION).generate();
    body.set(jwks(sig, enc));
    NimbusJwtValidator validator = validator(jwksClient(), clock::get);

    assertInstanceOf(JwtValidationError.UnknownKid.class, errorOf(validator.validate(token(enc))));
    assertTrue(validator.validate(token(sig)).isSuccess(), "the use=sig key keeps working");
  }

  @Test
  @DisplayName("key hygiene: key_ops without 'verify' excludes a key; key_ops with 'verify' admits it")
  void keyOperationsAreHonoured() throws Exception {
    RSAKey encryptOnly = new RSAKeyGenerator(2048).keyID("ops-enc")
        .keyOperations(Set.of(KeyOperation.ENCRYPT, KeyOperation.WRAP_KEY)).generate();
    RSAKey verifying = new RSAKeyGenerator(2048).keyID("ops-verify")
        .keyOperations(Set.of(KeyOperation.VERIFY)).generate();
    // toPublicJWK() keeps key_ops; publish both
    body.set(jwks(encryptOnly, verifying));
    HttpJwksClient client = jwksClient();

    assertTrue(client.findKey("ops-enc", JwsAlgorithm.RS256).isEmpty());
    assertTrue(client.findKey("ops-verify", JwsAlgorithm.RS256).isPresent());
  }

  @Test
  @DisplayName("key hygiene: a 1024-bit RSA key from the JWKS is not served (UnknownKid)")
  void weakRsaKeyFromJwksIsSkipped() throws Exception {
    RSAKey weak = weakKey("weak");
    body.set(jwks(weak));
    NimbusJwtValidator validator = validator(jwksClient(), clock::get);
    assertInstanceOf(JwtValidationError.UnknownKid.class, errorOf(validator.validate(token(weak))));
  }

  @Test
  @DisplayName("key hygiene: a 1024-bit RSA key from ANY JwksClient is refused by the validator itself")
  void weakRsaKeyFromCustomClientIsRefused() throws Exception {
    RSAKey weak = weakKey("weak");
    PublicKey weakPublic = weak.toRSAPublicKey();
    JwksClient staticKeys = new JwksClient() {
      @Override
      public Optional<PublicKey> findKey(String kid, JwsAlgorithm alg) {
        return Optional.of(weakPublic);
      }

      @Override
      public JwksRefreshResult refreshOnce() {
        return new JwksRefreshResult(1, T0, Duration.ofMinutes(5), Optional.empty());
      }
    };
    Result<ValidatedJwt, JwtValidationError> result = validator(staticKeys, clock::get).validate(token(weak));
    assertInstanceOf(JwtValidationError.SignatureInvalid.class, errorOf(result));
  }

  @Test
  @DisplayName("key hygiene: a key declared alg=PS256 does not verify an RS256 token, but does verify PS256")
  void declaredAlgorithmIsBinding() throws Exception {
    RSAKey pssOnly = new RSAKeyGenerator(2048).keyID("pss").algorithm(JWSAlgorithm.PS256).generate();
    body.set(jwks(pssOnly));
    NimbusJwtValidator validator = validator(jwksClient(), clock::get);
    String claims = "{\"iss\":\"https://idp.example\",\"sub\":\"u1\"}";

    assertInstanceOf(JwtValidationError.UnknownKid.class,
        errorOf(validator.validate(sign(pssOnly, JWSAlgorithm.RS256, claims))));
    // the unknown-kid throttle (JS-SEC-001) is open now; step past it for the positive case
    clock.set(T0.plusSeconds(60));
    assertTrue(validator.validate(sign(pssOnly, JWSAlgorithm.PS256, claims)).isSuccess());
  }

  private static RSAKey weakKey(String kid) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(1024);
    KeyPair pair = generator.generateKeyPair();
    return new RSAKey.Builder((RSAPublicKey) pair.getPublic())
        .privateKey((RSAPrivateKey) pair.getPrivate()).keyID(kid).build();
  }

  // ── (c) the Result contract ─────────────────────────────────────────────────────

  @Test
  @DisplayName("null claim: a validly signed token with \"middle_name\": null yields a Result, not an exception")
  void jsonNullClaimDoesNotThrow() throws Exception {
    RSAKey key = rsa("k1");
    body.set(jwks(key));
    NimbusJwtValidator validator = validator(jwksClient(), clock::get);
    String token = sign(key, JWSAlgorithm.RS256,
        "{\"iss\":\"https://idp.example\",\"sub\":\"u1\",\"middle_name\":null,\"email\":\"u1@example.com\"}");

    Result<ValidatedJwt, JwtValidationError> result = assertDoesNotThrow(() -> validator.validate(token));
    ValidatedJwt jwt = result.toOptional().orElseThrow(() -> new AssertionError("expected success: " + result));
    assertFalse(jwt.claims().containsKey("middle_name"), "a JSON null is an absent claim");
    assertEquals(Optional.of("u1@example.com"), jwt.claim("email", String.class));
    assertEquals(Optional.of("u1"), jwt.subject());
  }

  @Test
  @DisplayName("Result contract: a RuntimeException in the late validation steps becomes MalformedJwt")
  void lateRuntimeExceptionBecomesMalformedJwt() throws Exception {
    RSAKey key = rsa("k1");
    body.set(jwks(key));
    // the validator's own clock fails — the first thing the claims step calls
    NimbusJwtValidator validator = validator(jwksClient(), () -> {
      throw new IllegalStateException("clock source unavailable");
    });
    Result<ValidatedJwt, JwtValidationError> result =
        assertDoesNotThrow(() -> validator.validate(token(key)));
    assertInstanceOf(JwtValidationError.MalformedJwt.class, errorOf(result));
  }
}
