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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import eu.jsentinel.jcustos.jwt.api.AlgorithmProfile;
import eu.jsentinel.jcustos.jwt.api.ClaimExpectations;
import eu.jsentinel.jcustos.jwt.api.ClockSkewPolicy;
import eu.jsentinel.jcustos.jwt.api.JwksClient;
import eu.jsentinel.jcustos.jwt.api.JwksRefreshResult;
import eu.jsentinel.jcustos.jwt.api.JwsAlgorithm;
import eu.jsentinel.jcustos.jwt.api.JwtValidationError;
import eu.jsentinel.jcustos.jwt.impl.NimbusJwtValidator;
import eu.jsentinel.jcustos.oidc.api.BackChannelLogoutOutcome;
import eu.jsentinel.jcustos.oidc.api.LogoutTokenValidationError;
import eu.jsentinel.jcustos.oidc.api.SessionRegistry;
import eu.jsentinel.jcustos.replay.impl.InMemoryJtiStore;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * No-mock Back-Channel + Front-Channel Logout: real RSA-signed logout tokens, the real
 * {@link NimbusJwtValidator}, the real {@link InMemoryJtiStore} +
 * {@link InMemorySessionRegistry}. Proves accept-on-valid + reject on each
 * OIDC Back-Channel Logout 1.0 §2.4 failure, plus session termination.
 */
@DisplayName("Logout hardening — back-channel + front-channel (OIDC BCL/FCL 1.0)")
class LogoutHardeningTest {

  private static final String ISSUER = "https://op.example.com";
  private static final String CLIENT = "rp-client-1";
  private static final String KID = "k-logout";
  private static final Instant NOW = Instant.parse("2026-06-27T12:00:00Z");

  private final RSAKey rsa = newKey();

  private static RSAKey newKey() {
    try {
      return new RSAKeyGenerator(2048).keyID(KID).generate();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private PublicKey publicKey() {
    try {
      return rsa.toRSAPublicKey();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private NimbusJwtValidator jwtValidator() {
    // exp is not required by the composed validator (the logout validator demands it itself,
    // JS-SEC-087); iat is.
    return jwtValidator(new ClaimExpectations(
        Optional.of(ISSUER), Set.of(CLIENT), false, false, false, false,
        ClockSkewPolicy.DEFAULT, Optional.empty()), () -> NOW);
  }

  /**
   * JS-SEC-087: the composed validator the bootstrap permits — NO issuer and NO audience
   * expectation, so it accepts a validly signed token of any tenant that shares the keys.
   */
  private NimbusJwtValidator jwtValidatorWithoutExpectations(Supplier<Instant> clock) {
    return jwtValidator(new ClaimExpectations(
        Optional.empty(), Set.of(), false, false, false, false,
        ClockSkewPolicy.DEFAULT, Optional.empty()), clock);
  }

  private NimbusJwtValidator jwtValidator(ClaimExpectations expectations, Supplier<Instant> clock) {
    JwksClient keys = new JwksClient() {
      @Override
      public Optional<PublicKey> findKey(String kid, JwsAlgorithm alg) {
        return KID.equals(kid) ? Optional.of(publicKey()) : Optional.empty();
      }

      @Override
      public JwksRefreshResult refreshOnce() {
        return new JwksRefreshResult(1, NOW, Duration.ofMinutes(5), Optional.empty());
      }
    };
    return new NimbusJwtValidator(
        AlgorithmProfile.STRICT_MODERN.toAllowList(), keys, expectations, clock);
  }

  private DefaultLogoutTokenValidator validator() {
    // JS-SEC-041: the validator's jti-retention window is anchored on ITS clock (first-seen),
    // pinned here to NOW so both the validator and the jti store share one deterministic clock.
    return new DefaultLogoutTokenValidator(
        jwtValidator(), ISSUER, CLIENT, new InMemoryJtiStore(1000, () -> NOW), () -> NOW);
  }

  /** Signs exactly the given claims — no defaults — with the legitimate key. */
  private String signRaw(JWTClaimsSet claims) {
    try {
      SignedJWT jwt = new SignedJWT(
          new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build(), claims);
      jwt.sign(new RSASSASigner(rsa));
      return jwt.serialize();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static String claimCode(LogoutTokenValidationError error) {
    LogoutTokenValidationError.JwtInvalid invalid =
        assertInstanceOf(LogoutTokenValidationError.JwtInvalid.class, error);
    return invalid.cause().code();
  }

  /** A real registry that additionally counts how often a termination was requested. */
  private static final class CountingRegistry implements SessionRegistry {
    private final InMemorySessionRegistry delegate = new InMemorySessionRegistry();
    private final AtomicInteger terminateCalls = new AtomicInteger();

    @Override
    public void register(String issuer, String subject, Optional<String> sid, String sessionId) {
      delegate.register(issuer, subject, sid, sessionId);
    }

    @Override
    public Set<String> terminate(String issuer, Optional<String> subject, Optional<String> sid) {
      terminateCalls.incrementAndGet();
      return delegate.terminate(issuer, subject, sid);
    }

    @Override
    public void unregister(String sessionId) {
      delegate.unregister(sessionId);
    }
  }

  /** Like {@link #sign} but WITHOUT an issueTime — an iat-less logout token. */
  private String signNoIat(JWTClaimsSet.Builder claims) {
    try {
      claims.issuer(ISSUER).audience(CLIENT).jwtID("jti-noiat")
          .expirationTime(Date.from(NOW.plusSeconds(120)));
      SignedJWT jwt = new SignedJWT(
          new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build(), claims.build());
      jwt.sign(new RSASSASigner(rsa));
      return jwt.serialize();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private String sign(JWTClaimsSet.Builder claims) {
    try {
      claims.issuer(ISSUER).audience(CLIENT).issueTime(Date.from(NOW))
          .expirationTime(Date.from(NOW.plusSeconds(120)))
          .jwtID("jti-" + System.identityHashCode(claims));
      SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build(), claims.build());
      jwt.sign(new RSASSASigner(rsa));
      return jwt.serialize();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static JWTClaimsSet.Builder logoutClaims() {
    return new JWTClaimsSet.Builder()
        .subject("alice")
        .claim("sid", "sess-1")
        .claim("events", Map.of(DefaultLogoutTokenValidator.BACKCHANNEL_LOGOUT_EVENT, Map.of()));
  }

  @Test
  @DisplayName("a valid logout token validates and terminates the registered session")
  void validLogoutTerminatesSession() {
    InMemorySessionRegistry registry = new InMemorySessionRegistry();
    registry.register(ISSUER, "alice", Optional.of("sess-1"), "rp-session-aaa");
    BackChannelLogoutReceiver receiver = new BackChannelLogoutReceiver(validator(), registry);

    BackChannelLogoutOutcome outcome = receiver.receive(sign(logoutClaims()));
    BackChannelLogoutOutcome.Accepted accepted = assertInstanceOf(BackChannelLogoutOutcome.Accepted.class, outcome);
    assertEquals(Set.of("rp-session-aaa"), accepted.terminatedSessionIds());
  }

  @Test
  @DisplayName("a present nonce is rejected (logout tokens must not carry one)")
  void noncePresentRejected() {
    var err = validator().validate(sign(logoutClaims().claim("nonce", "n-1"))).fold(ok -> null, e -> e);
    assertInstanceOf(LogoutTokenValidationError.NonceMustNotBePresent.class, err);
  }

  @Test
  @DisplayName("a token without the back-channel-logout event is rejected (an ID token cannot log out)")
  void missingEventRejected() {
    String idTokenShaped = sign(new JWTClaimsSet.Builder().subject("alice").claim("sid", "sess-1"));
    var err = validator().validate(idTokenShaped).fold(ok -> null, e -> e);
    assertInstanceOf(LogoutTokenValidationError.MissingBackchannelEvent.class, err);
  }

  @Test
  @DisplayName("a token with neither sub nor sid is rejected")
  void missingSubAndSidRejected() {
    String token = sign(new JWTClaimsSet.Builder()
        .claim("events", Map.of(DefaultLogoutTokenValidator.BACKCHANNEL_LOGOUT_EVENT, Map.of())));
    var err = validator().validate(token).fold(ok -> null, e -> e);
    assertInstanceOf(LogoutTokenValidationError.MissingSubjectAndSid.class, err);
  }

  @Test
  @DisplayName("a token signed by the wrong key is rejected as JwtInvalid")
  void forgedSignatureRejected() {
    RSAKey attacker = newKey();
    String forged;
    try {
      JWTClaimsSet.Builder c = logoutClaims().issuer(ISSUER).audience(CLIENT).issueTime(Date.from(NOW)).jwtID("x");
      SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build(), c.build());
      jwt.sign(new RSASSASigner(attacker));
      forged = jwt.serialize();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
    var err = validator().validate(forged).fold(ok -> null, e -> e);
    assertInstanceOf(LogoutTokenValidationError.JwtInvalid.class, err);
  }

  @Test
  @DisplayName("a logout token without the required jti is rejected")
  void missingJtiRejected() {
    String token;
    try {
      JWTClaimsSet.Builder c = logoutClaims().issuer(ISSUER).audience(CLIENT).issueTime(Date.from(NOW))
          .expirationTime(Date.from(NOW.plusSeconds(120)));
      SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build(), c.build());
      jwt.sign(new RSASSASigner(rsa));
      token = jwt.serialize();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
    var err = validator().validate(token).fold(ok -> null, e -> e);
    assertInstanceOf(LogoutTokenValidationError.MissingJwtId.class, err);
  }

  @Test
  @DisplayName("a replayed logout token (same jti) is rejected the second time")
  void replayRejected() {
    DefaultLogoutTokenValidator v = validator();
    String token = sign(logoutClaims());
    assertTrue(v.validate(token).isSuccess());
    var err = v.validate(token).fold(ok -> null, e -> e);
    assertInstanceOf(LogoutTokenValidationError.Replay.class, err);
  }

  @Test
  @DisplayName("JS-SEC-087: a logout token WITHOUT iat is rejected, although the composed validator does not require iat")
  void iatLessTokenRejected() {
    // Up to 00.83.x an iat-less logout token validated (JS-SEC-041 only made its replay
    // detectable). §2.4 requires iat, and the age check of JS-SEC-087 is built on it.
    var err = validator().validate(signNoIat(logoutClaims())).fold(ok -> null, e -> e);
    assertEquals("claims/iat-missing", claimCode(err));
  }

  @Test
  @DisplayName("JS-SEC-087: a logout token WITHOUT exp is rejected, although the composed validator does not require exp")
  void expLessTokenRejected() {
    String token = signRaw(logoutClaims().issuer(ISSUER).audience(CLIENT)
        .issueTime(Date.from(NOW)).jwtID("jti-noexp").build());
    var err = validator().validate(token).fold(ok -> null, e -> e);
    assertEquals("claims/exp-missing", claimCode(err));
  }

  @Test
  @DisplayName("JS-SEC-087: foreign iss is rejected by the logout validator itself and no session is terminated")
  void foreignIssuerRejectedWithoutTermination() {
    CountingRegistry registry = new CountingRegistry();
    registry.register(ISSUER, "alice", Optional.of("sess-1"), "rp-session-aaa");
    // the composed JwtValidator has NO issuer/audience expectation (the bootstrap permits that)
    DefaultLogoutTokenValidator validator = new DefaultLogoutTokenValidator(
        jwtValidatorWithoutExpectations(() -> NOW), ISSUER, CLIENT,
        new InMemoryJtiStore(1000, () -> NOW), () -> NOW);
    BackChannelLogoutReceiver receiver = new BackChannelLogoutReceiver(validator, registry);

    // another tenant of the same OP key set: same keys, other issuer, same sub/sid
    String foreign = signRaw(logoutClaims().issuer("https://other-tenant.example.com").audience(CLIENT)
        .issueTime(Date.from(NOW)).expirationTime(Date.from(NOW.plusSeconds(120)))
        .jwtID("jti-foreign-iss").build());

    BackChannelLogoutOutcome.Rejected rejected =
        assertInstanceOf(BackChannelLogoutOutcome.Rejected.class, receiver.receive(foreign));
    assertEquals("claims/iss-mismatch", claimCode(rejected.error()));
    assertEquals(0, registry.terminateCalls.get(), "SessionRegistry.terminate must not be called");
    assertEquals(Set.of("rp-session-aaa"),
        registry.terminate(ISSUER, Optional.of("alice"), Optional.of("sess-1")),
        "the session must still be registered");
  }

  @Test
  @DisplayName("JS-SEC-087: foreign aud is rejected by the logout validator itself and no session is terminated")
  void foreignAudienceRejectedWithoutTermination() {
    CountingRegistry registry = new CountingRegistry();
    registry.register(ISSUER, "alice", Optional.of("sess-1"), "rp-session-aaa");
    DefaultLogoutTokenValidator validator = new DefaultLogoutTokenValidator(
        jwtValidatorWithoutExpectations(() -> NOW), ISSUER, CLIENT,
        new InMemoryJtiStore(1000, () -> NOW), () -> NOW);
    BackChannelLogoutReceiver receiver = new BackChannelLogoutReceiver(validator, registry);

    // a logout token the same OP minted for ANOTHER client
    String foreign = signRaw(logoutClaims().issuer(ISSUER).audience("some-other-client")
        .issueTime(Date.from(NOW)).expirationTime(Date.from(NOW.plusSeconds(120)))
        .jwtID("jti-foreign-aud").build());

    BackChannelLogoutOutcome.Rejected rejected =
        assertInstanceOf(BackChannelLogoutOutcome.Rejected.class, receiver.receive(foreign));
    assertEquals("claims/aud-mismatch", claimCode(rejected.error()));
    assertEquals(0, registry.terminateCalls.get(), "SessionRegistry.terminate must not be called");
  }

  @Test
  @DisplayName("JS-SEC-087: with a composed validator without expectations the RIGHT iss/aud still logs out")
  void ownTokenAcceptedWithExpectationFreeJwtValidator() {
    CountingRegistry registry = new CountingRegistry();
    registry.register(ISSUER, "alice", Optional.of("sess-1"), "rp-session-aaa");
    DefaultLogoutTokenValidator validator = new DefaultLogoutTokenValidator(
        jwtValidatorWithoutExpectations(() -> NOW), ISSUER, CLIENT,
        new InMemoryJtiStore(1000, () -> NOW), () -> NOW);

    BackChannelLogoutOutcome outcome =
        new BackChannelLogoutReceiver(validator, registry).receive(sign(logoutClaims()));
    assertEquals(Set.of("rp-session-aaa"),
        assertInstanceOf(BackChannelLogoutOutcome.Accepted.class, outcome).terminatedSessionIds());
    assertEquals(1, registry.terminateCalls.get());
  }

  @Test
  @SuppressWarnings("removal")
  @DisplayName("JS-SEC-087: the deprecated constructors know no issuer and client and reject every token (fail closed)")
  void deprecatedConstructorsFailClosed() {
    String valid = sign(logoutClaims());
    var viaOneArg = new DefaultLogoutTokenValidator(jwtValidator()).validate(valid).fold(ok -> null, e -> e);
    assertEquals("claims/iss-mismatch", claimCode(viaOneArg));
    var viaTwoArg = new DefaultLogoutTokenValidator(jwtValidator(), new InMemoryJtiStore())
        .validate(valid).fold(ok -> null, e -> e);
    assertEquals("claims/iss-mismatch", claimCode(viaTwoArg));
  }

  @Test
  @DisplayName("JS-SEC-087: blank expectations are refused at construction")
  void blankExpectationsRefused() {
    assertThrows(IllegalArgumentException.class,
        () -> new DefaultLogoutTokenValidator(jwtValidator(), " ", CLIENT));
    assertThrows(IllegalArgumentException.class,
        () -> new DefaultLogoutTokenValidator(jwtValidator(), ISSUER, ""));
  }

  @Test
  @DisplayName("JS-SEC-087: a token valid for one hour is still a Replay when delivered again after eleven minutes")
  void replayAfterElevenMinutesIsStillCaught() {
    AtomicReference<Instant> now = new AtomicReference<>(NOW);
    CountingRegistry registry = new CountingRegistry();
    registry.register(ISSUER, "alice", Optional.empty(), "rp-session-1");
    DefaultLogoutTokenValidator validator = new DefaultLogoutTokenValidator(
        jwtValidatorWithoutExpectations(now::get), ISSUER, CLIENT,
        new InMemoryJtiStore(1000, now::get), now::get);
    BackChannelLogoutReceiver receiver = new BackChannelLogoutReceiver(validator, registry);

    // exp = iat + 1 h — far longer than the fixed ten-minute jti retention of 00.83.x
    String token = signRaw(new JWTClaimsSet.Builder().subject("alice")
        .claim("events", Map.of(DefaultLogoutTokenValidator.BACKCHANNEL_LOGOUT_EVENT, Map.of()))
        .issuer(ISSUER).audience(CLIENT)
        .issueTime(Date.from(NOW)).expirationTime(Date.from(NOW.plus(Duration.ofHours(1))))
        .jwtID("jti-long-lived").build());

    BackChannelLogoutOutcome first = receiver.receive(token);
    assertEquals(Set.of("rp-session-1"),
        assertInstanceOf(BackChannelLogoutOutcome.Accepted.class, first).terminatedSessionIds());

    // the user signs in again; eleven minutes later the captured token is delivered once more
    registry.register(ISSUER, "alice", Optional.empty(), "rp-session-2");
    now.set(NOW.plus(Duration.ofMinutes(11)));

    BackChannelLogoutOutcome.Rejected second =
        assertInstanceOf(BackChannelLogoutOutcome.Rejected.class, receiver.receive(token));
    assertInstanceOf(LogoutTokenValidationError.Replay.class, second.error());
    assertEquals(1, registry.terminateCalls.get(), "the replay must not terminate the new session");

    // ...and it stays a replay for as long as the token itself could be accepted
    now.set(NOW.plus(Duration.ofMinutes(59)));
    assertInstanceOf(LogoutTokenValidationError.Replay.class,
        validator.validate(token).fold(ok -> null, e -> e));
  }

  @Test
  @DisplayName("JS-SEC-087: a never-seen logout token whose iat is older than ten minutes is rejected")
  void staleTokenRejected() {
    String token = signRaw(logoutClaims().issuer(ISSUER).audience(CLIENT)
        .issueTime(Date.from(NOW.minus(Duration.ofMinutes(11))))
        .expirationTime(Date.from(NOW.plus(Duration.ofMinutes(30))))
        .jwtID("jti-stale").build());
    var err = validator().validate(token).fold(ok -> null, e -> e);
    assertEquals("claims/iat-too-old", claimCode(err));

    // the boundary: exactly ten minutes old is still accepted
    String boundary = signRaw(logoutClaims().issuer(ISSUER).audience(CLIENT)
        .issueTime(Date.from(NOW.minus(Duration.ofMinutes(10))))
        .expirationTime(Date.from(NOW.plus(Duration.ofMinutes(30))))
        .jwtID("jti-boundary").build());
    assertTrue(validator().validate(boundary).isSuccess());
  }

  @Test
  @DisplayName("JS-SEC-087: an expired logout token is rejected by the logout validator's own exp check")
  void expiredTokenRejectedByOwnCheck() {
    // a composed validator that does not look at the clock at all (e.g. a mis-wired custom one)
    // is modelled by a NimbusJwtValidator whose clock is stuck in the past
    DefaultLogoutTokenValidator validator = new DefaultLogoutTokenValidator(
        jwtValidatorWithoutExpectations(() -> NOW.minus(Duration.ofHours(1))), ISSUER, CLIENT,
        new InMemoryJtiStore(1000, () -> NOW), () -> NOW);
    String token = signRaw(logoutClaims().issuer(ISSUER).audience(CLIENT)
        .issueTime(Date.from(NOW.minus(Duration.ofMinutes(8))))
        .expirationTime(Date.from(NOW.minus(Duration.ofMinutes(5))))
        .jwtID("jti-expired").build());
    LogoutTokenValidationError.JwtInvalid invalid = assertInstanceOf(
        LogoutTokenValidationError.JwtInvalid.class, validator.validate(token).fold(ok -> null, e -> e));
    assertInstanceOf(JwtValidationError.Expired.class, invalid.cause());
  }

  @Test
  @DisplayName("front-channel logout terminates on a trusted issuer and ignores a forged one")
  void frontChannel() {
    InMemorySessionRegistry registry = new InMemorySessionRegistry();
    registry.register(ISSUER, "alice", Optional.of("sess-9"), "rp-session-fc");
    FrontChannelLogoutEndpoint endpoint = new FrontChannelLogoutEndpoint(ISSUER, registry);

    assertEquals(Set.of(), endpoint.logout("https://evil.example.com", Optional.of("sess-9")));
    assertEquals(Set.of("rp-session-fc"), endpoint.logout(ISSUER, Optional.of("sess-9")));
  }
}
