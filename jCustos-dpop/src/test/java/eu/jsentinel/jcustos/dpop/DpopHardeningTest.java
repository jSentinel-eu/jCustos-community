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
package eu.jsentinel.jcustos.dpop;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.dpop.DpopValidationError.KeyBindingMismatch;
import eu.jsentinel.jcustos.dpop.DpopValidationError.ProofMalformed;
import eu.jsentinel.jcustos.jwt.api.JoseLimits;
import eu.jsentinel.jcustos.replay.api.JtiStore;
import eu.jsentinel.jcustos.replay.api.ReplayError;
import eu.jsentinel.jcustos.replay.impl.InMemoryJtiStore;

import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * JS-SEC-148 (CWE-770, CWE-345): the DPoP validator bounds what an unauthenticated sender can
 * make it parse and store, and it checks the key binding itself. No mocks: real EC keys, real
 * Nimbus signing and verification, the real {@link InMemoryJtiStore} behind a counting wrapper.
 */
@DisplayName("DPoP hardening — size bounds and key binding (JS-SEC-148)")
class DpopHardeningTest {

  private static final URI RESOURCE = URI.create("https://api.example.com/resource");
  private static final String TOKEN = "access-token-xyz";

  private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-11-10T12:00:00Z"));
  private final CountingJtiStore store = new CountingJtiStore(new InMemoryJtiStore(1000, now::get));
  private final NimbusDpopProofValidator validator =
      new NimbusDpopProofValidator(Set.of("ES256"), store, now::get);
  private final AtomicInteger jtiCounter = new AtomicInteger();
  private final DpopProofGenerator generator =
      new DpopProofGenerator(now::get, () -> "jti-" + jtiCounter.incrementAndGet());

  /** The real store, plus a count of how often the validator wrote to it. */
  private static final class CountingJtiStore implements JtiStore {
    private final JtiStore delegate;
    private final AtomicInteger records = new AtomicInteger();

    CountingJtiStore(JtiStore delegate) {
      this.delegate = delegate;
    }

    @Override
    public Result<Boolean, ReplayError> record(String jti, Instant expiresAt) {
      records.incrementAndGet();
      return delegate.record(jti, expiresAt);
    }
  }

  private static ECKey ecKey() throws Exception {
    return new ECKeyGenerator(Curve.P_256).generate();
  }

  private static JwkThumbprint thumbprintOf(ECKey key) throws Exception {
    return new JwkThumbprint(key.computeThumbprint().toString());
  }

  /** Hand-signs a proof so the test controls the jti and can add an arbitrary extra claim. */
  private String proof(ECKey key, String jti, Optional<String> padding) throws Exception {
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
        .type(new JOSEObjectType("dpop+jwt"))
        .jwk(key.toPublicJWK())
        .build();
    JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
        .jwtID(jti)
        .claim("htm", "GET")
        .claim("htu", DpopHttpUri.normalize(RESOURCE))
        .issueTime(Date.from(now.get()));
    padding.ifPresent(p -> claims.claim("pad", p));
    SignedJWT jws = new SignedJWT(header, claims.build());
    jws.sign(new ECDSASigner(key));
    return jws.serialize();
  }

  @Test
  @DisplayName("a validly signed proof with a 300-character jti is ProofMalformed and the store is not written")
  void overlongJtiRejectedBeforeRecord() throws Exception {
    String proof = proof(ecKey(), "j".repeat(300), Optional.empty());
    DpopValidationError error = validator.validate(DpopValidationRequest.of(proof, "GET", RESOURCE))
        .fold(ok -> null, e -> e);
    assertInstanceOf(ProofMalformed.class, error);
    assertEquals(0, store.records.get(), "an over-long jti must never reach the JtiStore");
  }

  @Test
  @DisplayName("a jti of exactly the maximum length is still accepted")
  void jtiAtTheLimitAccepted() throws Exception {
    String proof = proof(ecKey(), "j".repeat(JoseLimits.MAX_JTI_CHARS), Optional.empty());
    assertTrue(validator.validate(DpopValidationRequest.of(proof, "GET", RESOURCE)).isSuccess());
    assertEquals(1, store.records.get());
  }

  @Test
  @DisplayName("a validly signed 150 kB proof is ProofMalformed before any parsing; the store is not written")
  void oversizedProofRejectedBeforeParsing() throws Exception {
    // signed correctly and otherwise valid — only the size cap stands between it and success
    String proof = proof(ecKey(), "jti-big", Optional.of("p".repeat(150_000)));
    assertTrue(proof.length() > JoseLimits.MAX_COMPACT_BYTES);
    DpopValidationError error = validator.validate(DpopValidationRequest.of(proof, "GET", RESOURCE))
        .fold(ok -> null, e -> e);
    ProofMalformed malformed = assertInstanceOf(ProofMalformed.class, error);
    assertEquals("proof exceeds the size cap", malformed.detail());
    assertEquals(0, store.records.get());
  }

  @Test
  @DisplayName("a proof signed with a FOREIGN key and a correct ath fails the key binding; the jti is not consumed")
  void foreignKeyFailsKeyBinding() throws Exception {
    ECKey legitimate = ecKey();
    ECKey thief = ecKey();
    JwkThumbprint cnfJkt = thumbprintOf(legitimate);

    // the thief holds the stolen token, signs his own proof with a correct ath / htm / htu
    String thiefProof = generator.generate(thief, "GET", RESOURCE, Optional.of(TOKEN));
    DpopValidationError error = validator
        .validate(DpopValidationRequest.boundTo(thiefProof, "GET", RESOURCE, TOKEN, cnfJkt))
        .fold(ok -> null, e -> e);
    KeyBindingMismatch mismatch = assertInstanceOf(KeyBindingMismatch.class, error);
    assertEquals("dpop/key-binding-mismatch", mismatch.code());
    assertEquals(0, store.records.get(), "a proof that fails the key binding must not consume a jti");

    // the legitimate holder succeeds, and the validated proof confirms the token's cnf.jkt
    String ownProof = generator.generate(legitimate, "GET", RESOURCE, Optional.of(TOKEN));
    ValidatedDpopProof validated = validator
        .validate(DpopValidationRequest.boundTo(ownProof, "GET", RESOURCE, TOKEN, cnfJkt))
        .getOrThrow();
    assertTrue(validated.confirms(cnfJkt));
    assertEquals(1, store.records.get());
  }

  @Test
  @SuppressWarnings("removal")
  @DisplayName("the deprecated four-argument boundTo(...) fails closed: no thumbprint, no success")
  void deprecatedBoundToFailsClosed() throws Exception {
    ECKey key = ecKey();
    String proof = generator.generate(key, "GET", RESOURCE, Optional.of(TOKEN));
    Result<ValidatedDpopProof, DpopValidationError> result =
        validator.validate(DpopValidationRequest.boundTo(proof, "GET", RESOURCE, TOKEN));
    assertFalse(result.isSuccess());
    assertInstanceOf(KeyBindingMismatch.class, result.fold(ok -> null, e -> e));
    assertEquals(0, store.records.get());

    // the same holds for the compatibility constructor
    assertInstanceOf(KeyBindingMismatch.class, validator.validate(
            new DpopValidationRequest(proof, "GET", RESOURCE, Optional.of(TOKEN)))
        .fold(ok -> null, e -> e));
  }

  @Test
  @DisplayName("of(...) keeps working for the token endpoint: no access token, no key-binding check")
  void tokenEndpointProfileUnchanged() throws Exception {
    String proof = generator.generate(ecKey(), "GET", RESOURCE, Optional.empty());
    assertTrue(validator.validate(DpopValidationRequest.of(proof, "GET", RESOURCE)).isSuccess());
  }
}
