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

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.jwt.api.JoseLimits;
import eu.jsentinel.jcustos.replay.api.JtiStore;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Nimbus-backed {@link DpopProofValidator} (RFC 9449 §4.3), V00.79. Composition, not
 * inheritance: {@code final}, holds an algorithm allow-list (no {@code none}), a
 * {@link JtiStore} for single-use enforcement, and an injectable clock + freshness
 * window. Validation order rejects on the first failure with a leak-free
 * {@link DpopValidationError}.
 *
 * @since 00.79.10
 */
@ExperimentalJCustosApi
public final class NimbusDpopProofValidator implements DpopProofValidator {

  private final Set<String> allowedAlgorithms;
  private final JtiStore jtiStore;
  private final Supplier<Instant> clock;
  private final Duration maxAge;
  private final Duration maxFutureSkew;

  public NimbusDpopProofValidator(Set<String> allowedAlgorithms, JtiStore jtiStore, Supplier<Instant> clock) {
    this(allowedAlgorithms, jtiStore, clock, Duration.ofSeconds(60), Duration.ofSeconds(5));
  }

  public NimbusDpopProofValidator(
      Set<String> allowedAlgorithms,
      JtiStore jtiStore,
      Supplier<Instant> clock,
      Duration maxAge,
      Duration maxFutureSkew) {
    this.allowedAlgorithms = Set.copyOf(Objects.requireNonNull(allowedAlgorithms, "allowedAlgorithms"));
    if (this.allowedAlgorithms.isEmpty()) {
      throw new IllegalArgumentException("allowedAlgorithms must not be empty");
    }
    if (this.allowedAlgorithms.stream().anyMatch(a -> a.equalsIgnoreCase("none"))) {
      throw new IllegalArgumentException("'none' is not a permitted DPoP algorithm");
    }
    this.jtiStore = Objects.requireNonNull(jtiStore, "jtiStore");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.maxAge = Objects.requireNonNull(maxAge, "maxAge");
    this.maxFutureSkew = Objects.requireNonNull(maxFutureSkew, "maxFutureSkew");
  }

  @Override
  public Result<ValidatedDpopProof, DpopValidationError> validate(DpopValidationRequest request) {
    Objects.requireNonNull(request, "request");

    // JS-SEC-148 (CWE-770): the DPoP header is an unauthenticated value that embeds a JWK. Cap it
    // with the limit every other JOSE parser applies (JS-SEC-053) BEFORE SignedJWT.parse — the
    // proof parser lived in another module and had been left out.
    if (request.proofCompact().length() > JoseLimits.MAX_COMPACT_BYTES) {
      return fail(new DpopValidationError.ProofMalformed("proof exceeds the size cap"));
    }
    // JS-SEC-148 (CWE-345): an access token without the thumbprint it is bound to cannot be
    // checked for its key binding. Fail closed rather than validate half a binding — this is what
    // the deprecated four-argument boundTo(...) produces.
    if (request.accessToken().isPresent() && request.expectedJkt().isEmpty()) {
      return fail(new DpopValidationError.KeyBindingMismatch(
          "access token supplied without the expected key thumbprint (cnf.jkt)"));
    }

    SignedJWT jws;
    try {
      jws = SignedJWT.parse(request.proofCompact());
    } catch (ParseException e) {
      return fail(new DpopValidationError.ProofMalformed("not a compact JWS"));
    }

    JWSHeader header = jws.getHeader();
    if (header.getType() == null || !"dpop+jwt".equals(header.getType().getType())) {
      return fail(new DpopValidationError.ProofMalformed("typ is not dpop+jwt"));
    }
    String alg = header.getAlgorithm() == null ? "" : header.getAlgorithm().getName();
    if (!allowedAlgorithms.contains(alg)) {
      return fail(new DpopValidationError.ProofMalformed("algorithm not allowed"));
    }
    JWK headerJwk = header.getJWK();
    if (headerJwk == null || headerJwk.isPrivate()) {
      return fail(new DpopValidationError.ProofMalformed("missing or non-public header jwk"));
    }

    JWSVerifier verifier;
    try {
      verifier = verifierFor(headerJwk);
    } catch (Exception e) {
      return fail(new DpopValidationError.ProofMalformed("unsupported header jwk"));
    }
    try {
      if (!jws.verify(verifier)) {
        return fail(new DpopValidationError.SignatureInvalid("signature did not verify"));
      }
    } catch (Exception e) {
      return fail(new DpopValidationError.SignatureInvalid("signature verification failed"));
    }

    JWTClaimsSet claims;
    try {
      claims = jws.getJWTClaimsSet();
    } catch (ParseException e) {
      return fail(new DpopValidationError.ProofMalformed("claims not parseable"));
    }

    String htm = claims.getClaim("htm") instanceof String s ? s : null;
    if (htm == null || !htm.equals(request.httpMethod())) {
      return fail(new DpopValidationError.HtmMismatch("htm does not match request method"));
    }
    String htu = claims.getClaim("htu") instanceof String s ? s : null;
    if (htu == null || !htu.equals(DpopHttpUri.normalize(request.httpUri()))) {
      return fail(new DpopValidationError.HtuMismatch("htu does not match request uri"));
    }

    Date iat = claims.getIssueTime();
    if (iat == null) {
      return fail(new DpopValidationError.ProofMalformed("missing iat"));
    }
    Instant issuedAt = iat.toInstant();
    Instant now = clock.get();
    if (issuedAt.isAfter(now.plus(maxFutureSkew))) {
      return fail(new DpopValidationError.ProofExpired("iat is in the future"));
    }
    if (issuedAt.isBefore(now.minus(maxAge))) {
      return fail(new DpopValidationError.ProofExpired("proof is too old"));
    }

    // JS-SEC-023 (CWE-345): if the proof carries an `ath` claim but no access
    // token was supplied, the caller used the binding-only profile (of(...)) at
    // a protected resource — fail closed rather than silently skipping the
    // RFC 9449 mandatory ath check.
    boolean hasAth = claims.getClaim("ath") instanceof String a && !a.isBlank();
    if (hasAth && request.accessToken().isEmpty()) {
      return fail(new DpopValidationError.AccessTokenHashMismatch(
          "proof carries ath but no access token was provided for validation"));
    }

    if (request.accessToken().isPresent()) {
      String ath = claims.getClaim("ath") instanceof String s ? s : null;
      String expected = DpopProofGenerator.accessTokenHash(request.accessToken().get());
      if (ath == null || !constantTimeEquals(ath, expected)) {
        return fail(new DpopValidationError.AccessTokenHashMismatch("ath does not match access token"));
      }
    }

    String jti = claims.getJWTID();
    if (jti == null || jti.isBlank()) {
      return fail(new DpopValidationError.ProofMalformed("missing jti"));
    }
    // JS-SEC-148 (CWE-770): the jti is chosen by the sender and is kept in the JtiStore for the
    // freshness window. A legitimate jti is a UUID or 96+ random bits; reject anything longer
    // before it is recorded, so that a store entry cannot be inflated.
    if (jti.length() > JoseLimits.MAX_JTI_CHARS) {
      return fail(new DpopValidationError.ProofMalformed("jti exceeds the length cap"));
    }
    // Compute the thumbprint (the last fallible step) BEFORE recording the jti, so a
    // thumbprint failure cannot consume a one-time jti and still fail the proof.
    JwkThumbprint thumbprint = thumbprintOf(headerJwk);
    // JS-SEC-148 (CWE-345, RFC 9449 §6.1): the proof must be signed with the key the access
    // token is bound to. Compared in constant time and BEFORE the jti is recorded, so a proof
    // signed with a foreign key neither succeeds nor burns the legitimate holder's jti.
    if (request.expectedJkt().isPresent()
        && !constantTimeEquals(thumbprint.value(), request.expectedJkt().get().value())) {
      return fail(new DpopValidationError.KeyBindingMismatch(
          "proof key does not match the key the access token is bound to"));
    }
    Instant expiresAt = issuedAt.plus(maxAge).plus(maxFutureSkew);
    boolean recorded = jtiStore.record(jti, expiresAt).isSuccess();
    if (!recorded) {
      return fail(new DpopValidationError.Replay("jti already seen"));
    }
    return Result.success(new ValidatedDpopProof(thumbprint, htm, request.httpUri(), jti, issuedAt));
  }

  /**
   * JS-SEC-029 (CWE-326): accepted RSA proof-key modulus bounds. JS-SEC-149: the values have their
   * single home in the core API so that the JWKS path applies the same floor.
   */
  private static final int MIN_RSA_MODULUS_BITS = JoseLimits.MIN_RSA_MODULUS_BITS;
  private static final int MAX_RSA_MODULUS_BITS = JoseLimits.MAX_RSA_MODULUS_BITS;

  private static JWSVerifier verifierFor(JWK jwk) throws Exception {
    if (jwk instanceof RSAKey rsa) {
      // JS-SEC-029 (CWE-326): reject a factorable (or absurdly large) RSA proof key.
      // DPoP is a sender-constraint — binding a token to a weak RSA key lets a token
      // thief factor it offline and forge valid proofs; Nimbus's RSASSAVerifier enforces
      // no floor, and the RSASSASigner floor only guards honest signers, not an attacker.
      // An oversized modulus also amplifies unauthenticated verification cost.
      int bits = rsa.toRSAPublicKey().getModulus().bitLength();
      if (bits < MIN_RSA_MODULUS_BITS || bits > MAX_RSA_MODULUS_BITS) {
        throw new IllegalArgumentException("RSA proof-key modulus out of range: " + bits + " bits");
      }
      return new RSASSAVerifier(rsa.toRSAPublicKey());
    }
    if (jwk instanceof ECKey ec) {
      return new ECDSAVerifier(ec.toECPublicKey());
    }
    throw new IllegalArgumentException("unsupported jwk type");
  }

  private static JwkThumbprint thumbprintOf(JWK jwk) {
    try {
      return new JwkThumbprint(jwk.computeThumbprint().toString());
    } catch (Exception e) {
      throw new IllegalStateException("failed to compute jwk thumbprint", e);
    }
  }

  private static boolean constantTimeEquals(String a, String b) {
    return java.security.MessageDigest.isEqual(
        a.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
        b.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
  }

  private static Result<ValidatedDpopProof, DpopValidationError> fail(DpopValidationError error) {
    return Result.failure(error);
  }
}
