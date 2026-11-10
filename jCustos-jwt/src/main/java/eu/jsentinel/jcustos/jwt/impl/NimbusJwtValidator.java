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

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.jwt.api.AlgorithmAllowList;
import eu.jsentinel.jcustos.jwt.api.ClaimExpectations;
import eu.jsentinel.jcustos.jwt.api.JoseHeader;
import eu.jsentinel.jcustos.jwt.api.JoseLimits;
import eu.jsentinel.jcustos.jwt.api.JwksClient;
import eu.jsentinel.jcustos.jwt.api.JwsAlgorithm;
import eu.jsentinel.jcustos.jwt.api.JwtValidationError;
import eu.jsentinel.jcustos.jwt.api.JwtValidator;
import eu.jsentinel.jcustos.jwt.api.ValidatedJwt;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Nimbus JOSE+JWT-backed {@link JwtValidator} implementing the Konzept §6.3
 * pipeline: format → header → allow-list → key lookup → algorithm-family check →
 * signature → claims. Expected failures are returned as {@link JwtValidationError}
 * in the {@link Result}; the raw token is never logged.
 *
 * <p>V00.76 is asymmetric-only. RSA ({@code RS*}/{@code PS*}) and EC ({@code ES*})
 * verifiers are built directly from the resolved {@link PublicKey}; EdDSA verifier
 * wiring is completed in a follow-up within the cycle.
 *
 * @since 00.76.00
 */
public final class NimbusJwtValidator implements JwtValidator {

  private final AlgorithmAllowList allowList;
  private final JwksClient jwksClient;
  private final ClaimExpectations expectations;
  private final Supplier<Instant> clock;

  public NimbusJwtValidator(AlgorithmAllowList allowList, JwksClient jwksClient,
      ClaimExpectations expectations, Supplier<Instant> clock) {
    this.allowList = Objects.requireNonNull(allowList, "allowList");
    this.jwksClient = Objects.requireNonNull(jwksClient, "jwksClient");
    this.expectations = Objects.requireNonNull(expectations, "expectations");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  public NimbusJwtValidator(AlgorithmAllowList allowList, JwksClient jwksClient,
      ClaimExpectations expectations) {
    this(allowList, jwksClient, expectations, Instant::now);
  }

  @Override
  public Result<ValidatedJwt, JwtValidationError> validate(String compactJwt) {
    if (compactJwt == null || compactJwt.isBlank()) {
      return Result.failure(new JwtValidationError.MalformedJwt("compact JWT is blank"));
    }
    // JS-SEC-053 (CWE-770): cap the input BEFORE the unconditional header base64-decode + JSON parse
    // and SignedJWT.parse below, which an unauthenticated caller can trigger with garbage. The JWE
    // sibling already caps at the same shared ceiling; a real signed token is a few tens of KB.
    if (compactJwt.length() > JoseLimits.MAX_COMPACT_BYTES) {
      return Result.failure(new JwtValidationError.MalformedJwt("compact JWT exceeds the size cap"));
    }
    // 1. Format check — three segments for JWS, five for JWE.
    int segments = countSegments(compactJwt);
    if (segments == 5) {
      return Result.failure(new JwtValidationError.JweNotSupported(
          "encrypted JWT (JWE) is not supported in V00.76"));
    }
    if (segments != 3) {
      return Result.failure(new JwtValidationError.MalformedJwt(
          "compact JWT does not have three segments"));
    }

    // 2. Header parse — read alg/kid from the untrusted header WITHOUT requiring a
    //    valid signature structure, so an alg:none token (no signature segment) is
    //    detected here rather than being misclassified as malformed. Konzept §4.7.
    String headerAlg;
    String kid;
    String typ;
    try {
      String headerJson = new String(
          new Base64URL(compactJwt.substring(0, compactJwt.indexOf('.'))).decode(),
          StandardCharsets.UTF_8);
      Map<String, Object> header = JSONObjectUtils.parse(headerJson);
      headerAlg = header.get("alg") instanceof String s ? s : null;
      kid = header.get("kid") instanceof String s ? s : null;
      typ = header.get("typ") instanceof String s ? s : null;
    } catch (ParseException | RuntimeException e) {
      return Result.failure(new JwtValidationError.MalformedJwt("JOSE header is not parseable"));
    }

    // 3. Allow-list check — alg:none and any non-listed algorithm are rejected here.
    if ("none".equalsIgnoreCase(headerAlg)) {
      return Result.failure(new JwtValidationError.UnsupportedAlgorithm(
          "jwt/algorithm-none-attempted", "alg:none is never accepted"));
    }
    Optional<JwsAlgorithm> algorithm = JwsAlgorithm.fromHeader(headerAlg);
    if (algorithm.isEmpty() || !allowList.allows(algorithm.get())) {
      return Result.failure(new JwtValidationError.UnsupportedAlgorithm(
          "jwt/algorithm-not-in-allow-list",
          "header algorithm is not in the allow-list"));
    }
    JwsAlgorithm alg = algorithm.get();

    // 4. Key lookup — a kid miss triggers at most one refresh inside the client.
    Optional<PublicKey> key = jwksClient.findKey(kid, alg);
    if (key.isEmpty()) {
      return Result.failure(new JwtValidationError.UnknownKid(
          "no key for the presented kid"));
    }

    // 5. Algorithm-family check — the resolved key type must match the alg family.
    //    This is the algorithm-confusion defence: an HS alg can never reach here
    //    (not allow-listed), and an RS/PS/ES alg must pair with the matching key.
    if (!familyMatches(alg, key.get())) {
      return Result.failure(new JwtValidationError.UnsupportedAlgorithm(
          "jwt/algorithm-confusion-suspected",
          "algorithm family does not match the resolved key type"));
    }
    // JS-SEC-149 (CWE-326): an RSA key below the floor can be factored, whichever JwksClient
    // handed it out — HttpJwksClient already skips such a key, this is the back-stop for every
    // other source (a static key set, a custom client). Same limit as the DPoP path (JS-SEC-029).
    if (key.get() instanceof RSAPublicKey rsa
        && rsa.getModulus().bitLength() < JoseLimits.MIN_RSA_MODULUS_BITS) {
      return Result.failure(new JwtValidationError.SignatureInvalid(
          "resolved RSA key is below the minimum modulus size"));
    }

    // 6. Signature verification — parse the full JWS (a real signing alg), then
    //    verify. EdDSA uses the JDK's native Ed25519 provider (no Google Tink
    //    dependency); RSA/EC use the Nimbus verifiers.
    SignedJWT jwt;
    try {
      jwt = SignedJWT.parse(compactJwt);
    } catch (ParseException e) {
      return Result.failure(new JwtValidationError.SignatureInvalid("token is not a parseable JWS"));
    }
    // JS-SEC-020 (RFC 7515 §4.1.11 / CWE-345): reject any token that declares a
    // `crit` header parameter. jCustos understands no crit extensions, so it
    // rejects them uniformly across all alg families. The RSA/EC path gets this
    // from Nimbus's CriticalHeaderParamsDeferral; the EdDSA path bypasses Nimbus,
    // so enforce it here for consistency and spec compliance.
    var crit = jwt.getHeader().getCriticalParams();
    if (crit != null && !crit.isEmpty()) {
      return Result.failure(new JwtValidationError.SignatureInvalid(
          "token declares unsupported critical header parameters"));
    }
    boolean signatureValid;
    if (alg == JwsAlgorithm.EdDSA) {
      signatureValid = verifyEd25519(jwt, key.get());
    } else {
      Optional<JWSVerifier> verifier = verifierFor(alg, key.get());
      if (verifier.isEmpty()) {
        return Result.failure(new JwtValidationError.SignatureInvalid(
            "no verifier available for the algorithm"));
      }
      try {
        signatureValid = jwt.verify(verifier.get());
      } catch (RuntimeException | com.nimbusds.jose.JOSEException e) {
        return Result.failure(new JwtValidationError.SignatureInvalid("signature verification failed"));
      }
    }
    if (!signatureValid) {
      return Result.failure(new JwtValidationError.SignatureInvalid("signature does not verify"));
    }

    // 7. Claims validation.
    JWTClaimsSet claims;
    try {
      claims = jwt.getJWTClaimsSet();
    } catch (ParseException e) {
      return Result.failure(new JwtValidationError.MalformedJwt("claims set is not parseable"));
    }
    // JS-SEC-149 (CWE-476, CWE-248): the claims come from a signed but otherwise arbitrary JSON
    // document. Whatever shape they have, the late steps must end in a Result — a
    // RuntimeException here used to escape validate() and turned a login or a back-channel
    // logout into an HTTP 500.
    try {
      Optional<JwtValidationError> claimError = validateClaims(claims);
      if (claimError.isPresent()) {
        return Result.failure(claimError.get());
      }

      // 7b. F4 (RFC 8725 §3.11): optional typ-header check against cross-JWT-type
      //     confusion. Only enforced when an expected type is configured; default
      //     behaviour (no expectedTyp) is unchanged. The typ header is part of the
      //     signed JOSE header, so it is trusted only after signature verification.
      Optional<JwtValidationError> typError = validateTyp(typ);
      if (typError.isPresent()) {
        return Result.failure(typError.get());
      }

      // 8. Success.
      JoseHeader header = new JoseHeader(headerAlg, Optional.ofNullable(kid), Optional.ofNullable(typ));
      return Result.success(new ValidatedJwt(compactJwt, header, toClaimMap(claims), clock.get()));
    } catch (RuntimeException e) {
      return Result.failure(new JwtValidationError.MalformedJwt("claims set could not be processed"));
    }
  }

  private Optional<JwtValidationError> validateClaims(JWTClaimsSet claims) {
    Instant now = clock.get();
    long leeway = expectations.skewPolicy().leeway().getSeconds();

    Date exp = claims.getExpirationTime();
    if (exp == null) {
      if (expectations.requireExp()) {
        return Optional.of(new JwtValidationError.ClaimInvalid("claims/exp-missing", "exp is required"));
      }
    } else if (now.getEpochSecond() > exp.toInstant().getEpochSecond() + leeway) {
      return Optional.of(new JwtValidationError.Expired("token is expired"));
    }

    Date nbf = claims.getNotBeforeTime();
    if (nbf == null) {
      if (expectations.requireNbf()) {
        return Optional.of(new JwtValidationError.ClaimInvalid("claims/nbf-missing", "nbf is required"));
      }
    } else if (now.getEpochSecond() < nbf.toInstant().getEpochSecond() - leeway) {
      return Optional.of(new JwtValidationError.NotYetValid("token is not yet valid"));
    }

    if (expectations.requireIat() && claims.getIssueTime() == null) {
      return Optional.of(new JwtValidationError.ClaimInvalid("claims/iat-missing", "iat is required"));
    }
    if (expectations.requireJti() && claims.getJWTID() == null) {
      return Optional.of(new JwtValidationError.ClaimInvalid("claims/jti-missing", "jti is required"));
    }

    if (expectations.expectedIssuer().isPresent()
        && !expectations.expectedIssuer().get().equals(claims.getIssuer())) {
      return Optional.of(new JwtValidationError.ClaimInvalid(
          "claims/issuer-mismatch", "issuer does not match the expected value"));
    }

    if (!expectations.acceptedAudiences().isEmpty()) {
      List<String> aud = claims.getAudience();
      boolean ok = aud != null && aud.stream().anyMatch(expectations.acceptedAudiences()::contains);
      if (!ok) {
        return Optional.of(new JwtValidationError.ClaimInvalid(
            "claims/audience-mismatch", "no audience matches the accepted set"));
      }
    }
    return Optional.empty();
  }

  /**
   * F4 (RFC 8725 §3.11): when an expected {@code typ} is configured, the token's
   * {@code typ} header must be present and match (case-insensitive, tolerating an
   * {@code application/} prefix). No expectation configured → no check.
   */
  private Optional<JwtValidationError> validateTyp(String typ) {
    Optional<String> expected = expectations.expectedTyp();
    if (expected.isEmpty()) {
      return Optional.empty();
    }
    if (typ == null || !typMatches(expected.get(), typ)) {
      return Optional.of(new JwtValidationError.ClaimInvalid(
          "claims/typ-mismatch", "token typ header does not match the expected media type"));
    }
    return Optional.empty();
  }

  private static boolean typMatches(String expected, String actual) {
    return normalizeTyp(expected).equals(normalizeTyp(actual));
  }

  private static String normalizeTyp(String t) {
    String lower = t.trim().toLowerCase(java.util.Locale.ROOT);
    return lower.startsWith("application/") ? lower.substring("application/".length()) : lower;
  }

  private static boolean familyMatches(JwsAlgorithm alg, PublicKey key) {
    return switch (alg) {
      case RS256, RS384, RS512, PS256, PS384, PS512 -> key instanceof RSAPublicKey;
      case ES256, ES384, ES512 -> key instanceof ECPublicKey;
      case EdDSA -> "EdDSA".equalsIgnoreCase(key.getAlgorithm())
          || "Ed25519".equalsIgnoreCase(key.getAlgorithm());
    };
  }

  private static Optional<JWSVerifier> verifierFor(JwsAlgorithm alg, PublicKey key) {
    try {
      return switch (alg) {
        case RS256, RS384, RS512, PS256, PS384, PS512 ->
            Optional.of(new RSASSAVerifier((RSAPublicKey) key));
        case ES256, ES384, ES512 ->
            Optional.of(new ECDSAVerifier((ECPublicKey) key));
        // EdDSA is verified via the JDK path in verifyEd25519(...), not here.
        case EdDSA -> Optional.empty();
      };
    } catch (com.nimbusds.jose.JOSEException e) {
      return Optional.empty();
    }
  }

  /**
   * Verifies an EdDSA (Ed25519) JWS using the JDK's native provider — avoids a
   * Google Tink dependency that Nimbus's own Ed25519 verifier would require. The
   * signing input is {@code header.payload}; the signature is the third segment.
   */
  private static boolean verifyEd25519(SignedJWT jwt, PublicKey key) {
    if (!(key instanceof EdECPublicKey)) {
      return false;
    }
    try {
      Signature sig = Signature.getInstance("Ed25519");
      sig.initVerify(key);
      sig.update(jwt.getSigningInput());
      return sig.verify(jwt.getSignature().decode());
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  private static int countSegments(String compact) {
    int dots = 0;
    for (int i = 0; i < compact.length(); i++) {
      if (compact.charAt(i) == '.') {
        dots++;
      }
    }
    return dots + 1;
  }

  private static Map<String, Object> toClaimMap(JWTClaimsSet claims) {
    Map<String, Object> out = new LinkedHashMap<>();
    for (Map.Entry<String, Object> e : claims.getClaims().entrySet()) {
      Object value = e.getValue();
      // JS-SEC-149 (CWE-476): a JSON null ("middle_name": null) is an absent claim. ValidatedJwt
      // holds an immutable copy that rejects null values, so carrying it over threw a
      // NullPointerException for a validly signed token.
      if (value == null) {
        continue;
      }
      out.put(e.getKey(), value instanceof Date d ? d.toInstant() : value);
    }
    return out;
  }
}
