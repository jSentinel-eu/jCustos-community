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
package eu.jsentinel.jcustos.oauth2.http;

import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.jwt.api.JwtSigner;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Builds the signed JWT client assertion for {@code private_key_jwt} and
 * {@code client_secret_jwt} (RFC 7523 §2.2 / OIDC Core §9, V00.77) and drops the
 * {@code client_assertion} / {@code client_assertion_type} form fields in place.
 *
 * <p>The asymmetric case delegates to the {@link JwtSigner} SPI (so the JOSE
 * library stays in {@code jCustos-jwt}); the symmetric case HMACs the assertion
 * with the shared secret using the JDK {@link Mac} — no JOSE dependency. The
 * {@code aud} claim is the endpoint the request is sent to, {@code jti} is a fresh
 * 128-bit random nonce and {@code exp} bounds the assertion to its lifetime.
 */
final class ClientAssertions {

  /** RFC 7523 §2.2 assertion type. */
  public static final String ASSERTION_TYPE =
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
  private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
  private static final SecureRandom RANDOM = new SecureRandom();

  private ClientAssertions() {
    throw new AssertionError("no instances");
  }

  /** Builds + signs a {@code private_key_jwt} assertion via the {@link JwtSigner} SPI. */
  public static void applyPrivateKeyJwt(ClientAuthentication.PrivateKeyJwt auth, URI audience,
      Supplier<Instant> clock, JwtSigner signer, Map<String, String> form) {
    Map<String, Object> claims = claims(auth.clientId(), audience, auth.assertionLifetime(), clock);
    String assertion = signer.sign(claims, auth.signingKey());
    put(form, auth.clientId(), assertion);
  }

  /** Builds + HMAC-signs (HS256) a {@code client_secret_jwt} assertion with the JDK {@link Mac}. */
  public static void applyClientSecretJwt(ClientAuthentication.ClientSecretJwt auth, URI audience,
      Supplier<Instant> clock, Map<String, String> form) {
    Map<String, Object> claims = claims(auth.clientId(), audience, auth.assertionLifetime(), clock);
    String header = json(Map.of("alg", "HS256", "typ", "JWT"));
    String signingInput = B64.encodeToString(header.getBytes(StandardCharsets.UTF_8))
        + "." + B64.encodeToString(json(claims).getBytes(StandardCharsets.UTF_8));
    String assertion = signingInput + "." + B64.encodeToString(hmacSha256(auth.secret(), signingInput));
    put(form, auth.clientId(), assertion);
  }

  private static void put(Map<String, String> form, String clientId, String assertion) {
    form.put("client_id", clientId);
    form.put("client_assertion_type", ASSERTION_TYPE);
    form.put("client_assertion", assertion);
  }

  private static Map<String, Object> claims(String clientId, URI audience,
      java.time.Duration lifetime, Supplier<Instant> clock) {
    Instant now = clock.get();
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("iss", clientId);
    claims.put("sub", clientId);
    claims.put("aud", audience.toString());
    claims.put("jti", newJti());
    claims.put("iat", now.getEpochSecond());
    claims.put("exp", now.plus(lifetime).getEpochSecond());
    return claims;
  }

  private static String newJti() {
    byte[] nonce = new byte[16];
    RANDOM.nextBytes(nonce);
    return B64.encodeToString(nonce);
  }

  private static byte[] hmacSha256(SecretValue secret, String signingInput) {
    byte[] keyBytes = secret.asUtf8Bytes();
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
      return mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
    } catch (java.security.NoSuchAlgorithmException | java.security.InvalidKeyException e) {
      throw new IllegalStateException("HmacSHA256 unavailable", e);
    } finally {
      Arrays.fill(keyBytes, (byte) 0);
    }
  }

  /** Minimal JSON object writer for the flat String/Long claim maps used here. */
  private static String json(Map<String, Object> map) {
    StringBuilder sb = new StringBuilder("{");
    boolean first = true;
    for (Map.Entry<String, Object> e : map.entrySet()) {
      if (!first) {
        sb.append(',');
      }
      first = false;
      sb.append('"').append(escape(e.getKey())).append("\":");
      Object v = e.getValue();
      if (v instanceof Number) {
        sb.append(v);
      } else {
        sb.append('"').append(escape(String.valueOf(v))).append('"');
      }
    }
    return sb.append('}').toString();
  }

  private static String escape(String s) {
    StringBuilder sb = new StringBuilder(s.length());
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"' -> sb.append("\\\"");
        case '\\' -> sb.append("\\\\");
        case '\n' -> sb.append("\\n");
        case '\r' -> sb.append("\\r");
        case '\t' -> sb.append("\\t");
        default -> {
          if (c < 0x20) {
            sb.append(String.format("\\u%04x", (int) c));
          } else {
            sb.append(c);
          }
        }
      }
    }
    return sb.toString();
  }
}
