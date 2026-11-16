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
package eu.jsentinel.jcustos.oidc.api;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * The inputs an {@code IdTokenValidator} checks an ID token against (V00.78,
 * OIDC Core §3.1.3.7). {@code expectedIssuer} + {@code expectedAudience} are
 * mandatory; the rest enable the optional OIDC checks (nonce, azp, at_hash/c_hash,
 * max_age, acr).
 *
 * @param expectedIssuer        the issuer the ID token must carry
 * @param expectedAudience      the client_id the ID token must be addressed to
 * @param expectedNonce         the nonce bound at authorization time, if any
 * @param accessTokenForAtHash  the access token to verify {@code at_hash} against, if any
 * @param codeForCHash          the authorization code to verify {@code c_hash} against, if any
 * @param maxAge                the maximum acceptable age since {@code auth_time}, if any
 * @param requestedAcr          the acceptable {@code acr} values (empty = no acr check)
 * @param clockSkew             the allowed clock skew for time-based checks
 * @since 00.78.00
 */
public record IdTokenExpectations(
    String expectedIssuer,
    String expectedAudience,
    Optional<String> expectedNonce,
    Optional<String> accessTokenForAtHash,
    Optional<String> codeForCHash,
    Optional<Duration> maxAge,
    Set<String> requestedAcr,
    Duration clockSkew) {

  /** OIDC Core §15.1 recommends a small leeway; default 60s if unspecified. */
  public static final Duration DEFAULT_CLOCK_SKEW = Duration.ofSeconds(60);

  public IdTokenExpectations {
    Objects.requireNonNull(expectedIssuer, "expectedIssuer");
    Objects.requireNonNull(expectedAudience, "expectedAudience");
    Objects.requireNonNull(expectedNonce, "expectedNonce");
    Objects.requireNonNull(accessTokenForAtHash, "accessTokenForAtHash");
    Objects.requireNonNull(codeForCHash, "codeForCHash");
    Objects.requireNonNull(maxAge, "maxAge");
    requestedAcr = Set.copyOf(Objects.requireNonNull(requestedAcr, "requestedAcr"));
    Objects.requireNonNull(clockSkew, "clockSkew");
  }

  /** Minimal expectations: issuer + audience + nonce, default skew, no hash/acr/max_age checks. */
  public static IdTokenExpectations of(String issuer, String audience, Optional<String> nonce) {
    return new IdTokenExpectations(issuer, audience, nonce, Optional.empty(), Optional.empty(),
        Optional.empty(), Set.of(), DEFAULT_CLOCK_SKEW);
  }

  /**
   * Masks the access token and the authorisation code (JS-SEC-127, CWE-532): the
   * generated {@code toString()} printed both into any log line or exception message that
   * stringified the expectations. The nonce is shown only as present or absent.
   *
   * @return a description without token, code or nonce
   */
  @Override
  public String toString() {
    return "IdTokenExpectations[expectedIssuer=" + expectedIssuer
        + ", expectedAudience=" + expectedAudience
        + ", expectedNonce=" + masked(expectedNonce)
        + ", accessTokenForAtHash=" + masked(accessTokenForAtHash)
        + ", codeForCHash=" + masked(codeForCHash)
        + ", maxAge=" + maxAge.map(Duration::toString).orElse("<none>")
        + ", requestedAcr=" + requestedAcr
        + ", clockSkew=" + clockSkew + "]";
  }

  private static String masked(Optional<String> value) {
    return value.isPresent() ? "***" : "<none>";
  }
}
