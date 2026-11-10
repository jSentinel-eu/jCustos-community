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
package eu.jsentinel.jcustos.identity.vendor.github;

import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.oidc.api.ClaimsToSubjectMapper;
import eu.jsentinel.jcustos.oidc.api.VendorProfile;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The GitHub vendor profile (V00.79). GitHub speaks OAuth2 but issues no ID token,
 * so identity comes from the UserInfo (the {@code /user} API).
 *
 * <p><strong>JS-SEC-039 (CWE-290):</strong> the subject id is anchored to GitHub's
 * <em>immutable numeric account id</em> ({@code github#<id>}), never the mutable
 * {@code login} (username). A GitHub {@code login} can be renamed at any time and,
 * once relinquished, immediately reclaimed by any other account — keying identity on
 * it would let an attacker who claims a freed username inherit the previous holder's
 * local grants. {@code name} (falling back to {@code login}) is display-only.
 *
 * <p><strong>JS-SEC-151 (CWE-290):</strong> the promise above is now enforced, not merely
 * stated. The id is read from the numeric {@code id} claim of the UserInfo first — the field the
 * GitHub {@code /user} API itself returns. The UserInfo {@code sub} is accepted only when it
 * consists of decimal digits; the id_token {@code sub} is consulted (under the same condition)
 * only when there is no UserInfo at all. Anything else — in particular a {@code sub} an
 * integrator's adapter filled with the {@code login} — makes the mapper throw an
 * {@link IllegalArgumentException}: it fails closed rather than key a principal on a name that
 * can change hands. Up to 00.83.x any non-blank {@code sub} won, even over a present {@code id}.
 */
public final class GitHubProfile implements VendorProfile {

  public static final GitHubProfile INSTANCE = new GitHubProfile();

  /** A GitHub account id: decimal digits only (a 64-bit value has at most 20 of them). */
  private static final Pattern NUMERIC_ID = Pattern.compile("[0-9]{1,20}");

  public GitHubProfile() {
  }

  @Override
  public String id() {
    return "github";
  }

  @Override
  public Optional<ClaimsToSubjectMapper> subjectMapper() {
    return Optional.of((idToken, userInfo) -> {
      // JS-SEC-039 / JS-SEC-151 (CWE-290): key on the immutable numeric account id, never the
      // mutable `login`. The numeric `id` claim comes first (GitHub returns it as a JSON number);
      // a `sub` counts only when it is numeric. Fail closed otherwise.
      // A present UserInfo is the authority (GitHub issues no ID token): the id_token `sub` is
      // consulted only when there is no UserInfo at all, never to paper over a UserInfo that
      // carries a name where the account id belongs.
      Optional<String> numericId = userInfo.isPresent()
          ? numericIdClaim(userInfo.get().claims().get("id"))
              .or(() -> Optional.of(userInfo.get().subject()).filter(GitHubProfile::isNumericId))
          : idToken.subject().filter(GitHubProfile::isNumericId);
      String stableId = numericId.orElseThrow(() -> new IllegalArgumentException(
          "github: no stable numeric account id available "
              + "(UserInfo id / numeric UserInfo sub; numeric id_token sub without a UserInfo)"));
      Optional<String> login = userInfo.flatMap(u -> u.claim("login", String.class));
      String displayName = userInfo.flatMap(u -> u.claim("name", String.class))
          .or(() -> login)
          .orElse(stableId);
      return new JCustosSubject("github#" + stableId, displayName, Set.of(), Set.of());
    });
  }

  private static boolean isNumericId(String value) {
    return value != null && NUMERIC_ID.matcher(value).matches();
  }

  /**
   * Reads the {@code id} claim: a positive integral JSON number, or a string of decimal digits.
   * A fractional or non-positive number is not an account id and yields empty.
   */
  private static Optional<String> numericIdClaim(Object raw) {
    if (raw instanceof String text) {
      return isNumericId(text) ? Optional.of(text) : Optional.empty();
    }
    if (raw instanceof Long || raw instanceof Integer || raw instanceof Short || raw instanceof Byte) {
      long value = ((Number) raw).longValue();
      return value > 0 ? Optional.of(Long.toString(value)) : Optional.empty();
    }
    if (raw instanceof BigInteger big) {
      return big.signum() > 0 ? Optional.of(big.toString()).filter(GitHubProfile::isNumericId) : Optional.empty();
    }
    if (raw instanceof Number number) {
      // Double / Float / BigDecimal: accept only an exact, positive integral value.
      try {
        BigInteger exact = new BigDecimal(number.toString()).toBigIntegerExact();
        return exact.signum() > 0
            ? Optional.of(exact.toString()).filter(GitHubProfile::isNumericId) : Optional.empty();
      } catch (ArithmeticException | NumberFormatException e) {
        return Optional.empty();
      }
    }
    return Optional.empty();
  }
}
