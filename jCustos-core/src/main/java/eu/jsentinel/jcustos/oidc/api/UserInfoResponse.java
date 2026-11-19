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

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The claims returned by the OIDC UserInfo endpoint (OIDC Core §5.3, V00.78). The
 * {@code sub} claim is mandatory and MUST match the ID token's {@code sub} (the RP
 * verifies this) — the rest are provider-specific profile claims.
 *
 * <p>A claim whose value is JSON {@code null} — {@code "middle_name": null}, which OIDC Core
 * §5.3.2 allows a provider to send — is an absent claim (CWE-476, as for the claims of a
 * validated JWT, JS-SEC-149): it is dropped from {@link #claims()}. Until 00.84.00 the
 * immutable copy threw a {@link NullPointerException} for such a response. Values inside a
 * nested object or array are kept as given, {@code null} included; the copy is shallow.
 *
 * @param subject the {@code sub} claim (mandatory)
 * @param claims  the full claim set (immutable; includes {@code sub}); entries with a
 *                {@code null} value are dropped, a {@code null} claim name is refused
 * @since 00.78.00
 */
public record UserInfoResponse(String subject, Map<String, Object> claims) {

  /**
   * Validates the subject and keeps an immutable copy of the claims without the entries
   * whose value is {@code null}.
   *
   * @throws NullPointerException when {@code subject}, {@code claims} or a claim name is
   *                              {@code null}
   */
  public UserInfoResponse {
    Objects.requireNonNull(subject, "subject");
    claims = presentClaims(Objects.requireNonNull(claims, "claims"));
  }

  /** CWE-476: a JSON {@code null} claim is an absent claim; {@link Map#copyOf} refuses it. */
  private static Map<String, Object> presentClaims(Map<String, Object> claims) {
    Map<String, Object> present = new HashMap<>();
    claims.forEach((name, value) -> {
      Objects.requireNonNull(name, "claim name");
      if (value != null) {
        present.put(name, value);
      }
    });
    return Map.copyOf(present);
  }

  /** @return the claim {@code name} as {@code type}, if present and assignable. */
  public <T> Optional<T> claim(String name, Class<T> type) {
    Object value = claims.get(name);
    return type.isInstance(value) ? Optional.of(type.cast(value)) : Optional.empty();
  }
}
