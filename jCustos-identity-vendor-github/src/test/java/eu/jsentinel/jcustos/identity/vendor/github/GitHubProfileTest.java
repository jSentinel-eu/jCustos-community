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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.jwt.api.JoseHeader;
import eu.jsentinel.jcustos.jwt.api.ValidatedJwt;
import eu.jsentinel.jcustos.oidc.api.UserInfoResponse;
import eu.jsentinel.jcustos.oidc.api.ValidatedIdToken;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("GitHubProfile — UserInfo-only subject (no ID token)")
class GitHubProfileTest {

  private static ValidatedIdToken placeholderIdToken() {
    return idTokenWithSub("12345");
  }

  private static ValidatedIdToken idTokenWithSub(String sub) {
    return new ValidatedIdToken(new ValidatedJwt("c",
        new JoseHeader("RS256", Optional.empty(), Optional.empty()),
        Map.of("sub", sub), Instant.now()),
        Optional.empty(), Optional.empty(), Optional.empty(), List.of(), Optional.empty(),
        Optional.empty());
  }

  @Test
  @DisplayName("JS-SEC-039: anchors the subject to the immutable numeric id (sub), login is display-only")
  void anchorsSubjectToNumericIdNotLogin() {
    UserInfoResponse userInfo = new UserInfoResponse("12345",
        Map.of("sub", "12345", "login", "octocat", "name", "The Octocat"));
    JCustosSubject subject = GitHubProfile.INSTANCE.subjectMapper().orElseThrow()
        .map(placeholderIdToken(), Optional.of(userInfo));
    // the principal keys on the numeric id, NOT the reclaimable login "octocat"
    assertEquals("github#12345", subject.subjectId());
    assertEquals("The Octocat", subject.displayName());
    assertEquals("github", GitHubProfile.INSTANCE.id());
  }

  @Test
  @DisplayName("JS-SEC-039: falls back to the raw numeric `id` claim when `sub` is blank")
  void fallsBackToNumericIdClaim() {
    // a GitHub UserInfo whose `sub` was not populated but which carries the numeric `id`
    // as a JSON number — must still key on the id, not the login.
    UserInfoResponse userInfo = new UserInfoResponse("",
        Map.of("id", 12345, "login", "octocat"));
    JCustosSubject subject = GitHubProfile.INSTANCE.subjectMapper().orElseThrow()
        .map(placeholderIdToken(), Optional.of(userInfo));
    assertEquals("github#12345", subject.subjectId());
    assertEquals("octocat", subject.displayName());
  }

  @Test
  @DisplayName("JS-SEC-151: sub=login with a numeric id → the id wins, never the login")
  void numericIdWinsOverLoginInSub() {
    // the mapping every integrator writes by hand: /user has no `sub`, so `login` ends up there
    UserInfoResponse userInfo = new UserInfoResponse("octocat",
        Map.of("sub", "octocat", "id", 583231, "login", "octocat"));
    JCustosSubject subject = GitHubProfile.INSTANCE.subjectMapper().orElseThrow()
        .map(placeholderIdToken(), Optional.of(userInfo));
    assertEquals("github#583231", subject.subjectId());
    assertEquals("octocat", subject.displayName());
  }

  @Test
  @DisplayName("JS-SEC-151: sub=login without an id → IllegalArgumentException (fail closed)")
  void loginInSubWithoutIdFailsClosed() {
    UserInfoResponse userInfo = new UserInfoResponse("octocat",
        Map.of("sub", "octocat", "login", "octocat"));
    // not even a numeric id_token sub rescues a UserInfo that names no account id
    assertThrows(IllegalArgumentException.class, () -> GitHubProfile.INSTANCE.subjectMapper().orElseThrow()
        .map(placeholderIdToken(), Optional.of(userInfo)));
  }

  @Test
  @DisplayName("JS-SEC-151: the id is read as an exact positive integer — Long, numeric string; not a fraction, not zero")
  void idClaimShapes() {
    var mapper = GitHubProfile.INSTANCE.subjectMapper().orElseThrow();
    assertEquals("github#583231", mapper.map(placeholderIdToken(), Optional.of(
        new UserInfoResponse("octocat", Map.of("id", 583231L)))).subjectId());
    assertEquals("github#583231", mapper.map(placeholderIdToken(), Optional.of(
        new UserInfoResponse("octocat", Map.of("id", "583231")))).subjectId());
    assertEquals("github#583231", mapper.map(placeholderIdToken(), Optional.of(
        new UserInfoResponse("octocat", Map.of("id", 583231.0d)))).subjectId());
    assertThrows(IllegalArgumentException.class, () -> mapper.map(placeholderIdToken(), Optional.of(
        new UserInfoResponse("octocat", Map.of("id", 583231.5d)))));
    assertThrows(IllegalArgumentException.class, () -> mapper.map(placeholderIdToken(), Optional.of(
        new UserInfoResponse("octocat", Map.of("id", 0)))));
    assertThrows(IllegalArgumentException.class, () -> mapper.map(placeholderIdToken(), Optional.of(
        new UserInfoResponse("octocat", Map.of("id", "octocat")))));
  }

  @Test
  @DisplayName("JS-SEC-151: without a UserInfo only a numeric id_token sub is accepted")
  void idTokenSubMustBeNumeric() {
    var mapper = GitHubProfile.INSTANCE.subjectMapper().orElseThrow();
    assertEquals("github#12345", mapper.map(idTokenWithSub("12345"), Optional.empty()).subjectId());
    assertThrows(IllegalArgumentException.class,
        () -> mapper.map(idTokenWithSub("octocat"), Optional.empty()));
  }
}
