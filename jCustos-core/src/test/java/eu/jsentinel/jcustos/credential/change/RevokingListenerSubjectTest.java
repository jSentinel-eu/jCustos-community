/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
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
package eu.jsentinel.jcustos.credential.change;

import eu.jsentinel.jcustos.authentication.InMemoryRefreshTokenStore;
import eu.jsentinel.jcustos.authentication.InMemoryRememberMeTokenStore;
import eu.jsentinel.jcustos.authentication.StoreBackedRememberMeService;
import eu.jsentinel.jcustos.authentication.TokenService;
import eu.jsentinel.jcustos.credential.CredentialTestKit;
import eu.jsentinel.jcustos.credential.token.Sha256TokenHasher;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-128 (CWE-613): the listener derives the subject id from the user name.
 * When the tokens carry another id, the revocation hits nothing - which is now
 * reported instead of passing silently, and the subject resolver fixes it.
 */
@DisplayName("JS-SEC-128 — a revocation that hits nothing is reported; the subject resolver aims it")
class RevokingListenerSubjectTest {

  /** Tokens are issued for the application's user id, not for the login name. */
  private static final SubjectId USER_42 = SubjectId.of("user-42");

  private final CredentialTestKit kit = new CredentialTestKit();
  private final StoreBackedRememberMeService rememberMe = new StoreBackedRememberMeService(
      new InMemoryRememberMeTokenStore(), new Sha256TokenHasher());
  private final TokenService tokens = new TokenService(
      new InMemoryRefreshTokenStore(), new Sha256TokenHasher(), kit.audit);

  @Test
  @DisplayName("default mapping, tokens under another id: nothing is revoked and that is reported")
  void mismatchIsReported() {
    StoreBackedRememberMeService.IssuedToken cookie = rememberMe.issue(USER_42, Duration.ofDays(1));
    TokenService.TokenPair pair = tokens.issue(USER_42);
    RevokingCredentialChangeListener listener = RevokingCredentialChangeListener.builder()
        .rememberMe(rememberMe).refreshTokens(tokens).build();

    listener.credentialChanged("alice", CredentialChangeListener.Cause.PASSWORD_CHANGED,
        kit.clock.instant());

    assertEquals(1L, listener.emptyRevocationCount());
    assertTrue(rememberMe.validate(cookie.plainToken()).isPresent(), "the gap the report names");
    assertTrue(tokens.rotate(pair.refreshToken()).isPresent());
  }

  @Test
  @DisplayName("with the subject resolver the tokens are revoked and nothing is reported")
  void resolverAimsTheRevocation() {
    StoreBackedRememberMeService.IssuedToken cookie = rememberMe.issue(USER_42, Duration.ofDays(1));
    TokenService.TokenPair pair = tokens.issue(USER_42);
    RevokingCredentialChangeListener listener = RevokingCredentialChangeListener.builder()
        .rememberMe(rememberMe).refreshTokens(tokens)
        .subjectResolver(username -> "alice".equals(username) ? USER_42 : SubjectId.of(username))
        .build();

    listener.credentialChanged("alice", CredentialChangeListener.Cause.PASSWORD_RESET,
        kit.clock.instant());

    assertEquals(0L, listener.emptyRevocationCount());
    assertTrue(rememberMe.validate(cookie.plainToken()).isEmpty());
    assertTrue(tokens.rotate(pair.refreshToken()).isEmpty());
  }

  @Test
  @DisplayName("a listener without token steps reports nothing")
  void noTokenStepsNoReport() {
    RevokingCredentialChangeListener listener = RevokingCredentialChangeListener.builder().build();
    listener.credentialChanged("alice", CredentialChangeListener.Cause.PASSWORD_CHANGED,
        kit.clock.instant());
    assertEquals(0L, listener.emptyRevocationCount());
  }
}
