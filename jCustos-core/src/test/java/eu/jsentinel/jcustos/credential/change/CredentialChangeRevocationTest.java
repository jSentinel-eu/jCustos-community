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
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.credential.CredentialTestKit;
import eu.jsentinel.jcustos.credential.reset.PasswordResetConsumeResult;
import eu.jsentinel.jcustos.credential.reset.PasswordResetService;
import eu.jsentinel.jcustos.credential.reset.ResetTokenCreationResult;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.token.Sha256TokenHasher;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.JCustosVersionStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-128 (CWE-613, CWE-640): a password change retires open reset links,
 * and both ways of replacing a password revoke what was issued under the old one.
 */
@DisplayName("JS-SEC-128 — password change and reset invalidate older artefacts")
class CredentialChangeRevocationTest {

  private static final Duration TTL = Duration.ofHours(1);
  private static final SubjectId BOB = SubjectId.of("bob");
  private static final SubjectId CAROL = SubjectId.of("carol");

  /** Everything a subject can hold besides the password, on real in-memory stores. */
  private static final class Artefacts {
    final InMemoryJCustosVersionStore versions = new InMemoryJCustosVersionStore();
    final StoreBackedRememberMeService rememberMe;
    final TokenService tokens;
    final RevokingCredentialChangeListener listener;

    Artefacts(CredentialTestKit kit) {
      rememberMe = new StoreBackedRememberMeService(
          new InMemoryRememberMeTokenStore(), new Sha256TokenHasher());
      tokens = new TokenService(
          new InMemoryRefreshTokenStore(), new Sha256TokenHasher(), kit.audit);
      listener = RevokingCredentialChangeListener.builder()
          .versionStore(versions).rememberMe(rememberMe).refreshTokens(tokens).build();
    }

    JCustosVersion version(SubjectId subject) {
      return versions.current(new JCustosVersionKey(TenantId.DEFAULT, subject));
    }
  }

  private static PasswordChangeService changeService(CredentialTestKit kit) {
    return new PasswordChangeService(kit.credentials, kit.hashing, kit.validator,
        kit.inputPolicy, kit.lifecycle(), kit.clock);
  }

  private static PasswordResetService resetService(CredentialTestKit kit) {
    return new PasswordResetService(kit.credentials, kit.resetTokens, kit.digests, kit.hashing,
        kit.validator, kit.inputPolicy, kit.lifecycle(), kit.clock, kit.audit);
  }

  private static PasswordChangeCommand change(String user, String current, String next) {
    return new PasswordChangeCommand(
        user, SecretValue.ofString(current), SecretValue.ofString(next));
  }

  private static String issue(PasswordResetService reset, String username) {
    return assertInstanceOf(ResetTokenCreationResult.Created.class,
        reset.issue(username, TTL)).token().encode();
  }

  @Test
  @DisplayName("issue -> change -> consume(older link) fails; the changed password stays")
  void changeRetiresOpenResetLinks() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("bob", "bobs first password", CredentialStatus.ACTIVE);
    PasswordResetService reset = resetService(kit);
    PasswordChangeService change = changeService(kit).withResetTokenStore(kit.resetTokens);
    String intercepted = issue(reset, "bob");

    assertInstanceOf(PasswordChangeResult.Succeeded.class,
        change.change(change("bob", "bobs first password", "bobs second password")));

    kit.clock.advance(Duration.ofMinutes(30));
    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        reset.consume(intercepted, SecretValue.ofString("attackers password")));
    assertTrue(kit.passwordIs("bob", "bobs second password"));
    assertFalse(kit.passwordIs("bob", "attackers password"));
  }

  @Test
  @DisplayName("a failed change retires nothing")
  void rejectedChangeKeepsTheLink() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("bob", "bobs first password", CredentialStatus.ACTIVE);
    PasswordResetService reset = resetService(kit);
    PasswordChangeService change = changeService(kit).withResetTokenStore(kit.resetTokens);
    String link = issue(reset, "bob");

    assertSame(PasswordChangeResult.CurrentPasswordRejected.INSTANCE,
        change.change(change("bob", "not bobs password", "bobs second password")));

    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(link, SecretValue.ofString("bobs reset password")),
        "someone guessing the current password must not be able to kill the owner's link");
  }

  @Test
  @DisplayName("without the reset store the service behaves as before: the link survives the change")
  void withoutResetStoreNothingIsRetired() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("bob", "bobs first password", CredentialStatus.ACTIVE);
    PasswordResetService reset = resetService(kit);
    String link = issue(reset, "bob");

    changeService(kit).change(change("bob", "bobs first password", "bobs second password"));

    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(link, SecretValue.ofString("bobs reset password")),
        "the optional collaborator is additive; nobody is rewired silently");
  }

  @Test
  @DisplayName("after a change the security version is raised and remember-me and refresh tokens are dead")
  void changeRevokesArtefacts() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("bob", "bobs first password", CredentialStatus.ACTIVE);
    kit.register("carol", "carols password 1", CredentialStatus.ACTIVE);
    Artefacts artefacts = new Artefacts(kit);
    String bobsCookie = artefacts.rememberMe.issue(BOB, Duration.ofDays(14)).plainToken();
    String carolsCookie = artefacts.rememberMe.issue(CAROL, Duration.ofDays(14)).plainToken();
    String bobsRefresh = artefacts.tokens.issue(BOB).refreshToken();
    String carolsRefresh = artefacts.tokens.issue(CAROL).refreshToken();
    PasswordChangeService change =
        changeService(kit).withCredentialChangeListener(artefacts.listener);

    assertInstanceOf(PasswordChangeResult.Succeeded.class,
        change.change(change("bob", "bobs first password", "bobs second password")));

    assertEquals(new JCustosVersion(1), artefacts.version(BOB));
    assertTrue(artefacts.rememberMe.validate(bobsCookie).isEmpty());
    assertTrue(artefacts.tokens.rotate(bobsRefresh).isEmpty());
    // Another subject is not affected.
    assertEquals(JCustosVersion.INITIAL, artefacts.version(CAROL));
    assertTrue(artefacts.rememberMe.validate(carolsCookie).isPresent());
    assertTrue(artefacts.tokens.rotate(carolsRefresh).isPresent());
  }

  @Test
  @DisplayName("after a consumed reset the security version is raised and remember-me and refresh tokens are dead")
  void resetRevokesArtefacts() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("bob", "bobs first password", CredentialStatus.ACTIVE);
    Artefacts artefacts = new Artefacts(kit);
    String cookie = artefacts.rememberMe.issue(BOB, Duration.ofDays(14)).plainToken();
    String refresh = artefacts.tokens.issue(BOB).refreshToken();
    PasswordResetService reset =
        resetService(kit).withCredentialChangeListener(artefacts.listener);
    String link = issue(reset, "bob");

    assertEquals(JCustosVersion.INITIAL, artefacts.version(BOB),
        "requesting a link revokes nothing — the request is unauthenticated");
    assertTrue(artefacts.rememberMe.validate(cookie).isPresent());

    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(link, SecretValue.ofString("bobs reset password")));

    assertEquals(new JCustosVersion(1), artefacts.version(BOB));
    assertTrue(artefacts.rememberMe.validate(cookie).isEmpty());
    assertTrue(artefacts.tokens.rotate(refresh).isEmpty());
  }

  @Test
  @DisplayName("a failed change does not call the listener")
  void failedChangeRevokesNothing() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("bob", "bobs first password", CredentialStatus.ACTIVE);
    List<String> calls = new ArrayList<>();
    PasswordChangeService change = changeService(kit).withCredentialChangeListener(
        (username, cause, at) -> calls.add(username + "/" + cause));

    change.change(change("bob", "not bobs password", "bobs second password"));
    change.change(change("bob", "bobs first password", "short"));
    change.change(change("nobody", "x", "bobs second password"));
    assertTrue(calls.isEmpty());

    change.change(change("bob", "bobs first password", "bobs second password"));
    assertEquals(List.of("bob/PASSWORD_CHANGED"), calls);
  }

  @Test
  @DisplayName("one failing revocation step does not keep the others from running, nor the change from succeeding")
  void revocationStepsAreIndependent() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("bob", "bobs first password", CredentialStatus.ACTIVE);
    Artefacts artefacts = new Artefacts(kit);
    String cookie = artefacts.rememberMe.issue(BOB, Duration.ofDays(14)).plainToken();
    String refresh = artefacts.tokens.issue(BOB).refreshToken();
    JCustosVersionStore brokenVersions = new JCustosVersionStore() {
      @Override
      public JCustosVersion current(JCustosVersionKey key) {
        return artefacts.versions.current(key);
      }

      @Override
      public JCustosVersion increment(JCustosVersionKey key) {
        throw new IllegalStateException("version store unavailable");
      }

      @Override
      public void reset(JCustosVersionKey key) {
        artefacts.versions.reset(key);
      }
    };
    PasswordChangeService change = changeService(kit).withCredentialChangeListener(
        RevokingCredentialChangeListener.builder()
            .versionStore(brokenVersions)
            .rememberMe(artefacts.rememberMe)
            .refreshTokens(artefacts.tokens)
            .build());

    assertInstanceOf(PasswordChangeResult.Succeeded.class,
        change.change(change("bob", "bobs first password", "bobs second password")));

    assertTrue(artefacts.rememberMe.validate(cookie).isEmpty());
    assertTrue(artefacts.tokens.rotate(refresh).isEmpty());
  }

  @Test
  @DisplayName("the listener maps the username through the configured resolver and tenant")
  void subjectResolverAndTenant() {
    InMemoryJCustosVersionStore versions = new InMemoryJCustosVersionStore();
    TenantId acme = new TenantId("acme");
    RevokingCredentialChangeListener listener = RevokingCredentialChangeListener.builder()
        .versionStore(versions)
        .tenant(acme)
        .subjectResolver(username -> SubjectId.of("user:" + username))
        .build();

    listener.credentialChanged("bob", CredentialChangeListener.Cause.PASSWORD_RESET,
        CredentialTestKit.T0);

    assertEquals(new JCustosVersion(1),
        versions.current(new JCustosVersionKey(acme, SubjectId.of("user:bob"))));
    assertEquals(JCustosVersion.INITIAL,
        versions.current(new JCustosVersionKey(TenantId.DEFAULT, SubjectId.of("bob"))));
  }
}
