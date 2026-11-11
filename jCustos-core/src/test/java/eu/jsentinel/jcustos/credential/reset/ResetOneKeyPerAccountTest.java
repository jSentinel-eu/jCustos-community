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
package eu.jsentinel.jcustos.credential.reset;

import eu.jsentinel.jcustos.audit.PasswordResetRequested;
import eu.jsentinel.jcustos.authentication.InMemoryRememberMeTokenStore;
import eu.jsentinel.jcustos.authentication.StoreBackedRememberMeService;
import eu.jsentinel.jcustos.credential.CredentialTestKit;
import eu.jsentinel.jcustos.credential.change.CredentialChangeListener;
import eu.jsentinel.jcustos.credential.change.PasswordChangeCommand;
import eu.jsentinel.jcustos.credential.change.PasswordChangeResult;
import eu.jsentinel.jcustos.credential.change.PasswordChangeService;
import eu.jsentinel.jcustos.credential.change.RevokingCredentialChangeListener;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.token.Sha256TokenHasher;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-123 (CWE-178): the credential store decides which spellings of a user
 * name are one account. The reset and change services key what they keep for
 * an account on the name of its record, so a request under another spelling
 * reaches the same reset links, the same remembered status and the same
 * subject.
 */
@DisplayName("JS-SEC-123 — reset and change act on the account, whatever spelling the request uses")
class ResetOneKeyPerAccountTest {

  private static final Duration TTL = Duration.ofMinutes(15);

  private static PasswordResetService resetService(CredentialTestKit kit) {
    return new PasswordResetService(kit.credentials, kit.resetTokens, kit.digests, kit.hashing,
        kit.validator, kit.inputPolicy, kit.lifecycle(), kit.clock, kit.audit);
  }

  private static PasswordChangeService changeService(CredentialTestKit kit) {
    return new PasswordChangeService(kit.credentials, kit.hashing, kit.validator,
        kit.inputPolicy, kit.lifecycle(), kit.clock);
  }

  private static String wire(ResetTokenCreationResult result) {
    return assertInstanceOf(ResetTokenCreationResult.Created.class, result).token().encode();
  }

  private static SecretValue secret(String value) {
    return SecretValue.ofString(value);
  }

  @Test
  @DisplayName("a link requested as 'ALICE' retires the link requested as 'alice': only the newest link of the account works")
  void requestUnderAnotherSpellingRetiresTheOlderLink() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);
    PasswordResetService reset = resetService(kit);

    String older = wire(reset.issue("alice", TTL));
    String newer = wire(reset.issue("ALICE", TTL));

    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        reset.consume(older, secret("password from the older link")),
        "the older link must be dead although it was requested under another spelling");
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        reset.consume(newer, secret("password from the newer link")));
    assertTrue(kit.passwordIs("alice", "password from the newer link"));
  }

  @Test
  @DisplayName("every token of the account is stored and audited under the name of its record")
  void tokensAndAuditCarryTheAccountName() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);
    PasswordResetService reset = resetService(kit);

    wire(reset.issue(" Alice ", TTL));

    assertEquals(1, kit.resetTokens.findByUsername("alice").size());
    assertTrue(kit.resetTokens.findByUsername(" Alice ").isEmpty());
    List<String> audited = kit.audit.events.stream()
        .filter(PasswordResetRequested.class::isInstance)
        .map(e -> ((PasswordResetRequested) e).subjectId())
        .toList();
    assertEquals(List.of("alice"), audited);
  }

  @Test
  @DisplayName("a password change requested as 'ALICE' retires the reset link requested as 'alice'")
  void changeUnderAnotherSpellingRetiresOpenLinks() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);
    PasswordResetService reset = resetService(kit);
    PasswordChangeService change = changeService(kit).withResetTokenStore(kit.resetTokens);
    String intercepted = wire(reset.issue("alice", TTL));

    assertInstanceOf(PasswordChangeResult.Succeeded.class, change.change(
        new PasswordChangeCommand("ALICE", secret("correct horse battery"),
            secret("alices second password"))));

    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        reset.consume(intercepted, secret("attackers password")),
        "a link issued before the change must not replace the new password");
    assertTrue(kit.passwordIs("alice", "alices second password"));
  }

  @Test
  @DisplayName("a password change requested as 'ALICE' tells the listener the account 'alice' and revokes its remember-me tokens")
  void changeUnderAnotherSpellingRevokesTheAccountsTokens() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);
    StoreBackedRememberMeService rememberMe = new StoreBackedRememberMeService(
        new InMemoryRememberMeTokenStore(), new Sha256TokenHasher());
    String remembered = rememberMe.issue(SubjectId.of("alice"), Duration.ofDays(14)).plainToken();
    List<String> notified = new ArrayList<>();
    CredentialChangeListener revoking =
        RevokingCredentialChangeListener.builder().rememberMe(rememberMe).build();
    PasswordChangeService change = changeService(kit).withCredentialChangeListener(
        (username, cause, at) -> {
          notified.add(username);
          revoking.credentialChanged(username, cause, at);
        });

    assertInstanceOf(PasswordChangeResult.Succeeded.class, change.change(
        new PasswordChangeCommand("ALICE", secret("correct horse battery"),
            secret("alices second password"))));

    assertEquals(List.of("alice"), notified);
    assertTrue(rememberMe.validate(remembered).isEmpty(),
        "the remembered login of the account must not survive the password change");
  }

  @Test
  @DisplayName("the way out of COMPROMISED works across spellings: issue as 'ALICE', release as 'Alice'")
  void compromisedPathFollowsTheAccount() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", "leaked password 1", CredentialStatus.COMPROMISED);
    PasswordResetService reset = resetService(kit);

    wire(reset.issue("ALICE", TTL));
    assertEquals(CredentialStatus.RESET_PENDING, kit.status("alice"));
    assertEquals(Optional.of(CredentialStatus.COMPROMISED),
        kit.resetTokens.statusBeforeReset("alice"));

    kit.clock.advance(TTL.plusSeconds(1));

    assertEquals(Optional.of(CredentialStatus.COMPROMISED), reset.releaseLapsedReset("Alice"));
    assertEquals(CredentialStatus.COMPROMISED, kit.status("alice"));
  }

  @Test
  @DisplayName("an unknown name is still unknown and stores nothing")
  void unknownNameStoresNothing() {
    CredentialTestKit kit = new CredentialTestKit();
    kit.register("alice", "correct horse battery", CredentialStatus.ACTIVE);
    PasswordResetService reset = resetService(kit);

    assertSame(ResetTokenCreationResult.UnknownUser.INSTANCE, reset.issue("mallory", TTL));
    assertTrue(kit.resetTokens.findByUsername("mallory").isEmpty());
    assertEquals(Optional.empty(), reset.releaseLapsedReset("mallory"));
  }
}
