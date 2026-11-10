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
package eu.jsentinel.jcustos.credential.history;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.credential.InternalAuditEventType;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.secret.SecretValue;

import java.time.Instant;
import java.util.Objects;

/**
 * Coordinates the optional password-history check.
 *
 * <p>Adapters call {@link #check(String, SecretValue, PasswordHistoryPolicy)}
 * (or the older {@link #evaluate(String, SecretValue, PasswordHistoryPolicy)})
 * with the candidate password <em>before</em> persisting the new hash.
 * If the policy is disabled the service reports "not reused" without
 * touching the store. If enabled it verifies the candidate against each
 * retained verifier through the same {@link PasswordHashingService} used for
 * the normal login path — old envelopes therefore remain readable
 * as long as their algorithm is still registered (CWE-693).</p>
 *
 * <p><strong>Fail closed (JS-SEC-126, CWE-636).</strong> Only a genuine
 * mismatch counts as "this entry is not the candidate". An entry that could
 * not be verified — the KDF limiter shed the call, the envelope's algorithm,
 * parameters or pepper key are no longer accepted — proves nothing, and the
 * check does not report "not reused" on the strength of it.</p>
 *
 * <p>After a successful change adapters call
 * {@link #recordNew(String, String, Instant, PasswordHistoryPolicy)}
 * with the freshly produced envelope and the active retention
 * setting. The store enforces the cap via
 * {@link PasswordHistoryStore#appendAndTrim} (CWE-400).</p>
 */
public final class PasswordHistoryService implements HasLogger {

  private final PasswordHistoryStore store;
  private final PasswordHashingService hashingService;

  public PasswordHistoryService(
      PasswordHistoryStore store,
      PasswordHashingService hashingService) {
    this.store = Objects.requireNonNull(store, "store");
    this.hashingService = Objects.requireNonNull(hashingService, "hashingService");
  }

  /**
   * Checks the candidate against the retained envelopes and keeps "could
   * not tell" apart from "not reused".
   *
   * <ul>
   *   <li>a retained entry verifies → {@link PasswordHistoryCheck.Reused};</li>
   *   <li>every retained entry was evaluated and mismatched →
   *       {@link PasswordHistoryCheck.NotReused};</li>
   *   <li>otherwise → {@link PasswordHistoryCheck.Indeterminate} with the
   *       reason of the first entry that could not be verified. Load
   *       shedding ends the check at once — more KDF work would only deepen
   *       the overload; an entry that is unverifiable for good does not,
   *       because a later entry can still prove a reuse.</li>
   * </ul>
   *
   * <p>History disabled or retention size 0 → always
   * {@link PasswordHistoryCheck.NotReused}.</p>
   *
   * @param username  account whose history is consulted
   * @param candidate the new password
   * @param policy    active history policy
   * @return the outcome; never {@code null}
   * @since 00.84.00
   */
  public PasswordHistoryCheck check(
      String username,
      SecretValue candidate,
      PasswordHistoryPolicy policy) {
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(candidate, "candidate");
    Objects.requireNonNull(policy, "policy");
    if (!policy.enabled()) {
      return PasswordHistoryCheck.NotReused.INSTANCE;
    }
    InternalAuditEventType unverifiable = null;
    for (PasswordHistoryEntry entry : store.recent(username, policy.retainLast())) {
      CredentialVerificationResult result =
          hashingService.verify(candidate, entry.encodedHash());
      if (result instanceof CredentialVerificationResult.Verified) {
        return PasswordHistoryCheck.Reused.INSTANCE;
      }
      // JS-SEC-126 (CWE-636): only a mismatch is a miss. Everything else is "do not know".
      InternalAuditEventType reason =
          ((CredentialVerificationResult.Failed) result).internalAuditEventType();
      if (reason == InternalAuditEventType.VERIFICATION_FAILED_MISMATCH) {
        continue;
      }
      if (result.temporarilyUnavailable()
          || reason == InternalAuditEventType.VERIFICATION_REJECTED_KDF_LIMIT) {
        return new PasswordHistoryCheck.Indeterminate(reason);
      }
      if (unverifiable == null) {
        unverifiable = reason;
      }
    }
    return unverifiable == null
        ? PasswordHistoryCheck.NotReused.INSTANCE
        : new PasswordHistoryCheck.Indeterminate(unverifiable);
  }

  /**
   * Returns {@link PasswordHistoryDecision.Reused} when the supplied
   * candidate verifies against any retained envelope under {@code policy}.
   * History disabled or retention size 0 → always
   * {@link PasswordHistoryDecision.Allowed}.
   *
   * <p>JS-SEC-126 (CWE-636): this two-valued form cannot say "could not
   * tell", so it fails closed — when {@link #check} is
   * {@link PasswordHistoryCheck.Indeterminate} the answer is
   * {@link PasswordHistoryDecision.Reused}, the variant every caller
   * already rejects, and {@code credential/history-indeterminate} is
   * logged. Until 00.83.00 the answer was {@code Allowed}. Callers that
   * want to tell the user "try again" rather than "choose another
   * password" use {@link #check}.</p>
   */
  public PasswordHistoryDecision evaluate(
      String username,
      SecretValue candidate,
      PasswordHistoryPolicy policy) {
    return switch (check(username, candidate, policy)) {
      case PasswordHistoryCheck.NotReused ignored -> PasswordHistoryDecision.Allowed.INSTANCE;
      case PasswordHistoryCheck.Reused ignored -> PasswordHistoryDecision.Reused.INSTANCE;
      case PasswordHistoryCheck.Indeterminate indeterminate -> {
        // no user name in the line: it is caller-supplied text
        logger().warn("credential/history-indeterminate: a retained password could not be "
            + "verified ({}); the change is rejected instead of being let through.",
            indeterminate.reason());
        yield PasswordHistoryDecision.Reused.INSTANCE;
      }
    };
  }

  /**
   * Records the new envelope in the per-user history and trims to the
   * retention size. No-op when {@code policy.enabled()} is false.
   */
  public void recordNew(
      String username,
      String encodedHash,
      Instant when,
      PasswordHistoryPolicy policy) {
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(encodedHash, "encodedHash");
    Objects.requireNonNull(when, "when");
    Objects.requireNonNull(policy, "policy");
    if (!policy.enabled()) {
      return;
    }
    store.appendAndTrim(
        username,
        new PasswordHistoryEntry(encodedHash, when),
        policy.retainLast());
  }
}
