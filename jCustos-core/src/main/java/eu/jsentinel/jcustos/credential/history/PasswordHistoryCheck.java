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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.credential.InternalAuditEventType;

import java.util.Objects;

/**
 * Outcome of {@link PasswordHistoryService#check}: the three things a
 * history check can find out, kept apart.
 *
 * <p>JS-SEC-126 (CWE-636): {@link PasswordHistoryDecision} knows only
 * "allowed" and "reused", and the service used to file every entry it could
 * not verify under "allowed" - a saturated KDF limiter, or history entries
 * whose algorithm, parameters or pepper key are no longer accepted, switched
 * the history off. This type adds the missing third answer without changing
 * the older one.</p>
 *
 * <ul>
 *   <li>{@link NotReused} - every retained entry was verified and none
 *       matched;</li>
 *   <li>{@link Reused} - the candidate matches a retained entry;</li>
 *   <li>{@link Indeterminate} - no entry matched, but at least one could
 *       not be verified, so "not reused" is not established.</li>
 * </ul>
 *
 * <p>Callers reject the change on anything but {@link NotReused}. For
 * {@link Indeterminate} the {@linkplain Indeterminate#transientCondition()
 * transient} case ("try again in a moment") differs from the lasting one,
 * which an operator has to resolve - typically by keeping the old algorithm
 * verifiable or by clearing the affected history.</p>
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public sealed interface PasswordHistoryCheck
    permits PasswordHistoryCheck.NotReused,
            PasswordHistoryCheck.Reused,
            PasswordHistoryCheck.Indeterminate {

  /** Every retained entry was verified; none matches the candidate. */
  record NotReused() implements PasswordHistoryCheck {
    /** Shared instance. */
    public static final NotReused INSTANCE = new NotReused();
  }

  /** The candidate matches a retained entry and must be rejected. */
  record Reused() implements PasswordHistoryCheck {
    /** Shared instance. */
    public static final Reused INSTANCE = new Reused();
  }

  /**
   * At least one retained entry could not be verified and none of the
   * others matched.
   *
   * @param reason internal classification of the first entry that could
   *               not be verified; for audit and metrics, never for the
   *               user
   */
  record Indeterminate(InternalAuditEventType reason) implements PasswordHistoryCheck {

    /** Validates the component. */
    public Indeterminate {
      Objects.requireNonNull(reason, "reason");
    }

    /**
     * @return {@code true} when the cause is load shedding and a retry can
     *         succeed; {@code false} when the entry stays unverifiable until
     *         the configuration changes
     */
    public boolean transientCondition() {
      return reason == InternalAuditEventType.VERIFICATION_REJECTED_KDF_LIMIT;
    }
  }
}
