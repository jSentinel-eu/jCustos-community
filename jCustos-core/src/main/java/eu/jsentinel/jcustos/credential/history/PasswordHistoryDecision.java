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

/**
 * Outcome of {@link PasswordHistoryService#evaluate}.
 *
 * <p>Sealed so callers pattern-match exhaustively, replacing the
 * primitive-boolean pattern (CWE-287). Adapters MUST surface the
 * {@code Reused} variant as the same generic perimeter message they
 * use for input-policy violations.</p>
 */
public sealed interface PasswordHistoryDecision
    permits PasswordHistoryDecision.Allowed,
            PasswordHistoryDecision.Reused {

  /**
   * The candidate password did not match any retained historical
   * entry — proceed.
   */
  record Allowed() implements PasswordHistoryDecision {
    public static final Allowed INSTANCE = new Allowed();
  }

  /**
   * The candidate password matched one of the retained historical
   * verifiers and must be rejected.
   *
   * <p>JS-SEC-126 (CWE-636): also the answer when a retained verifier
   * could not be verified at all, so that "could not tell" is rejected
   * rather than let through. {@link PasswordHistoryService#check} keeps
   * the two cases apart ({@link PasswordHistoryCheck.Indeterminate}).</p>
   */
  record Reused() implements PasswordHistoryDecision {
    public static final Reused INSTANCE = new Reused();
  }
}
