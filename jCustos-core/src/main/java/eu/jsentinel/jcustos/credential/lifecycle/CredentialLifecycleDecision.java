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
package eu.jsentinel.jcustos.credential.lifecycle;

/**
 * Adapter-neutral decision derived from a credential's current
 * lifecycle status.
 *
 * <p>The decision never references HTTP redirects, Vaadin routes or
 * any UI action. Adapters (Vaadin/REST/Standalone) own the mapping
 * from {@link CredentialLifecycleDecision} to a concrete user-visible
 * response (CWE-284).</p>
 */
public sealed interface CredentialLifecycleDecision
    permits CredentialLifecycleDecision.Proceed,
            CredentialLifecycleDecision.ForcePasswordChange,
            CredentialLifecycleDecision.ResetInProgress,
            CredentialLifecycleDecision.BlockedTemporary,
            CredentialLifecycleDecision.BlockedPermanent {

  /**
   * Normal login allowed. A rehash flag may still trigger a transparent
   * upgrade, but the lifecycle layer has nothing to add.
   */
  record Proceed() implements CredentialLifecycleDecision {
    public static final Proceed INSTANCE = new Proceed();
  }

  /**
   * Credentials verified, but the user must change the password before
   * the session may proceed.
   */
  record ForcePasswordChange() implements CredentialLifecycleDecision {
    public static final ForcePasswordChange INSTANCE = new ForcePasswordChange();
  }

  /**
   * The credential is {@code RESET_PENDING}: its secret may only be
   * replaced through the reset flow, and the password login stays closed
   * until a reset link is consumed.
   *
   * <p>Since 00.84.00 a reset <em>request</em> no longer puts a usable
   * credential into this state (JS-SEC-121, CWE-645): the request is
   * unauthenticated, and a decision that closes the password login must
   * not be obtainable by anyone who knows a username. The state is
   * reached from {@code COMPROMISED} when a reset is requested
   * (JS-SEC-076) and by an explicit administrative transition. A
   * credential that entered it from {@code COMPROMISED} returns there
   * when its last open link lapses unused.</p>
   */
  record ResetInProgress() implements CredentialLifecycleDecision {
    public static final ResetInProgress INSTANCE = new ResetInProgress();
  }

  /**
   * Temporary block (typically {@code LOCKED}). The adapter surfaces
   * this as a generic "try again later" without revealing the lockout
   * counter (CWE-203).
   */
  record BlockedTemporary() implements CredentialLifecycleDecision {
    public static final BlockedTemporary INSTANCE = new BlockedTemporary();
  }

  /**
   * Permanent block (typically {@code COMPROMISED} or {@code DISABLED}).
   * Adapters surface this as a generic failure too — the differentiated
   * reason stays in audit (CWE-284).
   */
  record BlockedPermanent() implements CredentialLifecycleDecision {
    public static final BlockedPermanent INSTANCE = new BlockedPermanent();
  }
}
