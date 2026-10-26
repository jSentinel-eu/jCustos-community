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

import eu.jsentinel.jcustos.audit.CredentialStatusChanged;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.store.CredentialStore;
import eu.jsentinel.jcustos.credential.store.CredentialUpdateResult;

import java.time.Clock;
import java.time.Instant;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Owns the lifecycle of stored credentials and the rules for moving
 * between {@link CredentialStatus} values.
 *
 * <h2>Decision side</h2>
 * <p>{@link #decide(CredentialStatus)} is a pure function: given a
 * stored status, returns the adapter-neutral
 * {@link CredentialLifecycleDecision}. No I/O, no audit.</p>
 *
 * <h2>Transition side</h2>
 * <p>{@link #transition(String, CredentialStatus, CredentialStatus, String)}
 * checks the configured state machine, calls
 * {@link CredentialStore#updateStatusIfCurrent} for the CAS, and
 * publishes {@link CredentialStatusChanged} on success. Disallowed
 * transitions throw {@link InvalidStatusTransitionException}
 * deterministically <em>before</em> touching the store
 * (CWE-284 / CWE-778).</p>
 */
public final class CredentialLifecycleService {

  private static final Map<CredentialStatus, Set<CredentialStatus>> ALLOWED =
      buildAllowedTransitions();

  private final CredentialStore store;
  private final JCustosAuditService auditService;
  private final Clock clock;

  public CredentialLifecycleService(
      CredentialStore store,
      JCustosAuditService auditService,
      Clock clock) {
    this.store = Objects.requireNonNull(store, "store");
    this.auditService = Objects.requireNonNull(auditService, "auditService");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Pure decision: maps stored status onto the adapter-neutral
   * lifecycle decision.
   */
  public CredentialLifecycleDecision decide(CredentialStatus status) {
    Objects.requireNonNull(status, "status");
    return switch (status) {
      case ACTIVE, REHASH_REQUIRED, DEPRECATED_ALGORITHM ->
          CredentialLifecycleDecision.Proceed.INSTANCE;
      case MUST_CHANGE ->
          CredentialLifecycleDecision.ForcePasswordChange.INSTANCE;
      case RESET_PENDING ->
          CredentialLifecycleDecision.ResetInProgress.INSTANCE;
      case LOCKED ->
          CredentialLifecycleDecision.BlockedTemporary.INSTANCE;
      case COMPROMISED, DISABLED ->
          CredentialLifecycleDecision.BlockedPermanent.INSTANCE;
    };
  }

  /**
   * Returns whether a transition is part of the configured state
   * machine. Exposed so adapters can preview decisions.
   */
  public boolean isAllowed(CredentialStatus from, CredentialStatus to) {
    Objects.requireNonNull(from, "from");
    Objects.requireNonNull(to, "to");
    return ALLOWED.getOrDefault(from, EnumSet.noneOf(CredentialStatus.class))
        .contains(to);
  }

  /**
   * Atomic state transition. Validates against the state machine, then
   * performs a CAS through the store.
   *
   * @param reason optional structural reason key (kept short; audit-only)
   * @throws InvalidStatusTransitionException if {@code expected → target}
   *                                          is not part of the state
   *                                          machine
   */
  public CredentialUpdateResult transition(
      String username,
      CredentialStatus expected,
      CredentialStatus target,
      String reason) {
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(expected, "expected");
    Objects.requireNonNull(target, "target");
    if (!isAllowed(expected, target)) {
      throw new InvalidStatusTransitionException(expected, target);
    }
    Instant when = Instant.now(clock);
    CredentialUpdateResult result = store.updateStatusIfCurrent(
        username, expected, target, when);
    if (result instanceof CredentialUpdateResult.Updated) {
      safePublish(new CredentialStatusChanged(
          when, username, expected, target, reason));
    }
    return result;
  }

  private void safePublish(CredentialStatusChanged event) {
    try {
      auditService.publish(event);
    } catch (RuntimeException ignored) {
      // Never let audit failure block a security-critical transition.
    }
  }

  private static Map<CredentialStatus, Set<CredentialStatus>> buildAllowedTransitions() {
    Map<CredentialStatus, Set<CredentialStatus>> map = new EnumMap<>(CredentialStatus.class);
    map.put(CredentialStatus.ACTIVE, EnumSet.of(
        CredentialStatus.MUST_CHANGE,
        CredentialStatus.RESET_PENDING,
        CredentialStatus.COMPROMISED,
        CredentialStatus.LOCKED,
        CredentialStatus.DISABLED,
        CredentialStatus.REHASH_REQUIRED,
        CredentialStatus.DEPRECATED_ALGORITHM));
    map.put(CredentialStatus.MUST_CHANGE, EnumSet.of(
        CredentialStatus.ACTIVE,
        CredentialStatus.COMPROMISED,
        CredentialStatus.LOCKED,
        CredentialStatus.DISABLED));
    map.put(CredentialStatus.RESET_PENDING, EnumSet.of(
        CredentialStatus.ACTIVE,
        CredentialStatus.COMPROMISED,
        CredentialStatus.DISABLED));
    map.put(CredentialStatus.LOCKED, EnumSet.of(
        CredentialStatus.ACTIVE,
        CredentialStatus.COMPROMISED,
        CredentialStatus.DISABLED));
    map.put(CredentialStatus.REHASH_REQUIRED, EnumSet.of(
        CredentialStatus.ACTIVE,
        CredentialStatus.COMPROMISED,
        CredentialStatus.DISABLED));
    map.put(CredentialStatus.DEPRECATED_ALGORITHM, EnumSet.of(
        CredentialStatus.ACTIVE,
        CredentialStatus.COMPROMISED,
        CredentialStatus.DISABLED));
    // JS-SEC-076 (CWE-284): a compromised secret must never be accepted again
    // unchanged. The only ways out of COMPROMISED rotate the secret (forced
    // change, reset) or retire the credential; ACTIVE is reachable from there
    // only after the rotation. The incident-response bulk path
    // (MassCredentialStatusChange) writes statuses directly and is unaffected.
    map.put(CredentialStatus.COMPROMISED, EnumSet.of(
        CredentialStatus.MUST_CHANGE,
        CredentialStatus.RESET_PENDING,
        CredentialStatus.DISABLED));
    // Re-enabling a disabled credential is an administrative decision about
    // the account, not a statement about the secret, so ACTIVE stays allowed;
    // MUST_CHANGE and RESET_PENDING offer the safer re-enable.
    map.put(CredentialStatus.DISABLED, EnumSet.of(
        CredentialStatus.ACTIVE,
        CredentialStatus.MUST_CHANGE,
        CredentialStatus.RESET_PENDING));
    return java.util.Collections.unmodifiableMap(map);
  }
}
