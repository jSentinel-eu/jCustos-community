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
package eu.jsentinel.jcustos.credential.emergency;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.CredentialStatusChanged;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.credential.store.CredentialRecord;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.store.CredentialStore;
import eu.jsentinel.jcustos.credential.store.CredentialUpdateResult;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Operational helper for incident response: bulk-transition every
 * named credential into a single target status (typically
 * {@link CredentialStatus#MUST_CHANGE} or
 * {@link CredentialStatus#COMPROMISED}).
 *
 * <p>The helper exists because the {@link CredentialStore} contract
 * deliberately exposes no iteration — the operator (or the consuming
 * application) chooses which subjects are in scope by supplying an
 * {@link Iterable Iterable&lt;String&gt;} of usernames. This shape
 * works the same against an in-memory store, a SQL store with a
 * cursor, or an Eclipse-Store snapshot.</p>
 *
 * <p>Every successful transition publishes a
 * {@link CredentialStatusChanged} audit event so the incident
 * timeline is preserved (CWE-778). Records that are already at the
 * target status are skipped; records that are missing from the
 * store are recorded as {@link Report#notFound()} so the operator
 * can investigate residue.</p>
 */
public final class MassCredentialStatusChange implements HasLogger {

  private final CredentialStore store;
  private final JCustosAuditService audit;
  private final Clock clock;

  public MassCredentialStatusChange(
      CredentialStore store,
      JCustosAuditService audit,
      Clock clock) {
    this.store = Objects.requireNonNull(store, "store");
    this.audit = Objects.requireNonNull(audit, "audit");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Transitions each named credential to {@code targetStatus}.
   *
   * @param usernames    subjects in scope
   * @param targetStatus the new status to set
   * @param override     the operator-declared incident context; its
   *                     {@code incidentId} and {@code reason.name()}
   *                     are recorded in the audit reason field
   * @return a {@link Report} with per-username outcomes; the report
   *         carries counts only — never the secret data of any
   *         touched record
   */
  public Report forceAllToStatus(
      Iterable<String> usernames,
      CredentialStatus targetStatus,
      EmergencyPolicyOverride override) {
    Objects.requireNonNull(usernames, "usernames");
    Objects.requireNonNull(targetStatus, "targetStatus");
    Objects.requireNonNull(override, "override");

    int changed = 0;
    int alreadyAtTarget = 0;
    int notFound = 0;
    int stale = 0;
    int auditFailures = 0;
    Instant when = Instant.now(clock);
    String reason = override.incidentId()
        + "/" + override.reason().name();

    for (String username : usernames) {
      if (username == null || username.isBlank()) {
        notFound++;
        continue;
      }
      Optional<CredentialRecord> current = store.findByUsername(username);
      if (current.isEmpty()) {
        notFound++;
        continue;
      }
      CredentialStatus from = current.get().status();
      if (from == targetStatus) {
        alreadyAtTarget++;
        continue;
      }
      CredentialUpdateResult result = store.updateStatusIfCurrent(
          username, from, targetStatus, when);
      switch (result) {
        case CredentialUpdateResult.Updated u -> {
          changed++;
          // JS-SEC-077 (CWE-703): the status is already written. A failing audit
          // sink must not abort the incident run and leave the remaining
          // accounts untouched — count it, log it, continue.
          if (!publish(new CredentialStatusChanged(when, username, from, targetStatus, reason))) {
            auditFailures++;
          }
        }
        case CredentialUpdateResult.Stale s -> stale++;
        case CredentialUpdateResult.NotFound nf -> notFound++;
      }
    }
    return new Report(changed, alreadyAtTarget, notFound, stale, auditFailures);
  }

  /**
   * Aggregate report of a mass status change. Counts only — the
   * report deliberately does not list affected usernames so the
   * incident-response output stream stays small and free of any
   * subject-level identifiers.
   */
  private boolean publish(CredentialStatusChanged event) {
    try {
      audit.publish(event);
      return true;
    } catch (RuntimeException auditFailure) {
      logger().warn("audit sink failed during emergency status change of {} ({} -> {}): {}",
          event.username(), event.fromStatus(), event.toStatus(), auditFailure.toString());
      return false;
    }
  }

  public record Report(int changed, int alreadyAtTarget, int notFound, int stale, int auditFailures) {
    public Report {
      if (changed < 0 || alreadyAtTarget < 0 || notFound < 0 || stale < 0 || auditFailures < 0) {
        throw new IllegalArgumentException("counts must be >= 0");
      }
    }

    /**
     * Report without audit failures — the shape before 00.84.00.
     *
     * @param changed         credentials moved to the target status
     * @param alreadyAtTarget credentials already at the target status
     * @param notFound        usernames without a credential (or blank)
     * @param stale           credentials whose status changed concurrently
     */
    public Report(int changed, int alreadyAtTarget, int notFound, int stale) {
      this(changed, alreadyAtTarget, notFound, stale, 0);
    }

    public int total() {
      return changed + alreadyAtTarget + notFound + stale;
    }
  }
}
