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
package eu.jsentinel.jcustos.credential.abuse;

/**
 * Multi-dimensional abuse detection contract.
 *
 * <h2>Two-call flow</h2>
 * <p>Callers ask {@link #evaluate} <em>before</em> performing the
 * credential operation. The decision says whether the call may
 * proceed, must wait, must hit a step-up check, or must be blocked.
 * After the credential operation completes (success or failure), the
 * caller hands the outcome back through {@link #recordOutcome} so the
 * counters update.</p>
 *
 * <h2>Cluster note</h2>
 * <p>The in-memory reference implementation
 * ({@link InMemoryAbuseDetectionService}) keeps state on the JVM heap
 * — multi-node deployments must replace it with a clustered store
 * (Redis, Hazelcast, Postgres) so a coordinated attack cannot dodge
 * the limits by hopping nodes. The Konzept §13 calls this out as a
 * production requirement.</p>
 *
 * <h2>No leak</h2>
 * <p>Decisions stay generic; exact counters and per-dimension
 * specifics never reach the perimeter (CWE-203 / CWE-307).</p>
 */
public interface AbuseDetectionService {

  /**
   * Decides what reaction the caller should apply <em>before</em>
   * running the credential operation.
   */
  AbuseDecision evaluate(AbuseAttemptContext context);

  /**
   * Records the outcome of the operation so the counters can update.
   * Successful logins typically reset the per-username failure
   * counter; volume counters (CLIENT_ADDRESS / TENANT / GLOBAL, and
   * the per-username counter of {@code RESET_REQUEST}) keep tracking
   * irrespective of outcome — an accepted reset request is a success
   * and must still count against the account's request budget
   * (JS-SEC-121, CWE-799).
   */
  void recordOutcome(AbuseAttemptContext context, AttemptOutcome outcome);
}
