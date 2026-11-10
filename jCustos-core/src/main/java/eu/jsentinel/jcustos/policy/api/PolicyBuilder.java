/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.jsentinel.jcustos.policy.api;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import static java.util.Objects.requireNonNull;

/**
 * Fluent builder for {@link Policy} instances.
 * <p>
 * Typical usage:
 * <pre>
 * Policy p = Policy.named("document.owner-or-admin")
 *     .allowIf(SubjectPredicates.hasRole("ADMIN"))
 *     .orIf(SubjectPredicates.hasPermission("document:write"))
 *     .deny("must be admin or document:write holder")
 *     .build();
 * </pre>
 *
 * <p>Evaluation order produced by the builder:
 * <ol>
 *   <li>Every {@link #denyIf(Predicate)} predicate is checked first; the
 *       first match yields {@code Denied}.</li>
 *   <li>Then every {@link #stepUpRequiredIf(Predicate,
 *       PolicyDecision.StepUpMethod, String)} predicate is checked; the
 *       first match yields {@code StepUpRequired}.</li>
 *   <li>Then every {@link #allowIf(Predicate)} / {@link #orIf(Predicate)}
 *       predicate is checked; the first match yields {@code Allowed}.</li>
 *   <li>If no predicate matches, the result is {@code Denied} with the
 *       reason passed to {@link #deny(String)} (or a generic default).</li>
 * </ol>
 *
 * <p>Builder is not thread-safe; build the policy once at registration
 * time, then evaluate the built {@link Policy} concurrently.
 */
@ExperimentalJCustosApi
public final class PolicyBuilder {

  static final String GENERIC_DEFAULT_DENY_REASON = "policy denied";

  private final String name;
  private final List<Predicate<PolicyContext>> denyPredicates = new ArrayList<>();
  private final List<StepUpRule> stepUpRules = new ArrayList<>();
  private final List<Predicate<PolicyContext>> allowPredicates = new ArrayList<>();
  private String defaultDenyReason = GENERIC_DEFAULT_DENY_REASON;
  private boolean allowAnonymous;

  /**
   * Internal step-up rule: a predicate plus the step-up method and
   * reason emitted when it matches. Package-visible so
   * {@code NamedPolicy} can read the components without exposing the
   * mutable builder state.
   */
  record StepUpRule(
      Predicate<PolicyContext> predicate,
      PolicyDecision.StepUpMethod method,
      String reason) {
    StepUpRule {
      requireNonNull(predicate, "predicate must not be null");
      requireNonNull(method, "method must not be null");
      reason = reason == null ? "" : reason;
    }
  }

  PolicyBuilder(String name) {
    if (name == null || name.isBlank()) {
      throw new IllegalArgumentException("policy name must not be blank");
    }
    this.name = name;
  }

  /**
   * Adds an allow-predicate. The built policy returns {@code Allowed} if
   * any registered allow-predicate (added via {@link #allowIf(Predicate)}
   * or {@link #orIf(Predicate)}) matches the context and no
   * deny-predicate matched first.
   *
   * @param predicate predicate; must not be {@code null}
   * @return this builder
   */
  public PolicyBuilder allowIf(Predicate<PolicyContext> predicate) {
    allowPredicates.add(requireNonNull(predicate, "predicate must not be null"));
    return this;
  }

  /**
   * Alias of {@link #allowIf(Predicate)} for chained reading
   * (e.g. {@code .allowIf(a).orIf(b)}).
   *
   * @param predicate predicate; must not be {@code null}
   * @return this builder
   */
  public PolicyBuilder orIf(Predicate<PolicyContext> predicate) {
    return allowIf(predicate);
  }

  /**
   * Adds a deny-predicate. The built policy returns {@code Denied}
   * immediately if any registered deny-predicate matches.
   *
   * @param predicate predicate; must not be {@code null}
   * @return this builder
   */
  public PolicyBuilder denyIf(Predicate<PolicyContext> predicate) {
    denyPredicates.add(requireNonNull(predicate, "predicate must not be null"));
    return this;
  }

  /**
   * Adds a step-up rule. The built policy returns
   * {@code StepUpRequired(reason, method)} when the predicate matches
   * and no deny-predicate matched first.
   *
   * <p>Adapter-side routing for the step-up case (MFA challenge,
   * re-auth) is part of a later phase; until then,
   * {@link PolicyDecisions#toAuthorizationDecision(PolicyDecision)}
   * bridges {@code StepUpRequired} to a {@code Forbidden} with a
   * structured reason prefix.
   *
   * @param predicate predicate; must not be {@code null}
   * @param method    step-up mechanism; must not be {@code null}
   * @param reason    short diagnostic; {@code null} becomes empty string
   * @return this builder
   */
  public PolicyBuilder stepUpRequiredIf(
      Predicate<PolicyContext> predicate,
      PolicyDecision.StepUpMethod method,
      String reason) {
    stepUpRules.add(new StepUpRule(predicate, method, reason));
    return this;
  }

  /**
   * Sets the reason returned for the fall-through {@code Denied} case
   * (no allow-predicate matched, no deny-predicate matched).
   *
   * @param reason non-blank reason
   * @return this builder
   */
  public PolicyBuilder deny(String reason) {
    if (reason == null || reason.isBlank()) {
      throw new IllegalArgumentException("default deny reason must not be blank");
    }
    this.defaultDenyReason = reason;
    return this;
  }

  /**
   * Opts the policy in to anonymous evaluation (JS-SEC-157, CWE-306).
   *
   * <p>Without this call a request that carries no authenticated subject is
   * refused as <em>unauthenticated</em> by {@code @RequiresPolicy} and
   * {@code JCustosEnforcer.requirePolicy(...)} before the policy is consulted.
   * Call it only for a policy that is meant to guard something reachable
   * without signing in — an office-network gate in front of a status page,
   * say — and whose predicates do not assume a subject.
   *
   * @return this builder
   * @see Policy#allowsAnonymous()
   * @since 00.84.00
   */
  public PolicyBuilder allowAnonymous() {
    this.allowAnonymous = true;
    return this;
  }

  /**
   * Builds the policy.
   *
   * @return policy
   * @throws IllegalStateException if neither an allow- nor a
   *         deny-predicate has been added
   */
  public Policy build() {
    if (allowPredicates.isEmpty() && denyPredicates.isEmpty() && stepUpRules.isEmpty()) {
      throw new IllegalStateException(
          "policy '" + name
              + "' requires at least one allowIf/orIf/denyIf/stepUpRequiredIf predicate");
    }
    return new NamedPolicy(
        name,
        List.copyOf(denyPredicates),
        List.copyOf(stepUpRules),
        List.copyOf(allowPredicates),
        defaultDenyReason,
        allowAnonymous);
  }
}
