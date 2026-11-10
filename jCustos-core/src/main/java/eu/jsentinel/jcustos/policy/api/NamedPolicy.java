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

import java.util.List;
import java.util.function.Predicate;

/**
 * Default implementation of {@link Policy} produced by
 * {@link PolicyBuilder}. Package-private — instances are obtained via
 * {@code Policy.named(...).build()}.
 */
final class NamedPolicy implements Policy {

  private final String name;
  private final List<Predicate<PolicyContext>> denyPredicates;
  private final List<PolicyBuilder.StepUpRule> stepUpRules;
  private final List<Predicate<PolicyContext>> allowPredicates;
  private final String defaultDenyReason;
  private final boolean allowAnonymous;

  NamedPolicy(String name,
              List<Predicate<PolicyContext>> denyPredicates,
              List<PolicyBuilder.StepUpRule> stepUpRules,
              List<Predicate<PolicyContext>> allowPredicates,
              String defaultDenyReason) {
    this(name, denyPredicates, stepUpRules, allowPredicates, defaultDenyReason, false);
  }

  NamedPolicy(String name,
              List<Predicate<PolicyContext>> denyPredicates,
              List<PolicyBuilder.StepUpRule> stepUpRules,
              List<Predicate<PolicyContext>> allowPredicates,
              String defaultDenyReason,
              boolean allowAnonymous) {
    this.name = name;
    this.denyPredicates = denyPredicates;
    this.stepUpRules = stepUpRules;
    this.allowPredicates = allowPredicates;
    this.defaultDenyReason = defaultDenyReason;
    this.allowAnonymous = allowAnonymous;
  }

  /** JS-SEC-157 (CWE-306): the explicit opt-in to anonymous evaluation. */
  @Override
  public boolean allowsAnonymous() {
    return allowAnonymous;
  }

  /** @return a copy of this policy that opted in to anonymous evaluation */
  NamedPolicy allowingAnonymous() {
    return new NamedPolicy(
        name, denyPredicates, stepUpRules, allowPredicates, defaultDenyReason, true);
  }

  @Override
  public String name() {
    return name;
  }

  @Override
  public PolicyDecision evaluate(PolicyContext context) {
    if (context == null) {
      throw new NullPointerException("context must not be null");
    }
    for (Predicate<PolicyContext> denyPredicate : denyPredicates) {
      if (denyPredicate.test(context)) {
        return PolicyDecision.denied("policy '" + name + "' explicit-deny");
      }
    }
    for (PolicyBuilder.StepUpRule rule : stepUpRules) {
      if (rule.predicate().test(context)) {
        return PolicyDecision.stepUpRequired(rule.reason(), rule.method());
      }
    }
    for (Predicate<PolicyContext> allowPredicate : allowPredicates) {
      if (allowPredicate.test(context)) {
        return PolicyDecision.allowed("policy '" + name + "' allow");
      }
    }
    return PolicyDecision.denied(defaultDenyReason);
  }
}
