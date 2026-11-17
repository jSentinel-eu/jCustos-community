/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.starter.ui;

import eu.jsentinel.jcustos.authorization.api.CurrentSubject;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.components.SecuredBindingRegistry;
import eu.jsentinel.jcustos.components.SecuredVisibilityMode;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.policy.api.Policy;
import eu.jsentinel.jcustos.policy.api.PolicyContext;
import eu.jsentinel.jcustos.policy.api.PolicyDecision;
import eu.jsentinel.jcustos.policy.spi.PolicyRegistry;
import com.vaadin.flow.component.Component;

import java.util.Optional;

/**
 * V00.73 policy-aware visibility helper for {@link SecuredUi}.
 *
 * <p>Adds an attach listener that resolves the current
 * {@link JCustosSubject}, builds a {@link PolicyContext}, and asks
 * the configured {@link PolicyRegistry} how to render the component.
 * The same instance is re-evaluated on every attach so navigation
 * between routes refreshes the decision (mirrors V00.71
 * {@code SecuredVisibility.apply(...)} semantics), and - since 00.84.00 -
 * whenever {@code SecuredVisibility.refreshAll(UI)} runs for its UI (R8,
 * JS-SEC-167).
 *
 * <p>Diagnostic logging differentiates the two denial paths
 * (Konzept §8.4):
 * <ul>
 *   <li>"no subject" — log INFO {@code secured-ui/no-subject}</li>
 *   <li>"policy denied" — log FINE {@code secured-ui/policy-denied}</li>
 *   <li>"unknown policy" — log WARNING {@code secured-ui/unknown-policy}</li>
 * </ul>
 *
 * @since 00.73.00
 */
final class PolicyVisibility {

  private PolicyVisibility() {
    throw new AssertionError("no instances");
  }

  /**
   * Wires {@code component} to evaluate {@code policyName} on attach.
   * Applies the chosen visibility {@code mode} on denied/missing.
   */
  static void install(Component component, String policyName, SecuredVisibilityMode mode) {
    component.addAttachListener(e -> applyOnce(component, policyName, mode));
    // Also evaluate immediately so tests that don't go through Vaadin's
    // attach lifecycle still see the initial verdict.
    applyOnce(component, policyName, mode);
    // R8 (JS-SEC-167): SecuredVisibility.refreshAll(UI) evaluates the policy again when the
    // subject's roles change while the view stays open.
    SecuredBindingRegistry.register(component, () -> applyOnce(component, policyName, mode));
  }

  /**
   * Evaluates {@code policyName} for the current subject, as {@link #install} does for the
   * visibility; used where an event has to be refused, not only a control hidden.
   *
   * @return {@code true} only when the policy allows the current subject
   */
  static boolean isAllowed(String policyName) {
    return evaluate(policyName) == Verdict.Allowed;
  }

  /** Evaluates {@code policyName} and applies the verdict to {@code component} according to {@code mode}. */
  static void applyOnce(Component component, String policyName, SecuredVisibilityMode mode) {
    Verdict v = evaluate(policyName);
    switch (v) {
      case Allowed -> show(component);
      case DeniedNoSubject -> {
        HasLogger.staticLogger().info(
            "secured-ui/no-subject: policy={} — no subject bound", policyName);
        denyVisible(component, mode);
      }
      case DeniedByPolicy -> {
        HasLogger.staticLogger().debug(
            "secured-ui/policy-denied: policy={}", policyName);
        denyVisible(component, mode);
      }
      case UnknownPolicy -> {
        HasLogger.staticLogger().warn(
            "secured-ui/unknown-policy: policy={} — PolicyRegistry has no entry", policyName);
        denyVisible(component, mode);
      }
      case StepUpRequired -> {
        HasLogger.staticLogger().debug(
            "secured-ui/step-up-required: policy={}", policyName);
        // Treat step-up like a denial at the UI layer; the route-level
        // @SecureRoute(policy=...) handles step-up navigation.
        denyVisible(component, mode);
      }
      default -> denyVisible(component, mode);
    }
  }

  private static Verdict evaluate(String policyName) {
    JCustosSubject subject = resolveSubject().orElse(null);
    if (subject == null) {
      return Verdict.DeniedNoSubject;
    }
    PolicyRegistry registry = JCustosServiceResolver.policyRegistry();
    Optional<Policy> known = registry.find(policyName);
    if (known.isEmpty()) {
      return Verdict.UnknownPolicy;
    }
    AccessContext ac = new AccessContext(
        Optional.of(subject),
        "ui-component",
        policyName,
        "evaluate",
        java.util.Map.of());
    PolicyContext pc = new PolicyContext(ac, policyName);
    PolicyDecision decision = registry.evaluate(policyName, pc);
    if (decision instanceof PolicyDecision.Allowed) {
      return Verdict.Allowed;
    }
    if (decision instanceof PolicyDecision.StepUpRequired) {
      return Verdict.StepUpRequired;
    }
    return Verdict.DeniedByPolicy;
  }

  /**
   * JS-SEC-097 (CWE-1041, CWE-532): the subject the policy sees comes from
   * {@link CurrentSubject#currentJCustosSubject()}. Its id is the registered
   * {@code SubjectIdResolver}'s value, otherwise the identity handle. Until 00.84.00 this
   * helper fell back to {@code String.valueOf(user)}, so without a resolver the subject's
   * {@code toString()} - an e-mail address, a password hash - reached every policy as
   * {@code subjectId} and {@code displayName}.
   */
  private static Optional<JCustosSubject> resolveSubject() {
    return CurrentSubject.currentJCustosSubject();
  }

  private static void show(Component c) {
    c.setVisible(true);
    if (c instanceof com.vaadin.flow.component.HasEnabled he) {
      he.setEnabled(true);
    }
  }

  private static void denyVisible(Component c, SecuredVisibilityMode mode) {
    if (mode == SecuredVisibilityMode.HIDE) {
      c.setVisible(false);
      return;
    }
    if (c instanceof com.vaadin.flow.component.HasEnabled he) {
      he.setEnabled(false);
    } else {
      c.setVisible(false);
    }
  }

  private enum Verdict {
    Allowed, DeniedNoSubject, DeniedByPolicy, UnknownPolicy, StepUpRequired
  }
}
