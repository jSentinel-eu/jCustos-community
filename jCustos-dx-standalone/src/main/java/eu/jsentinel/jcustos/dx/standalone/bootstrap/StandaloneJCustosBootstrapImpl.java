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
package eu.jsentinel.jcustos.dx.standalone.bootstrap;

import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.dx.bootstrap.JCustosBootstrapException;
import eu.jsentinel.jcustos.dx.internal.AbstractJCustosBootstrap;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJCustosService;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.standalone.ThreadLocalSubjectStore;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Package-private implementation of {@link StandaloneJCustosBootstrap}.
 *
 * @since 00.72.00
 */
final class StandaloneJCustosBootstrapImpl
    extends AbstractJCustosBootstrap<StandaloneJCustosBootstrap>
    implements StandaloneJCustosBootstrap {

  private SubjectStore subjectStore;
  private ThreadPropagationStrategy threadPropagation;
  private InteractiveLoginConfiguration interactiveLogin;
  private boolean installed;

  @Override
  public StandaloneJCustosBootstrap subjectStore(SubjectStore store) {
    this.subjectStore = Objects.requireNonNull(store, "store");
    return this;
  }

  /**
   * Legacy V00.73 entry point — kept for source-backwards-compat.
   * Delegates to {@link #bruteForce(LoginAttemptPolicy)} introduced
   * in V00.74 on {@code CommonJCustosBootstrap}.
   *
   * @param policy non-null login-attempt policy
   * @return this builder
   * @deprecated since 00.74.00 — use {@link #bruteForce(LoginAttemptPolicy)}
   *             instead. Both methods point at the same wiring.
   */
  @Deprecated(since = "00.74.00")
  @Override
  public StandaloneJCustosBootstrap loginAttemptPolicy(LoginAttemptPolicy policy) {
    return bruteForce(policy);
  }

  @Override
  public StandaloneJCustosBootstrap threadPropagation(
      Consumer<ThreadPropagationBuilder> consumer) {
    Objects.requireNonNull(consumer, "consumer");
    ThreadPropagationBuilder builder = new ThreadPropagationBuilder();
    consumer.accept(builder);
    this.threadPropagation = builder.toStrategy();
    return this;
  }

  @Override
  public StandaloneJCustosBootstrap interactiveLogin(
      Consumer<InteractiveLoginBuilder> consumer) {
    Objects.requireNonNull(consumer, "consumer");
    InteractiveLoginBuilder builder = new InteractiveLoginBuilder();
    consumer.accept(builder);
    this.interactiveLogin = builder.toConfiguration();
    return this;
  }

  @Override
  public JCustosRuntime install() {
    if (installed) {
      throw new IllegalStateException("install() may only be called once on the same builder");
    }
    installed = true;

    List<RegisteredJCustosService> services = new ArrayList<>();
    List<JCustosBootstrapWarning> warnings = new ArrayList<>();

    // The explicit service wins; otherwise the one registered through META-INF/services, as
    // the resolver finds it at run time (StandaloneLoginFlow's default constructor does).
    applyAuthenticationAndAuthorization("StandaloneSecurity.bootstrap()", services, warnings);

    SubjectStore effectiveSubjectStore = subjectStore;
    boolean subjectStoreDefaulted = false;
    if (effectiveSubjectStore != null) {
      // R008: actually wire the caller-provided store. Previously it was only
      // added to the runtime report while the resolver kept returning the SPI
      // default (ThreadLocalSubjectStore) — a cross-adapter asymmetry vs Vaadin,
      // which does call SubjectStores.setSubjectStore(...). Caller wins.
      SubjectStores.setSubjectStore(effectiveSubjectStore);
    } else {
      // No explicit store: fall back to the SPI-registered default
      // (ThreadLocalSubjectStore ships in jCustos-standalone). Mirrors
      // Vaadin's caller-wins-else-default — we do not override an existing
      // registration when the caller supplied nothing.
      effectiveSubjectStore = new ThreadLocalSubjectStore();
      subjectStoreDefaulted = true;
    }
    services.add(new RegisteredJCustosService(
        SubjectStore.class,
        effectiveSubjectStore.getClass(),
        subjectStoreDefaulted ? "bootstrap-default" : "bootstrap-explicit",
        subjectStoreDefaulted));

    // V00.74: apply direct-set services from CommonJCustosBootstrap
    // (logout / bruteForce / rateLimit / apiKeys / refreshTokens).
    // The legacy .loginAttemptPolicy(...) builder method on
    // StandaloneJCustosBootstrap delegates to .bruteForce(...).
    // R05-Rest (V00.76.10): the shared per-concern sub-builder consumption is
    // hoisted into the base. Standalone symmetry is preserved inside the applyX
    // methods (e.g. sessions emit standalone/sessions-not-applicable INFO).
    applyCommonConfiguration(AdapterKind.STANDALONE, services, warnings);

    // V00.74 (A2.3): publish thread-propagation strategy.
    if (threadPropagation != null) {
      StandaloneThreadPropagationContext.publish(threadPropagation);
      services.add(new RegisteredJCustosService(
          StandaloneThreadPropagationContext.class,
          ThreadPropagationStrategy.class,
          "bootstrap-thread-propagation=" + threadPropagation.mode(),
          false));
    }
    // V00.74 (A2.3): publish interactive-login configuration.
    if (interactiveLogin != null) {
      StandaloneInteractiveLoginContext.publish(interactiveLogin);
      services.add(new RegisteredJCustosService(
          StandaloneInteractiveLoginContext.class,
          InteractiveLoginConfiguration.class,
          "bootstrap-interactive-login", false));
    }

    JCustosBootstrapMode mode = state.mode();
    if (mode == JCustosBootstrapMode.STRICT && warningsContainError(warnings)) {
      throw new JCustosBootstrapException(warnings);
    }

    return new JCustosRuntime(services, warnings, mode);
  }
}
