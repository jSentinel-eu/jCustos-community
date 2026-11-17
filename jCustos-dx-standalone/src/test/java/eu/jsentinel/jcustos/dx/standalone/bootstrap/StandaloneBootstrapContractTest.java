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

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.standalone.ThreadLocalSubjectStore;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contracts of the standalone bootstrap that the scenario tests leave open: the legacy
 * {@code loginAttemptPolicy(...)} entry point, the worker-side restore of the
 * thread-propagating executor, the process-global holders and the fluent sub-builders.
 * Real stores, real executors, real resolver; the holders are reset around every test.
 */
@DisplayName("StandaloneSecurity.bootstrap() - legacy entry point, propagation restore, holders, sub-builders")
class StandaloneBootstrapContractTest {

  private static final String UNBOUND = "<unbound>";

  @BeforeEach
  @AfterEach
  void resetGlobalState() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    StandaloneThreadPropagationContext.reset();
    StandaloneInteractiveLoginContext.reset();
  }

  // ── legacy loginAttemptPolicy(...) ───────────────────────────────

  @Test
  @DisplayName("the deprecated loginAttemptPolicy(...) wires the policy into the resolver and the runtime report")
  @SuppressWarnings("deprecation")
  void legacyLoginAttemptPolicy_isWiredLikeBruteForce() {
    InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy();

    JCustosRuntime runtime = StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .loginAttemptPolicy(policy)
        .install();

    assertSame(policy, JCustosServiceResolver.loginAttemptPolicy(),
        "install() must hand the policy of the legacy entry point to the resolver");
    assertTrue(runtime.services().stream()
            .anyMatch(s -> s.spi() == LoginAttemptPolicy.class
                && s.impl() == InMemoryLoginAttemptPolicy.class
                && "bootstrap-explicit".equals(s.source())
                && !s.defaulted()),
        "the runtime report must list the policy as bootstrap-explicit: " + runtime.services());
  }

  // ── thread propagation: worker-side restore ──────────────────────

  @Test
  @DisplayName("a worker that had its own subject gets it back after a propagated task")
  void inheritOnSubmit_restoresTheWorkersOwnBinding() throws Exception {
    installWithPropagation();
    SubjectStore store = SubjectStores.subjectStore();
    store.setCurrentSubject("submitter", String.class);

    ExecutorService pool = Executors.newSingleThreadExecutor();
    try {
      pool.submit(() -> SubjectStores.subjectStore().setCurrentSubject("worker-own", String.class))
          .get(2, TimeUnit.SECONDS);

      CompletableFuture<String> during = new CompletableFuture<>();
      StandaloneThreadPropagationContext.wrap(pool).execute(() -> during.complete(currentSubject()));
      assertEquals("submitter", during.get(2, TimeUnit.SECONDS),
          "the task must run with the submitter's subject");

      String after = pool.submit(StandaloneBootstrapContractTest::currentSubject)
          .get(2, TimeUnit.SECONDS);
      assertEquals("worker-own", after,
          "the worker's own binding must be restored, neither kept as the submitter's nor deleted");
    } finally {
      pool.shutdownNow();
      store.deleteCurrentSubject(String.class);
    }
  }

  @Test
  @DisplayName("a submitter without a subject still has its task run, and the worker stays unbound")
  void inheritOnSubmit_withoutSubject_stillRunsTheTask() throws Exception {
    installWithPropagation();
    SubjectStores.subjectStore().deleteCurrentSubject(String.class);

    ExecutorService pool = Executors.newSingleThreadExecutor();
    try {
      CompletableFuture<String> ran = new CompletableFuture<>();
      StandaloneThreadPropagationContext.wrap(pool).execute(() -> ran.complete(currentSubject()));
      assertEquals(UNBOUND, ran.get(2, TimeUnit.SECONDS),
          "the task must run, without a subject, when the submitter has none");
    } finally {
      pool.shutdownNow();
    }
  }

  // ── process-global holders ───────────────────────────────────────

  @Test
  @DisplayName("the propagation holder accepts an equal strategy again, refuses a different one and is cleared by reset()")
  void propagationHolder_isIdempotentForEqualAndRefusesDifferent() {
    ThreadPropagationStrategy inherit = new ThreadPropagationStrategy(ThreadPropagationMode.INHERIT_ON_SUBMIT);
    StandaloneThreadPropagationContext.publish(inherit);
    StandaloneThreadPropagationContext.publish(
        new ThreadPropagationStrategy(ThreadPropagationMode.INHERIT_ON_SUBMIT));

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> StandaloneThreadPropagationContext.publish(
            new ThreadPropagationStrategy(ThreadPropagationMode.NONE)));
    assertTrue(refused.getMessage().contains("process-global"), refused.getMessage());
    assertEquals(ThreadPropagationMode.INHERIT_ON_SUBMIT,
        StandaloneThreadPropagationContext.strategy().orElseThrow().mode(),
        "a refused publish must not replace the active strategy");

    StandaloneThreadPropagationContext.reset();
    assertTrue(StandaloneThreadPropagationContext.strategy().isEmpty());
  }

  @Test
  @DisplayName("the interactive-login holder accepts an equal configuration again, refuses a different one and is cleared by reset()")
  void interactiveLoginHolder_isIdempotentForEqualAndRefusesDifferent() {
    InteractiveLoginPrompt prompt = message -> new InteractiveLoginPrompt.Credentials(
        "alice", new char[]{'s', 'e', 'c'});
    StandaloneInteractiveLoginContext.publish(new InteractiveLoginConfiguration(prompt, 3));
    StandaloneInteractiveLoginContext.publish(new InteractiveLoginConfiguration(prompt, 3));

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> StandaloneInteractiveLoginContext.publish(new InteractiveLoginConfiguration(prompt, 5)));
    assertTrue(refused.getMessage().contains("process-global"), refused.getMessage());
    assertEquals(3, StandaloneInteractiveLoginContext.configuration().orElseThrow().maxAttempts(),
        "a refused publish must not replace the active configuration");

    StandaloneInteractiveLoginContext.reset();
    assertTrue(StandaloneInteractiveLoginContext.configuration().isEmpty(),
        "reset() must clear the holder");
  }

  // ── fluent sub-builders ──────────────────────────────────────────

  @Test
  @DisplayName("ThreadPropagationBuilder: NONE by default, every setter returns the builder and sets its mode")
  void threadPropagationBuilder_isFluentAndSetsTheMode() {
    ThreadPropagationBuilder builder = new ThreadPropagationBuilder();
    assertEquals(ThreadPropagationMode.NONE, builder.toStrategy().mode());

    assertSame(builder, builder.inheritOnSubmit());
    assertEquals(ThreadPropagationMode.INHERIT_ON_SUBMIT, builder.toStrategy().mode());
    assertSame(builder, builder.none());
    assertEquals(ThreadPropagationMode.NONE, builder.toStrategy().mode());
    assertSame(builder, builder.mode(ThreadPropagationMode.INHERIT_ON_SUBMIT));
    assertEquals(ThreadPropagationMode.INHERIT_ON_SUBMIT, builder.toStrategy().mode());
    assertThrows(NullPointerException.class, () -> builder.mode(null));
  }

  @Test
  @DisplayName("InteractiveLoginBuilder: 0 attempts (unlimited) is accepted and every setter returns the builder")
  void interactiveLoginBuilder_acceptsZeroAndIsFluent() {
    InteractiveLoginPrompt prompt = message -> new InteractiveLoginPrompt.Credentials(
        "bob", new char[]{'p', 'w'});
    InteractiveLoginBuilder builder = new InteractiveLoginBuilder();

    assertSame(builder, builder.maxAttempts(0), "maxAttempts(0) means unlimited and is valid");
    assertSame(builder, builder.prompt(prompt));
    InteractiveLoginConfiguration configuration = builder.toConfiguration();
    assertEquals(0, configuration.maxAttempts());
    assertSame(prompt, configuration.prompt());
  }

  // ── helpers ──────────────────────────────────────────────────────

  /** Installs with per-thread subjects (the SPI default store) and inherit-on-submit. */
  private static void installWithPropagation() {
    StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectStore(new ThreadLocalSubjectStore())
        .threadPropagation(t -> t.inheritOnSubmit())
        .install();
  }

  private static String currentSubject() {
    return SubjectStores.findSubjectStore()
        .flatMap(s -> s.currentSubject(String.class))
        .orElse(UNBOUND);
  }
}
