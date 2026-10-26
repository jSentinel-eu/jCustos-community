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

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJCustosService;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.standalone.ThreadLocalSubjectStore;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StandaloneJCustosBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JCustosServiceResolver.setAuthenticationService((AuthenticationService<?, ?>) null);
    JCustosServiceResolver.setAuthorizationService((AuthorizationService<?>) null);
    JCustosServiceResolver.setLoginAttemptPolicy(null);
    // R008 wires SubjectStores; clear the cached override so each test starts
    // from the SPI default and overrides don't leak between tests.
    SubjectStores.reset();
  }

  @Test
  void defaultSubjectStoreIsThreadLocal() {
    JCustosRuntime runtime = StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .install();

    RegisteredJCustosService storeEntry = runtime.services().stream()
        .filter(s -> s.spi() == SubjectStore.class)
        .findFirst().orElseThrow();
    assertEquals(ThreadLocalSubjectStore.class, storeEntry.impl());
    assertTrue(storeEntry.defaulted(), "default ThreadLocalSubjectStore must be flagged defaulted=true");
    assertEquals("bootstrap-default", storeEntry.source());
  }

  @Test
  void customSubjectStoreOverridesDefault() {
    InMemorySubjectStore customStore = new InMemorySubjectStore();
    JCustosRuntime runtime = StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectStore(customStore)
        .install();

    RegisteredJCustosService storeEntry = runtime.services().stream()
        .filter(s -> s.spi() == SubjectStore.class)
        .findFirst().orElseThrow();
    assertEquals(InMemorySubjectStore.class, storeEntry.impl());
    assertFalse(storeEntry.defaulted());
    assertEquals("bootstrap-explicit", storeEntry.source());
  }

  @Test
  void customSubjectStoreIsTheStoreTheResolverReturns() {
    // R008: the bug was that the custom store was reported but never wired,
    // so SubjectStores kept returning the SPI default ThreadLocalSubjectStore.
    InMemorySubjectStore customStore = new InMemorySubjectStore();
    StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectStore(customStore)
        .install();

    assertSame(customStore, SubjectStores.subjectStore(),
        "the custom store must be the one the resolver returns after install()");
  }

  @Test
  void defaultSubjectStoreResolvesToTheSpiThreadLocal() {
    // No explicit store: the resolver must fall back to the SPI default, not
    // a leaked override (caller-wins-else-default).
    StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .install();

    assertEquals(ThreadLocalSubjectStore.class, SubjectStores.subjectStore().getClass(),
        "without an explicit store the resolver must return the SPI ThreadLocalSubjectStore");
  }

  @Test
  void warningsEmptyOnHappyPath() {
    JCustosRuntime runtime = StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .audit(a -> a.logging()) // JS-SEC-080: without an audit trail the bootstrap now reports audit/noop-fallback
        .install();

    assertNotNull(runtime);
    assertTrue(runtime.warnings().isEmpty());
  }

  // ── V00.74 A2.3 threadPropagation / interactiveLogin ───────────

  @Test
  void threadPropagation_publishesStrategyAndRuntimeEntry() {
    StandaloneThreadPropagationContext.reset();
    JCustosRuntime runtime = StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .threadPropagation(t -> t.inheritOnSubmit())
        .install();

    ThreadPropagationStrategy s = StandaloneThreadPropagationContext.strategy().orElseThrow();
    assertEquals(ThreadPropagationMode.INHERIT_ON_SUBMIT, s.mode());
    assertTrue(runtime.services().stream()
        .anyMatch(r -> StandaloneThreadPropagationContext.class.equals(r.spi())
            && ThreadPropagationStrategy.class.equals(r.impl())
            && r.source().startsWith("bootstrap-thread-propagation=INHERIT_ON_SUBMIT")));
  }

  @Test
  void threadPropagation_inheritOnSubmit_bindsSubjectOnWorker() throws Exception {
    StandaloneThreadPropagationContext.reset();
    StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectStore(new InMemorySubjectStore())
        .threadPropagation(t -> t.inheritOnSubmit())
        .install();

    // R13: bind the subject under the application's subject type (String here),
    // exactly the way StandaloneLoginFlow#login does — NOT under
    // JCustosSubject.class. Before the fix the propagation captured under
    // JCustosSubject.class and so missed real logins, leaving the worker
    // unbound ("<unbound>") even though the feature looked wired.
    SubjectStores.subjectStore().setCurrentSubject("alice", String.class);

    var pool = java.util.concurrent.Executors.newSingleThreadExecutor();
    try {
      java.util.concurrent.Executor wrapped = StandaloneThreadPropagationContext.wrap(pool);
      java.util.concurrent.CompletableFuture<String> observed = new java.util.concurrent.CompletableFuture<>();
      wrapped.execute(() -> observed.complete(
          SubjectStores.findSubjectStore()
              .flatMap(st -> st.currentSubject(String.class))
              .orElse("<unbound>")));
      assertEquals("alice", observed.get(2, java.util.concurrent.TimeUnit.SECONDS),
          "the worker must see the subject bound under the application subject type");
    } finally {
      pool.shutdownNow();
      SubjectStores.subjectStore().deleteCurrentSubject(String.class);
    }
  }

  @Test
  void threadPropagation_inheritOnSubmit_restoresWorkerPriorBinding() throws Exception {
    // A worker with no prior binding must be left clean (deleteCurrentSubject)
    // after a propagated task. This requires per-thread semantics, so use the
    // real ThreadLocalSubjectStore (the SPI default) — not the shared
    // InMemorySubjectStore, where every thread sees the same binding.
    StandaloneThreadPropagationContext.reset();
    StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectStore(new ThreadLocalSubjectStore())
        .threadPropagation(t -> t.inheritOnSubmit())
        .install();
    SubjectStores.subjectStore().setCurrentSubject("submitter", String.class);

    var pool = java.util.concurrent.Executors.newSingleThreadExecutor();
    try {
      java.util.concurrent.Executor wrapped = StandaloneThreadPropagationContext.wrap(pool);
      // run once so the single worker thread has executed a propagated task
      java.util.concurrent.CompletableFuture<String> first = new java.util.concurrent.CompletableFuture<>();
      wrapped.execute(() -> first.complete(
          SubjectStores.findSubjectStore().flatMap(st -> st.currentSubject(String.class)).orElse("<unbound>")));
      assertEquals("submitter", first.get(2, java.util.concurrent.TimeUnit.SECONDS));
      // the worker thread must be clean again (no prior binding -> deleted)
      java.util.concurrent.CompletableFuture<String> after = new java.util.concurrent.CompletableFuture<>();
      pool.execute(() -> after.complete(
          SubjectStores.findSubjectStore().flatMap(st -> st.currentSubject(String.class)).orElse("<clean>")));
      assertEquals("<clean>", after.get(2, java.util.concurrent.TimeUnit.SECONDS),
          "the worker's binding must be cleared after a propagated task with no prior binding");
    } finally {
      pool.shutdownNow();
      SubjectStores.subjectStore().deleteCurrentSubject(String.class);
    }
  }

  @Test
  void threadPropagation_default_passthrough() {
    StandaloneThreadPropagationContext.reset();
    java.util.concurrent.Executor pool = java.util.concurrent.Executors.newSingleThreadExecutor();
    java.util.concurrent.Executor wrapped = StandaloneThreadPropagationContext.wrap(pool);
    assertEquals(pool, wrapped, "without published strategy, wrap() must be a pass-through");
  }

  @Test
  void interactiveLogin_publishesConfigurationAndRuntimeEntry() {
    StandaloneInteractiveLoginContext.reset();
    InteractiveLoginPrompt prompt = msg -> new InteractiveLoginPrompt.Credentials(
        "alice", new char[]{'s', 'e', 'c'});
    JCustosRuntime runtime = StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .interactiveLogin(l -> l.prompt(prompt).maxAttempts(3))
        .install();

    InteractiveLoginConfiguration cfg = StandaloneInteractiveLoginContext.configuration().orElseThrow();
    assertEquals(prompt, cfg.prompt());
    assertEquals(3, cfg.maxAttempts());
    assertTrue(runtime.services().stream()
        .anyMatch(r -> StandaloneInteractiveLoginContext.class.equals(r.spi())
            && InteractiveLoginConfiguration.class.equals(r.impl())));
  }

  @Test
  void interactiveLogin_missingPromptRejected() {
    org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
        () -> StandaloneSecurity.bootstrap()
            .authentication(FakeAuthenticationService.forType(String.class))
            .authorization(new FakeAuthorizationService<String>())
            .interactiveLogin(l -> l.maxAttempts(2))
            .install());
  }

  @Test
  void interactiveLogin_negativeMaxAttemptsRejected() {
    org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
        () -> StandaloneSecurity.bootstrap().interactiveLogin(l -> l.maxAttempts(-1)));
  }

  // ── V00.74.20 P015 mutation-lift: assert resolver state after install() ────

  @Test
  void install_publishesAuthnAuthzToServiceResolver() {
    AuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    AuthorizationService<String> authz = new FakeAuthorizationService<>();

    JCustosRuntime runtime = StandaloneSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .install();

    assertNotNull(runtime);
    // Kills the VoidMethodCallMutator that drops the
    // JCustosServiceResolver.setAuthenticationService(...) call inside
    // StandaloneJCustosBootstrapImpl.install() — if the call is gone,
    // the global resolver returns its empty default and these
    // assertions fail.
    assertEquals(authn, JCustosServiceResolver.authenticationService(),
        "install() must publish the AuthenticationService to JCustosServiceResolver");
    assertEquals(authz, JCustosServiceResolver.authorizationService(),
        "install() must publish the AuthorizationService to JCustosServiceResolver");
  }
}
