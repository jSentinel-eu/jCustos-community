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
package eu.jsentinel.jcustos.dx.vaadin.bootstrap;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.dx.bootstrap.JCustosBootstrapException;
import eu.jsentinel.jcustos.dx.diagnostics.DiagnosticReportBuilder;
import eu.jsentinel.jcustos.dx.diagnostics.DiscoveredService;
import eu.jsentinel.jcustos.dx.diagnostics.DuplicateService;
import eu.jsentinel.jcustos.dx.diagnostics.MissingRecommendedService;
import eu.jsentinel.jcustos.dx.diagnostics.ServiceWarning;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import eu.jsentinel.jcustos.dx.vaadin.diagnostics.VaadinDiagnosticContributor;
import eu.jsentinel.jcustos.dx.vaadin.routes.SecureRouteDiscovery;
import eu.jsentinel.jcustos.logout.SubjectClearingLogoutService;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-097 (CWE-778, CWE-1041), decision F06: without a {@link SubjectIdResolver} every
 * subject id of the Vaadin stack is the identity handle. The bootstrap reports
 * {@code audit/no-subject-id-resolver} - a WARNING, an ERROR in STRICT, so a STRICT
 * application without a resolver does not boot - and {@code JCustosDiagnostics.inspect()}
 * lists it through the Vaadin contributor.
 * <p>
 * The bootstrap is otherwise complete, so the finding stands alone.
 */
@DisplayName("JS-SEC-097 - audit/no-subject-id-resolver: WARNING, ERROR in STRICT")
class NoSubjectIdResolverFindingTest {

  @TempDir
  Path services;

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
  }

  @ParameterizedTest(name = "{0}")
  @EnumSource(value = JCustosBootstrapMode.class, names = {"STRICT"}, mode = EnumSource.Mode.EXCLUDE)
  @DisplayName("no resolver outside STRICT: WARNING, the bootstrap installs")
  void noResolver_warning(JCustosBootstrapMode mode) {
    Outcome outcome = install(mode, b -> { });

    assertFalse(outcome.threw(), mode + " must install; got " + outcome.warnings());
    assertEquals(Optional.of(Severity.WARNING), outcome.severityOf(VaadinDiagnosticContributor.NO_SUBJECT_ID_RESOLVER));
    assertTrue(outcome.messageOf(VaadinDiagnosticContributor.NO_SUBJECT_ID_RESOLVER).contains("identity handle"));
  }

  @Test
  @DisplayName("no resolver in STRICT: ERROR - the finding alone fails the boot")
  void noResolver_strict_failsTheBoot() {
    Outcome withResolver = install(JCustosBootstrapMode.STRICT,
        b -> b.sessions(s -> s.subjectIdResolver(subject -> SubjectId.of("user-7"))));
    assertFalse(withResolver.threw(), "precondition: this configuration boots in STRICT; got "
        + withResolver.warnings());
    assertTrue(withResolver.severityOf(VaadinDiagnosticContributor.NO_SUBJECT_ID_RESOLVER).isEmpty());

    JCustosServiceResolver.resetAll(); // the first install registered its resolver JVM-wide
    Outcome without = install(JCustosBootstrapMode.STRICT, b -> { });

    assertTrue(without.threw(), "STRICT must refuse to boot without a SubjectIdResolver");
    assertEquals(List.of(VaadinDiagnosticContributor.NO_SUBJECT_ID_RESOLVER), without.errorCodes(),
        "the missing resolver is the only error");
  }

  @Test
  @DisplayName("a resolver registered programmatically satisfies the check in STRICT")
  void programmaticResolver_noFinding() {
    JCustosServiceResolver.<String>setSubjectIdResolver(subject -> SubjectId.of("user-7"));

    Outcome outcome = install(JCustosBootstrapMode.STRICT, b -> { });

    assertFalse(outcome.threw(), outcome.warnings().toString());
    assertTrue(outcome.severityOf(VaadinDiagnosticContributor.NO_SUBJECT_ID_RESOLVER).isEmpty());
  }

  @Test
  @DisplayName("a resolver registered through META-INF/services satisfies the check; two registrations do not")
  void spiRegistration() throws IOException {
    register(StringIdResolver.class);
    Outcome one = withRegistrations(() -> install(JCustosBootstrapMode.STRICT, b -> { }));
    assertFalse(one.threw(), one.warnings().toString());
    assertTrue(one.severityOf(VaadinDiagnosticContributor.NO_SUBJECT_ID_RESOLVER).isEmpty());

    JCustosServiceResolver.resetAll();
    register(StringIdResolver.class, OtherStringIdResolver.class);
    Outcome two = withRegistrations(() -> install(JCustosBootstrapMode.STRICT, b -> { }));
    assertTrue(two.threw(), "an ambiguous registration resolves to no resolver at run time");
    assertEquals(List.of(VaadinDiagnosticContributor.NO_SUBJECT_ID_RESOLVER), two.errorCodes());
    assertTrue(two.messageOf(VaadinDiagnosticContributor.NO_SUBJECT_ID_RESOLVER)
        .startsWith("No SubjectIdResolver can be resolved"));
  }

  @Test
  @DisplayName("JCustosDiagnostics.inspect(): the Vaadin contributor lists the finding without a resolver only")
  void contributor() {
    assertTrue(contribute().stream()
        .anyMatch(w -> VaadinDiagnosticContributor.NO_SUBJECT_ID_RESOLVER.equals(w.code())));

    JCustosServiceResolver.<String>setSubjectIdResolver(subject -> SubjectId.of("user-7"));

    assertTrue(contribute().stream()
        .noneMatch(w -> VaadinDiagnosticContributor.NO_SUBJECT_ID_RESOLVER.equals(w.code())));
  }

  // ── helpers ────────────────────────────────────────────────────

  private record Outcome(List<JCustosBootstrapWarning> warnings, boolean threw) {
    Optional<Severity> severityOf(String code) {
      return warnings.stream().filter(w -> code.equals(w.code()))
          .map(JCustosBootstrapWarning::severity).findFirst();
    }

    String messageOf(String code) {
      return warnings.stream().filter(w -> code.equals(w.code()))
          .map(JCustosBootstrapWarning::message).findFirst().orElse("");
    }

    List<String> errorCodes() {
      return warnings.stream().filter(w -> w.severity() == Severity.ERROR)
          .map(JCustosBootstrapWarning::code).toList();
    }
  }

  /** A bootstrap that is complete apart from the subject id resolver. */
  private static Outcome install(JCustosBootstrapMode mode, Consumer<VaadinJCustosBootstrap> extra) {
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    VaadinJCustosBootstrap bootstrap = VaadinSecurity.bootstrap()
        .mode(mode)
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .audit(a -> a.logging())
        .logout(new SubjectClearingLogoutService<>(new InMemorySubjectStore(), String.class))
        .denyByDefault(true)
        .discoverSecureRoutes(new NoRoutesDiscovery());
    extra.accept(bootstrap);
    try {
      return new Outcome(bootstrap.install().warnings(), false);
    } catch (JCustosBootstrapException strict) {
      return new Outcome(strict.warnings(), true);
    }
  }

  private static List<ServiceWarning> contribute() {
    Recorder recorder = new Recorder();
    new VaadinDiagnosticContributor().contribute(recorder);
    return recorder.warnings;
  }

  /** Writes the {@code META-INF/services} file of {@link SubjectIdResolver}. */
  private void register(Class<?>... providers) throws IOException {
    Path dir = Files.createDirectories(services.resolve("META-INF/services"));
    StringBuilder lines = new StringBuilder();
    for (Class<?> provider : providers) {
      lines.append(provider.getName()).append('\n');
    }
    Files.writeString(dir.resolve(SubjectIdResolver.class.getName()), lines);
  }

  /** Runs {@code action} with the temporary directory on the thread's context class loader. */
  private <T> T withRegistrations(Supplier<T> action) {
    Thread thread = Thread.currentThread();
    ClassLoader previous = thread.getContextClassLoader();
    try (URLClassLoader loader = new URLClassLoader(
        new URL[] {services.toUri().toURL()}, NoSubjectIdResolverFindingTest.class.getClassLoader())) {
      thread.setContextClassLoader(loader);
      return action.get();
    } catch (IOException e) {
      throw new AssertionError(e);
    } finally {
      thread.setContextClassLoader(previous);
    }
  }

  /** A discovery without findings - keeps the deny-by-default cross-check out of the picture. */
  private static final class NoRoutesDiscovery implements SecureRouteDiscovery {
    @Override
    public Stream<String> discoverPolicyNames() {
      return Stream.empty();
    }
  }

  private static final class Recorder implements DiagnosticReportBuilder {
    final List<ServiceWarning> warnings = new ArrayList<>();

    @Override
    public DiagnosticReportBuilder addDiscovered(DiscoveredService entry) {
      return this;
    }

    @Override
    public DiagnosticReportBuilder addMissing(MissingRecommendedService entry) {
      return this;
    }

    @Override
    public DiagnosticReportBuilder addDuplicate(DuplicateService entry) {
      return this;
    }

    @Override
    public DiagnosticReportBuilder addWarning(ServiceWarning warning) {
      warnings.add(warning);
      return this;
    }
  }

  // ── providers, loaded by ServiceLoader through their public no-argument constructor ──

  /** Subject id resolver registered through {@code META-INF/services}. */
  public static class StringIdResolver implements SubjectIdResolver<String> {
    @Override
    public SubjectId resolve(String subject) {
      return SubjectId.of("id-" + subject.length());
    }
  }

  /** A second registration of the same SPI. */
  public static final class OtherStringIdResolver extends StringIdResolver {
  }
}
