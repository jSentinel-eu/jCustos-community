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
package eu.jsentinel.jcustos.dx.rest.bootstrap;

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.permissions.HasPermissions;
import eu.jsentinel.jcustos.authorization.api.roles.HasRoles;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJCustosService;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import eu.jsentinel.jcustos.logout.SubjectClearingLogoutService;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code RestSecurity.bootstrap().install()} accepts authentication and authorisation
 * services, and the subject resolver, that are registered through
 * {@code META-INF/services} - the alternative its own findings name. Until 00.84.00 it read
 * the explicit calls only and reported such a registration as missing (ERROR), so a
 * {@code STRICT} bootstrap refused to start. The registration is real: a
 * {@code META-INF/services} directory on a context class loader, read by the same
 * {@code ServiceLoader} lookup the resolver uses at run time.
 */
@DisplayName("RestSecurity.bootstrap() - SPI-registered services are not reported as missing")
class RestBootstrapRegisteredServicesTest {

  @TempDir
  Path services;

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("registered through META-INF/services: no missing-* finding, the services are listed as spi-registered, STRICT starts")
  void registeredServices_areAccepted() throws IOException {
    register(Map.of(
        AuthenticationService.class, List.of(SpiAuthentication.class),
        AuthorizationService.class, List.of(SpiAuthorization.class),
        RestSubjectResolver.class, List.of(SpiResolver.class)));

    JCustosRuntime runtime = withRegistrations(() -> strictBootstrap().install());

    assertTrue(runtime.warnings().stream().noneMatch(w -> w.severity() == Severity.ERROR),
        "a registered service is not missing, got: " + runtime.warnings());
    assertListed(runtime, AuthenticationService.class, SpiAuthentication.class);
    assertListed(runtime, AuthorizationService.class, SpiAuthorization.class);
    assertListed(runtime, RestSubjectResolver.class, SpiResolver.class);
    // and it is the service the resolver hands out at run time
    assertEquals(SpiAuthentication.class, JCustosServiceResolver.authenticationService().getClass());
    assertEquals(SpiAuthorization.class, JCustosServiceResolver.authorizationService().getClass());
  }

  @Test
  @DisplayName("explicit calls still win over a registration and are listed as bootstrap-explicit")
  void explicitServices_winOverRegistration() throws IOException {
    register(Map.of(
        AuthenticationService.class, List.of(SpiAuthentication.class),
        AuthorizationService.class, List.of(SpiAuthorization.class)));
    AuthenticationService<String, String> explicitAuthn = FakeAuthenticationService.forType(String.class);
    AuthorizationService<String> explicitAuthz = new FakeAuthorizationService<>();

    JCustosRuntime runtime = withRegistrations(() -> strictBootstrap()
        .authentication(explicitAuthn)
        .authorization(explicitAuthz)
        .subjectResolver(new SpiResolver())
        .install());

    assertTrue(runtime.warnings().stream().noneMatch(w -> w.severity() == Severity.ERROR),
        runtime.warnings().toString());
    assertEquals("bootstrap-explicit", entry(runtime, AuthenticationService.class).source());
    assertEquals("bootstrap-explicit", entry(runtime, AuthorizationService.class).source());
    assertSame(explicitAuthn, JCustosServiceResolver.authenticationService());
    assertSame(explicitAuthz, JCustosServiceResolver.authorizationService());
  }

  @Test
  @DisplayName("neither explicit nor registered: missing-authentication-service, missing-authorization-service and missing-rest-subject-resolver stay ERRORs")
  void nothingConfigured_isStillMissing() {
    JCustosRuntime runtime = withRegistrations(() -> RestSecurity.bootstrap().install());

    assertEquals(Severity.ERROR, finding(runtime, "missing-authentication-service").severity());
    assertEquals(Severity.ERROR, finding(runtime, "missing-authorization-service").severity());
    assertEquals(Severity.ERROR, finding(runtime, "missing-rest-subject-resolver").severity());
  }

  @Test
  @DisplayName("several registered implementations are ambiguous (ERROR), not silently picked")
  void severalRegistrations_areAmbiguous() throws IOException {
    register(Map.of(
        AuthenticationService.class, List.of(SpiAuthentication.class, OtherSpiAuthentication.class),
        AuthorizationService.class, List.of(SpiAuthorization.class),
        RestSubjectResolver.class, List.of(SpiResolver.class, OtherSpiResolver.class)));

    JCustosRuntime runtime = withRegistrations(() -> RestSecurity.bootstrap().install());

    assertEquals(Severity.ERROR, finding(runtime, "ambiguous-authentication-service").severity());
    assertEquals(Severity.ERROR, finding(runtime, "ambiguous-rest-subject-resolver").severity());
    assertFalse(runtime.warnings().stream().anyMatch(w -> w.code().startsWith("missing-")),
        runtime.warnings().toString());
    assertListed(runtime, AuthorizationService.class, SpiAuthorization.class);
  }

  // ── helpers ──────────────────────────────────────────────────────

  private static RestJCustosBootstrap strictBootstrap() {
    return RestSecurity.bootstrap()
        .mode(JCustosBootstrapMode.STRICT)
        .denyByDefault(true)
        .audit(a -> a.logging())
        .logout(new SubjectClearingLogoutService<>(new InMemorySubjectStore(), String.class));
  }

  /** Writes one {@code META-INF/services} file per SPI into the temporary directory. */
  private void register(Map<Class<?>, List<Class<?>>> providers) throws IOException {
    Path dir = Files.createDirectories(services.resolve("META-INF/services"));
    for (Map.Entry<Class<?>, List<Class<?>>> entry : providers.entrySet()) {
      StringBuilder lines = new StringBuilder();
      for (Class<?> provider : entry.getValue()) {
        lines.append(provider.getName()).append('\n');
      }
      Files.writeString(dir.resolve(entry.getKey().getName()), lines);
    }
  }

  /** Runs {@code action} with the temporary directory on the thread's context class loader. */
  private <T> T withRegistrations(Supplier<T> action) {
    Thread thread = Thread.currentThread();
    ClassLoader previous = thread.getContextClassLoader();
    try (URLClassLoader loader = new URLClassLoader(
        new URL[] {services.toUri().toURL()}, RestBootstrapRegisteredServicesTest.class.getClassLoader())) {
      thread.setContextClassLoader(loader);
      return action.get();
    } catch (IOException e) {
      throw new AssertionError(e);
    } finally {
      thread.setContextClassLoader(previous);
    }
  }

  private static void assertListed(JCustosRuntime runtime, Class<?> spi, Class<?> impl) {
    RegisteredJCustosService entry = entry(runtime, spi);
    assertEquals(impl, entry.impl(), runtime.services().toString());
    assertEquals("spi-registered", entry.source());
    assertFalse(entry.defaulted());
  }

  private static RegisteredJCustosService entry(JCustosRuntime runtime, Class<?> spi) {
    return runtime.services().stream().filter(s -> s.spi() == spi).findFirst()
        .orElseThrow(() -> new AssertionError(spi.getSimpleName() + " not listed: " + runtime.services()));
  }

  private static JCustosBootstrapWarning finding(JCustosRuntime runtime, String code) {
    return runtime.warnings().stream().filter(w -> code.equals(w.code())).findFirst()
        .orElseThrow(() -> new AssertionError(code + " not reported: " + runtime.warnings()));
  }

  // ── providers, loaded by ServiceLoader through their public no-argument constructor ──

  /** Authentication service registered through {@code META-INF/services}. */
  public static class SpiAuthentication implements AuthenticationService<String, String> {
    @Override
    public boolean checkCredentials(String credentials) {
      return false;
    }

    @Override
    public String loadSubject(String credentials) {
      return credentials;
    }

    @Override
    public Class<String> subjectType() {
      return String.class;
    }
  }

  /** A second registration of the same SPI. */
  public static final class OtherSpiAuthentication extends SpiAuthentication {
  }

  /** Authorisation service registered through {@code META-INF/services}. */
  public static final class SpiAuthorization implements AuthorizationService<String> {
    @Override
    public HasRoles rolesFor(String subject) {
      return () -> List.of();
    }

    @Override
    public HasPermissions permissionsFor(String subject) {
      return () -> List.of();
    }
  }

  /** Subject resolver registered through {@code META-INF/services}. */
  public static class SpiResolver implements RestSubjectResolver {
    @Override
    public Optional<JCustosSubject> resolveSubject(RestRequest request) {
      return Optional.empty();
    }
  }

  /** A second registration of the resolver SPI. */
  public static final class OtherSpiResolver extends SpiResolver {
  }
}
