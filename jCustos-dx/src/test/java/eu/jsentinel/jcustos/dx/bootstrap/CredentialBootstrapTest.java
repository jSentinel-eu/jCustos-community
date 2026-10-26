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
package eu.jsentinel.jcustos.dx.bootstrap;

import eu.jsentinel.jcustos.authentication.PasswordHasher;
import eu.jsentinel.jcustos.authentication.Pbkdf2PasswordHasher;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.dx.internal.AbstractJCustosBootstrap;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJCustosService;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("CredentialBootstrap real surface (V00.73)")
class CredentialBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName(".passwordHasher(...) registers via legacy resolver setter")
  void passwordHasherWiresLegacyResolver() {
    // JCustosServiceResolver.findPasswordHashingService() treats
    // Pbkdf2PasswordHasher as the default fallback and returns empty.
    // Use a non-PBKDF2 stub to verify the registration.
    PasswordHasher hasher = new RecordingPasswordHasher();
    JCustosRuntime runtime = new TestBootstrap()
        .credentials(c -> c.passwordHasher(hasher))
        .install();
    assertSame(hasher, JCustosServiceResolver.findPasswordHashingService().orElseThrow());
    assertTrue(runtime.services().stream()
        .anyMatch(s -> PasswordHasher.class.equals(s.spi())));
  }

  /** Non-Pbkdf2 PasswordHasher so findPasswordHashingService returns it. */
  private static final class RecordingPasswordHasher implements PasswordHasher {
    @Override public String hash(char[] password) { return "stub:" + new String(password); }
    @Override public boolean verify(char[] password, String hashed) {
      return hashed != null && hashed.equals("stub:" + new String(password));
    }
  }

  @Test
  @DisplayName(".hashing(...) is wired through the credential-pipeline resolver slot, never the legacy setter (JS-SEC-073)")
  void hashingServiceWiredThroughPipelineSlot() {
    PasswordHashingService pipeline = PasswordHashingServices.defaults();
    JCustosRuntime runtime = new TestBootstrap()
        .credentials(c -> c.hashing(pipeline))
        .install();
    assertTrue(runtime.services().stream()
        .anyMatch(s -> PasswordHashingService.class.equals(s.spi())));
    assertSame(pipeline, JCustosServiceResolver.findCredentialHashingService().orElseThrow(),
        ".hashing(...) must be what credentialHashingService() resolves");
    assertSame(pipeline, JCustosServiceResolver.credentialHashingService());
    assertFalse(JCustosServiceResolver.findPasswordHashingService().isPresent(),
        "V00.71 PasswordHashingService must never be stuffed into the legacy PasswordHasher setter");
  }

  @Test
  @DisplayName(".pbkdf2Defaults() sets BOTH the legacy hasher and the V00.71 pipeline")
  void pbkdf2DefaultsSetsBothWorlds() {
    JCustosRuntime runtime = new TestBootstrap()
        .credentials(c -> c.pbkdf2Defaults())
        .install();
    // findPasswordHashingService() returns empty for Pbkdf2 (treated as
    // default fallback) — verify legacy entry through runtime.services()
    // and pipeline entry the same way.
    assertTrue(runtime.services().stream()
        .anyMatch(s -> PasswordHasher.class.equals(s.spi())
            && Pbkdf2PasswordHasher.class.equals(s.impl())));
    assertTrue(runtime.services().stream()
        .anyMatch(s -> PasswordHashingService.class.equals(s.spi())));
    assertTrue(JCustosServiceResolver.findCredentialHashingService().isPresent(),
        ".pbkdf2Defaults() must wire the pipeline slot as well (JS-SEC-073)");
  }

  @Test
  @DisplayName("JS-SEC-073 acceptance: .modern() in STRICT wires an Argon2id pipeline — a fresh hash carries argon2id")
  void modernInStrictWiresArgon2id() {
    JCustosRuntime runtime = new TestBootstrap()
        .credentials(c -> c.modern())
        .mode(JCustosBootstrapMode.STRICT)
        .install();
    assertTrue(runtime.services().stream()
        .anyMatch(s -> PasswordHashingService.class.equals(s.spi())),
        "modern() should register a PasswordHashingService");
    PasswordHashingService wired = JCustosServiceResolver.findCredentialHashingService().orElseThrow(
        () -> new AssertionError(".modern() must be wired into credentialHashingService()"));
    var result = wired.hash("correct horse battery staple".toCharArray());
    assertEquals("Argon2id", result.algorithm(), "the wired pipeline must hash with Argon2id");
    assertEquals("argon2id-bc", result.providerId());
    assertTrue(result.encodedHash().toLowerCase().contains("argon2id"),
        "the encoded hash must name argon2id; got: " + result.encodedHash());
    assertSame(wired, JCustosServiceResolver.credentialHashingService());
  }

  @Test
  @DisplayName(".credentialStore(...) without .hashing(...) does not trigger missing-hashing; it is recorded-not-wired (JS-SEC-073)")
  void credentialStoreAloneIsRecordedNotWired() {
    JCustosRuntime runtime = new TestBootstrap()
        .credentials(c -> c.credentialStore(
            new eu.jsentinel.jcustos.credential.store.InMemoryCredentialStore()))
        .install();
    assertFalse(runtime.warnings().stream()
        .anyMatch(w -> "credentials/missing-hashing".equals(w.code())),
        ".credentialStore() alone must not trigger missing-hashing");
    assertFalse(runtime.services().stream()
        .anyMatch(s -> eu.jsentinel.jcustos.credential.store.CredentialStore.class.equals(s.spi())),
        "an unwired entry must not masquerade as a registered service");
    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "dx/credential-store-recorded-not-wired".equals(w.code())
            && w.severity() == Severity.WARNING),
        "an unwired entry must surface as an explicit WARNING");
  }

  @Test
  @DisplayName("JS-SEC-073: recorded-not-wired pipeline entries are a boot failure in STRICT")
  void recordedNotWiredEntriesFailStrict() {
    PasswordHashingService pipeline = PasswordHashingServices.defaults();
    assertThrows(JCustosBootstrapException.class, () -> new TestBootstrap()
        .credentials(c -> c.hashing(pipeline)
            .pepper(eu.jsentinel.jcustos.credential.password.pepper.NoOpPepperService.INSTANCE))
        .mode(JCustosBootstrapMode.STRICT)
        .install());
    JCustosServiceResolver.resetAll();
    JCustosRuntime lenient = new TestBootstrap()
        .credentials(c -> c.hashing(pipeline)
            .pepper(eu.jsentinel.jcustos.credential.password.pepper.NoOpPepperService.INSTANCE))
        .install();
    assertTrue(lenient.warnings().stream()
        .anyMatch(w -> "dx/credential-pepper-recorded-not-wired".equals(w.code())
            && w.severity() == Severity.WARNING));
    assertFalse(lenient.services().stream()
        .anyMatch(s -> eu.jsentinel.jcustos.credential.password.pepper.PepperService.class.equals(s.spi())));
  }

  @Test
  @DisplayName("RoleBootstrap-style API check: V00.73 CredentialBootstrap has the 8 documented methods")
  void apiSurface() {
    List<String> methodNames = java.util.Arrays.stream(CredentialBootstrap.class.getMethods())
        .map(java.lang.reflect.Method::getName)
        .sorted()
        .toList();
    assertEquals(
        List.of("credentialStore", "hashing", "modern", "passwordChange",
            "passwordHasher", "passwordReset", "pbkdf2Defaults", "pepper"),
        methodNames);
  }

  // ── adapter test double ──────────────────────────────────────────

  private static final class TestBootstrap
      extends AbstractJCustosBootstrap<TestBootstrap> {
    @Override
    public JCustosRuntime install() {
      List<RegisteredJCustosService> services = new ArrayList<>();
      List<JCustosBootstrapWarning> warnings = new ArrayList<>();
      applyAuditConfiguration(services, warnings);
      applySessionConfiguration(AdapterKind.VAADIN, services, warnings);
      applyRoleConfiguration(services, warnings);
      applyCredentialConfiguration(services, warnings);
      JCustosBootstrapMode mode = state.mode();
      if (mode == JCustosBootstrapMode.STRICT
          && warnings.stream().anyMatch(w -> w.severity() == Severity.ERROR)) {
        throw new JCustosBootstrapException(warnings);
      }
      return new JCustosRuntime(services, warnings, mode);
    }
  }
}
