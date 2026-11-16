package eu.jsentinel.jcustos.demo.skill.standalone.security.model;

import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationUnavailableException;
import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.password.RehashDecision;
import eu.jsentinel.jcustos.credential.password.limiter.KdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.limiter.KdfResourceBudget;
import eu.jsentinel.jcustos.credential.password.limiter.SemaphoreKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2Defaults;
import eu.jsentinel.jcustos.demo.skill.standalone.security.roles.AuthorizationRole;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.EnumSet;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The directory hashes and verifies through the credential pipeline it is
 * given (JS-SEC-134), runs one KDF for an unknown name (CWE-208) and reports
 * a shed verification as unavailable, not as a wrong password (JS-SEC-126).
 */
class UserDirectoryHashingTest {

  @Test
  @DisplayName("JS-SEC-134: a new user's hash is the configured pipeline's envelope and verifies")
  void storesThePipelinesEnvelope() {
    InMemoryUserDirectory directory = new InMemoryUserDirectory(PasswordHashingServices.defaults());
    directory.addUser("grace", "Grace-pass-2026", new User(7L, "Grace", EnumSet.of(AuthorizationRole.USER)));
    String hash = directory.storedPasswordHash("grace").orElseThrow();
    assertTrue(hash.startsWith("$pwh$"), hash);
    assertTrue(directory.findByCredentials(new Credentials("grace", "Grace-pass-2026")).isPresent());
  }

  @Test
  @DisplayName("CWE-208: an unknown name costs one KDF run, like a wrong password")
  void unknownNameRunsTheDummyKdf() {
    CountingHashingService counting = new CountingHashingService(PasswordHashingServices.defaults());
    InMemoryUserDirectory directory = new InMemoryUserDirectory(counting);
    directory.addUser("heidi", "Heidi-pass-2026", new User(8L, "Heidi", EnumSet.of(AuthorizationRole.USER)));

    assertTrue(directory.findByCredentials(new Credentials("nobody", "whatever")).isEmpty());
    assertEquals(1, counting.kdfRuns.get(), "unknown user");
    assertTrue(directory.findByCredentials(new Credentials("heidi", "wrong")).isEmpty());
    assertEquals(2, counting.kdfRuns.get(), "known user, wrong password");
  }

  @Test
  @DisplayName("JS-SEC-126: a verification shed by the KDF limiter is unavailable, not wrong")
  void shedVerificationIsUnavailable() throws Exception {
    KdfExecutionLimiter limiter = new SemaphoreKdfExecutionLimiter(
        new KdfResourceBudget(1, Duration.ofMillis(20)));
    InMemoryUserDirectory directory = new InMemoryUserDirectory(
        PasswordHashingServices.defaults(Pbkdf2Defaults.referencePolicy(), limiter));
    directory.addUser("ivan", "Ivan-pass-2026", new User(9L, "Ivan", EnumSet.of(AuthorizationRole.USER)));
    Optional<KdfExecutionLimiter.Lease> held = limiter.acquire();
    try {
      assertThrows(CredentialVerificationUnavailableException.class,
          () -> directory.findByCredentials(new Credentials("ivan", "Ivan-pass-2026")));
      assertThrows(CredentialVerificationUnavailableException.class,
          () -> directory.findByCredentials(new Credentials("nobody", "whatever")));
    } finally {
      held.orElseThrow().close();
    }
    assertTrue(directory.findByCredentials(new Credentials("ivan", "Ivan-pass-2026")).isPresent());
  }

  /** Hand-written decorator over a real pipeline; counts KDF executions. */
  private static final class CountingHashingService implements PasswordHashingService {
    private final PasswordHashingService delegate;
    private final AtomicInteger kdfRuns = new AtomicInteger();

    CountingHashingService(PasswordHashingService delegate) {
      this.delegate = delegate;
    }

    @Override
    public PasswordHashResult hash(char[] password) {
      return delegate.hash(password);
    }

    @Override
    public CredentialVerificationResult verify(char[] password, String encodedHash) {
      kdfRuns.incrementAndGet();
      return delegate.verify(password, encodedHash);
    }

    @Override
    public RehashDecision needsRehash(String encodedHash) {
      return delegate.needsRehash(encodedHash);
    }

    @Override
    public CredentialVerificationResult verifyAgainstNothing(char[] password) {
      kdfRuns.incrementAndGet();
      return delegate.verifyAgainstNothing(password);
    }
  }
}
