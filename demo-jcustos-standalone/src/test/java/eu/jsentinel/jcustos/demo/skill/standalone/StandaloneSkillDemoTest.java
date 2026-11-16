package eu.jsentinel.jcustos.demo.skill.standalone;

import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.password.limiter.KdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.limiter.KdfResourceBudget;
import eu.jsentinel.jcustos.credential.password.limiter.SemaphoreKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2Defaults;
import eu.jsentinel.jcustos.demo.skill.standalone.security.model.InMemoryUserDirectory;
import eu.jsentinel.jcustos.demo.skill.standalone.security.model.User;
import eu.jsentinel.jcustos.demo.skill.standalone.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.demo.skill.standalone.security.roles.AuthorizationRole;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives the layer-1 standalone CLI through {@link Main#run()} with the real
 * security stack: login outcomes (JS-SEC-123/126), deny-by-default and the
 * seed switch (JS-SEC-137).
 */
class StandaloneSkillDemoTest {

  private static InMemoryUserDirectory directory;

  @BeforeAll
  static void install() {
    directory = new InMemoryUserDirectory();
    UserDirectoryProvider.setDirectory(directory);
    Main.installSecurity();
    directory.seedInsecureDemoAccounts();
  }

  @AfterAll
  static void reset() {
    UserDirectoryProvider.reset();
  }

  @Test
  @DisplayName("A seeded user logs in; deny-by-default and the permission checks hold")
  void loginAndPermissionChecks() throws IOException {
    String out = run("user\nuser\nlist\ncreate notes\nquit\n");
    assertTrue(out.contains("Welcome, Regular User"), out);
    assertTrue(out.contains("DENIED"), "user lacks doc:create: " + out);
  }

  @Test
  @DisplayName("JS-SEC-126: a shed verification is 'try again later' and counts as no failure")
  void shedVerificationIsTryAgainLater() throws Exception {
    KdfExecutionLimiter limiter = new SemaphoreKdfExecutionLimiter(
        new KdfResourceBudget(1, Duration.ofMillis(20)));
    InMemoryUserDirectory shedding = new InMemoryUserDirectory(
        PasswordHashingServices.defaults(Pbkdf2Defaults.referencePolicy(), limiter));
    shedding.addUser("judy-shed", "Judy-pass-2026",
        new User(77L, "Judy", EnumSet.of(AuthorizationRole.USER)));
    UserDirectoryProvider.setDirectory(shedding);
    try {
      KdfExecutionLimiter.Lease held = limiter.acquire().orElseThrow();
      try {
        for (int i = 0; i < 6; i++) {
          String out = run("judy-shed\nJudy-pass-2026\nquit\n");
          assertTrue(out.contains("Login temporarily unavailable"), out);
        }
      } finally {
        held.close();
      }
      // Six shed attempts counted as failures would have locked the key (threshold 5).
      assertTrue(run("judy-shed\nJudy-pass-2026\nquit\n").contains("Welcome, Judy"));
    } finally {
      UserDirectoryProvider.setDirectory(directory);
    }
  }

  @Test
  @DisplayName("JS-SEC-124: repeated failures lock the account out")
  void repeatedFailuresLockOut() throws IOException {
    String out = "";
    for (int i = 0; i < 6; i++) {
      out = run("nobody-lockout\nguess-" + i + "\n");
    }
    assertTrue(out.contains("Locked. Try again in"), out);
  }

  @Test
  @DisplayName("JS-SEC-137: without the development switch the directory has no fixed-password accounts")
  void noSeedAccountsByDefault() {
    assertFalse(InMemoryUserDirectory.insecureSeedAccountsRequested());
    UserDirectoryProvider.reset();
    try {
      assertEquals(0L, UserDirectoryProvider.directory().all().count());
    } finally {
      UserDirectoryProvider.setDirectory(directory);
    }
  }

  private static String run(String input) throws IOException {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (PrintStream out = new PrintStream(bytes, true, StandardCharsets.UTF_8)) {
      new Main(new BufferedReader(new StringReader(input)), out).run();
    }
    return bytes.toString(StandardCharsets.UTF_8);
  }
}
