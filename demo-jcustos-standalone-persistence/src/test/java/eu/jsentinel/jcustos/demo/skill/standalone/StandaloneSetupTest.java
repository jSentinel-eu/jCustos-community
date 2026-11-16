package eu.jsentinel.jcustos.demo.skill.standalone;

import eu.jsentinel.jcustos.bootstrap.BootstrapConfiguration;
import eu.jsentinel.jcustos.bootstrap.BootstrapMode;
import eu.jsentinel.jcustos.bootstrap.InMemoryBootstrapTokenStore;
import eu.jsentinel.jcustos.demo.skill.standalone.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.skill.standalone.security.bootstrap.JCustosStorageProvider;
import eu.jsentinel.jcustos.demo.skill.standalone.security.model.InMemoryUserDirectoryPersistence;
import eu.jsentinel.jcustos.demo.skill.standalone.security.model.PersistentUserDirectory;
import eu.jsentinel.jcustos.demo.skill.standalone.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.persistence.eclipsestore.JCustosStorageFactory;
import eu.jsentinel.jcustos.persistence.eclipsestore.JCustosStoragePair;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives the persistence-layer standalone CLI through the first-admin setup and the
 * login with the real security stack (JS-SEC-134): the administrator is hashed
 * with the configured pipeline, can log in, and a weak password is refused.
 */
class StandaloneSetupTest {

  private static final String ADMIN = "root-admin";
  private static final String ADMIN_PASSWORD = "Root-admin-pass-2026";

  @TempDir
  static Path storageDir;

  private static JCustosStoragePair storage;
  private static PersistentUserDirectory directory;
  private static String weakSetupOutput;
  private static String setupOutput;
  private static String loginOutput;
  private static String adminHashAfterSetup;

  @BeforeAll
  static void setUp() throws IOException {
    storage = JCustosStorageFactory.openAt(storageDir);
    JCustosStorageProvider.setPair(storage);
    directory = new PersistentUserDirectory(new InMemoryUserDirectoryPersistence());
    UserDirectoryProvider.setDirectory(directory);
    AtomicReference<String> token = new AtomicReference<>();
    BootstrapWiring.setInstance(BootstrapWiring.create(
        new BootstrapConfiguration(BootstrapMode.TRANSIENT_CONSOLE, null,
            BootstrapConfiguration.DEFAULT_VALIDITY),
        new InMemoryBootstrapTokenStore(),
        (bootstrapToken, configuration) -> token.set(bootstrapToken.value())));
    Main.installSecurity();
    weakSetupOutput = run(token.get() + "\n" + ADMIN + "\nshort-pass\n");
    setupOutput = run(token.get() + "\n" + ADMIN + "\n" + ADMIN_PASSWORD + "\n");
    // Before the first login: a login would replace an outdated hash.
    adminHashAfterSetup = directory.storedPasswordHash(ADMIN).orElseThrow();
    loginOutput = run(ADMIN + "\n" + ADMIN_PASSWORD + "\nwhoami\nquit\n");
  }

  @AfterAll
  static void tearDown() {
    UserDirectoryProvider.reset();
    BootstrapWiring.setInstance(null);
    JCustosStorageProvider.setPair(null);
    storage.close();
  }

  @Test
  @DisplayName("JS-SEC-134: a weak first-administrator password is refused")
  void weakFirstAdministratorPasswordIsRefused() {
    assertTrue(weakSetupOutput.contains("Password policy:"), weakSetupOutput);
    assertTrue(weakSetupOutput.contains("Setup failed"), weakSetupOutput);
  }

  @Test
  @DisplayName("JS-SEC-134: the first administrator can log in")
  void firstAdministratorCanLogIn() {
    assertTrue(setupOutput.contains("Created admin " + ADMIN), setupOutput);
    assertTrue(loginOutput.contains("Welcome, " + ADMIN), loginOutput);
  }

  @Test
  @DisplayName("JS-SEC-134: the first administrator is hashed with the configured pipeline")
  void firstAdministratorUsesThePipeline() {
    assertTrue(adminHashAfterSetup.contains("$pwh$v=1$"), adminHashAfterSetup.substring(0, 40));
  }

  private static String run(String input) throws IOException {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (PrintStream out = new PrintStream(bytes, true, StandardCharsets.UTF_8)) {
      new Main(new BufferedReader(new StringReader(input)), out).run();
    }
    return bytes.toString(StandardCharsets.UTF_8);
  }
}
