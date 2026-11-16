package eu.jsentinel.jcustos.demo.skill.standalone.security.bootstrap;

import eu.jsentinel.jcustos.bootstrap.BootstrapConfiguration;
import eu.jsentinel.jcustos.bootstrap.BootstrapMode;
import eu.jsentinel.jcustos.bootstrap.BootstrapStartup;
import eu.jsentinel.jcustos.bootstrap.BootstrapStateService;
import eu.jsentinel.jcustos.bootstrap.BootstrapTokenGenerator;
import eu.jsentinel.jcustos.bootstrap.BootstrapTokenOutput;
import eu.jsentinel.jcustos.bootstrap.BootstrapTokenStore;
import eu.jsentinel.jcustos.bootstrap.FileBootstrapTokenOutput;
import eu.jsentinel.jcustos.bootstrap.FileBootstrapTokenStore;
import eu.jsentinel.jcustos.bootstrap.InitialAdminBootstrapService;
import eu.jsentinel.jcustos.bootstrap.MinimumLengthPasswordPolicy;
import eu.jsentinel.jcustos.bootstrap.PasswordPolicy;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.RehashDecision;
import eu.jsentinel.jcustos.demo.skill.standalone.security.model.UserDirectory;
import eu.jsentinel.jcustos.demo.skill.standalone.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.demo.skill.standalone.security.storage.AppStoragePaths;

import java.nio.file.Path;
import java.time.Clock;
import java.util.Objects;

/**
 * Wires the first-admin bootstrap flow.
 *
 * <p>Lazy singleton: the first call constructs the chain once and
 * caches it. Call {@link #instance()} after {@code install()} — the
 * CLI does so at start-up. Layers:
 *
 * <ol>
 *   <li>{@link BootstrapStateService} reads
 *       {@code AdministratorAccountStore.hasAnyAdministrator()} to
 *       decide whether the system is uninitialised.</li>
 *   <li>{@link BootstrapStartup#initializeIfRequired} generates a
 *       one-time token on first start, persists it to
 *       {@code ./data/jcustos-standalone-persistence/bootstrap.token} and prints both the path and
 *       the token to stdout.</li>
 *   <li>{@link InitialAdminBootstrapService} validates the token from
 *       the CLI setup prompt and creates the admin via the
 *       {@link AdministratorAccountStoreImpl} adapter.</li>
 * </ol>
 *
 * <p>The administrator's password is hashed with the user directory's
 * own pipeline — the one the bootstrap configured — so the account it
 * creates can log in, and it must pass the password policy every
 * {@code BootstrapExtension} contributes (JS-SEC-134).
 *
 * <p>The token file lives at {@code ./data/jcustos-standalone-persistence/bootstrap.token} —
 * delete it (and any admin row in the persistent storage) to force
 * a re-bootstrap.
 */
public final class BootstrapWiring {

  public static final BootstrapMode DEFAULT_MODE = BootstrapMode.PERSISTENT_FILE;
  /**
   * Default token-file location. Reads {@link AppStoragePaths#PROPERTY}
   * so test forks land in {@code target/test-data/jcustos/bootstrap.token}
   * instead of the repo-rooted {@code ./data/jcustos-standalone-persistence/bootstrap.token}.
   */
  public static final Path DEFAULT_TOKEN_FILE =
      AppStoragePaths.bootstrapTokenFile();

  /** Minimum length of the first administrator's password. */
  public static final int MIN_ADMIN_PASSWORD_LENGTH = 12;

  private static volatile BootstrapWiring current;

  private final BootstrapStateService stateService;
  private final InitialAdminBootstrapService bootstrapService;

  private BootstrapWiring(BootstrapStateService stateService,
                          InitialAdminBootstrapService bootstrapService) {
    this.stateService = stateService;
    this.bootstrapService = bootstrapService;
  }

  public BootstrapStateService stateService() {
    return stateService;
  }

  public InitialAdminBootstrapService bootstrapService() {
    return bootstrapService;
  }

  public static BootstrapWiring instance() {
    BootstrapWiring local = current;
    if (local != null) return local;
    synchronized (BootstrapWiring.class) {
      if (current == null) {
        BootstrapConfiguration config = new BootstrapConfiguration(
            DEFAULT_MODE, DEFAULT_TOKEN_FILE, BootstrapConfiguration.DEFAULT_VALIDITY);
        current = create(config, new FileBootstrapTokenStore(config.tokenFilePath()),
            new FileBootstrapTokenOutput());
      }
      return current;
    }
  }

  /**
   * Builds the chain for {@code config}, generating a token when the
   * system is uninitialised.
   */
  public static BootstrapWiring create(BootstrapConfiguration config,
                                       BootstrapTokenStore tokenStore,
                                       BootstrapTokenOutput output) {
    UserDirectory directory = UserDirectoryProvider.directory();
    AdministratorAccountStoreImpl adminStore = new AdministratorAccountStoreImpl(directory);
    BootstrapStateService state = new BootstrapStateService(adminStore, config.mode());
    BootstrapStartup.initializeIfRequired(
        state, tokenStore, new BootstrapTokenGenerator(), output, config);
    PasswordPolicy policy = BootstrapBuilder.initialAdminPasswordPolicy(
        new MinimumLengthPasswordPolicy(MIN_ADMIN_PASSWORD_LENGTH));
    InitialAdminBootstrapService service = new InitialAdminBootstrapService(
        state, tokenStore, adminStore,
        directoryHashing(directory),
        policy,
        config.tokenValidity(), Clock.systemUTC());
    return new BootstrapWiring(state, service);
  }

  /** Test seam — installs {@code replacement}; {@code null} rebuilds on next use. */
  public static synchronized void setInstance(BootstrapWiring replacement) {
    current = replacement;
  }

  /**
   * The directory's pipeline, looked up per call: the first administrator
   * is hashed exactly like every other user, whenever the chain was built.
   */
  private static PasswordHashingService directoryHashing(UserDirectory directory) {
    Objects.requireNonNull(directory, "directory");
    return new PasswordHashingService() {
      @Override
      public PasswordHashResult hash(char[] password) {
        return directory.hashingService().hash(password);
      }

      @Override
      public CredentialVerificationResult verify(char[] password, String encodedHash) {
        return directory.hashingService().verify(password, encodedHash);
      }

      @Override
      public RehashDecision needsRehash(String encodedHash) {
        return directory.hashingService().needsRehash(encodedHash);
      }

      @Override
      public CredentialVerificationResult verifyAgainstNothing(char[] password) {
        return directory.hashingService().verifyAgainstNothing(password);
      }
    };
  }
}
