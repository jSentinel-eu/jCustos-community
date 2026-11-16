/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.jsentinel.jcustos.persistence.eclipsestore;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.accountlifecycle.EmailVerificationTokenStore;
import eu.jsentinel.jcustos.accountlifecycle.PasswordResetTokenStore;
import eu.jsentinel.jcustos.audit.AuditEventStore;
import eu.jsentinel.jcustos.authentication.ApiKeyStore;
import eu.jsentinel.jcustos.authentication.RefreshTokenRecord;
import eu.jsentinel.jcustos.authentication.RefreshTokenStore;
import eu.jsentinel.jcustos.authentication.RememberMeTokenRecord;
import eu.jsentinel.jcustos.authentication.RememberMeTokenStore;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.roles.RoleAssignmentStore;
import eu.jsentinel.jcustos.bootstrap.BootstrapStateStore;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore;
import eu.jsentinel.jcustos.persistence.eclipsestore.EclipseStoreJCustosRoot.RateLimitBucket;
import eu.jsentinel.jcustos.persistence.eclipsestore.EclipseStoreJCustosRoot.Tables;
import eu.jsentinel.jcustos.ratelimiting.RateLimitStore;
import eu.jsentinel.jcustos.session.JCustosVersionStore;
import eu.jsentinel.jcustos.session.SessionStore;
import eu.jsentinel.jcustos.util.CapacityBound;
import org.eclipse.serializer.persistence.types.Storer;
import org.eclipse.store.afs.nio.types.NioFileSystem;
import org.eclipse.store.storage.embedded.types.EmbeddedStorage;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;

/**
 * Lifecycle handle for an Eclipse-Store-backed security persistence
 * layer.
 * <p>
 * Applications create one instance at startup pointing at a
 * directory on disk and shut it down at process exit. Between those
 * two events the {@code …Store()}-accessors return concrete
 * implementations of the Phase-2 SPIs, all sharing the single
 * {@link EclipseStoreJCustosRoot} held by the underlying
 * {@link EmbeddedStorageManager}.
 *
 * <p>Pattern:
 * <pre>
 * try (var storage = EclipseStoreJCustosStorage.openAt(dir)) {
 *   AuditEventStore audit = storage.auditEventStore();
 *   SessionStore sessions = storage.sessionStore();
 *   // ... use the stores ...
 * }   // close() shuts the StorageManager down cleanly
 * </pre>
 *
 * <p>Reads run in parallel; writes serialise behind a
 * {@link ReentrantReadWriteLock} guarded by every {@code EclipseStore*Store}
 * implementation. {@link AutoCloseable} on the facade lets the
 * try-with-resources idiom drive shutdown.
 *
 * <h2>What a mutation writes (JS-SEC-125, CWE-770, CWE-400)</h2>
 * <p>Every store keeps its data in a {@link StoredTable} (the audit store in
 * a {@link StoredLog}); a mutation reports the objects it changed and the
 * storage stores them in one transaction when the operation ends.
 * A new key writes one segment of its table, a changed value its own slot —
 * until 00.84.00 each mutation rewrote the whole map of its store. A storage
 * written in that earlier layout is moved over when it is opened; the
 * releases before 00.84.00 cannot read it afterwards.</p>
 *
 * <h2>Bounds</h2>
 * <p>The stores whose keys arrive with requests — sessions, remember-me
 * tokens and their rotation trail, password-reset and email-verification
 * tokens, refresh tokens, rate-limit keys, login-attempt keys — hold at most
 * {@link #DEFAULT_MAX_ENTRIES_PER_STORE} entries each unless
 * {@link #openAt(Path, int)} says otherwise. What a full store does is
 * documented with the store accessor.</p>
 *
 * <h2>Foreign content (JS-SEC-136)</h2>
 * <p>A storage directory whose root object is not a jCustos security root
 * is refused with {@code persistence/foreign-root}; it is never replaced by
 * an empty one. On POSIX the directory has to belong to the process user and
 * is restricted to {@code 0700}, see {@link StorageTreeHardening}.</p>
 */
@ExperimentalJCustosApi
public final class EclipseStoreJCustosStorage implements AutoCloseable, HasLogger {

  /**
   * Default upper bound on the entries of each store that is filled with keys
   * arriving in requests (JS-SEC-125, CWE-770): {@value}.
   *
   * @since 00.84.00
   */
  public static final int DEFAULT_MAX_ENTRIES_PER_STORE = CapacityBound.DEFAULT_MAX_ENTRIES;

  /** Stable code of the refusal to adopt a storage whose root is not a jCustos root. */
  static final String FOREIGN_ROOT_CODE = "persistence/foreign-root";

  private static final String STORAGE_PERMISSIONS_CODE = "persistence/storage-permissions";
  private static final String BACKUP_PERMISSIONS_CODE = "persistence/backup-permissions";

  private final EmbeddedStorageManager manager;
  private final EclipseStoreJCustosRoot root;
  private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
  /** Objects changed by the running write operation; guarded by the write lock. */
  private final Set<Object> changed = Collections.newSetFromMap(new IdentityHashMap<>());
  private final int maxEntries;
  private final Clock clock;
  private boolean closed;

  /**
   * Package-private constructor used by both {@link #openAt(Path)}
   * and {@link JCustosStorageFactory}. The constructor owns the
   * root-loading / root-creating decision so that callers only have
   * to hand in an already-started {@link EmbeddedStorageManager}.
   *
   * @param manager started Eclipse-Store manager; will be adopted by
   *                this instance (this class then owns its lifecycle)
   * @throws IllegalStateException {@code persistence/foreign-root} when the
   *                               storage holds a root of another type; the
   *                               caller shuts the manager down
   */
  EclipseStoreJCustosStorage(EmbeddedStorageManager manager) {
    this(manager, DEFAULT_MAX_ENTRIES_PER_STORE, Clock.systemUTC());
  }

  /**
   * @param manager    started Eclipse-Store manager
   * @param maxEntries bound of each request-keyed store
   * @param clock      time source for what a full store considers expired
   */
  EclipseStoreJCustosStorage(EmbeddedStorageManager manager, int maxEntries, Clock clock) {
    this.manager = manager;
    this.maxEntries = CapacityBound.requirePositiveCapacity(maxEntries);
    this.clock = requireNonNull(clock, "clock must not be null");
    Object existing = manager.root();
    if (existing == null) {
      EclipseStoreJCustosRoot fresh = new EclipseStoreJCustosRoot();
      manager.setRoot(fresh);
      manager.storeRoot();
      this.root = fresh;
    } else if (existing instanceof EclipseStoreJCustosRoot loaded) {
      this.root = loaded;
      if (loaded.tables == null) {
        migrateEarlierLayout(loaded);
      }
    } else {
      // JS-SEC-136 (CWE-665, CWE-754): until 00.84.00 a root of any other type was replaced
      // by an empty security root - swapped directories wiped the security state, or the
      // other application's data, without a word.
      throw new IllegalStateException(FOREIGN_ROOT_CODE + ": the storage holds a root object of type "
          + existing.getClass().getName() + ", not a jCustos security store. The directory was"
          + " written by something else - most likely it is not the directory meant for the"
          + " security store. Nothing was changed.");
    }
    attach(root.tables);
  }

  /**
   * Opens (or creates) a security persistence layer at the supplied
   * directory, each request-keyed store bounded to
   * {@link #DEFAULT_MAX_ENTRIES_PER_STORE} entries.
   *
   * @param storageDirectory directory the embedded storage uses; will
   *                         be created if missing
   * @return a started storage facade
   * @throws IllegalStateException {@code persistence/storage-permissions}
   *     when the directory cannot be restricted to its owner on POSIX, or
   *     {@code persistence/foreign-root} when it holds another application's
   *     storage (JS-SEC-136)
   */
  public static EclipseStoreJCustosStorage openAt(Path storageDirectory) {
    return openAt(storageDirectory, DEFAULT_MAX_ENTRIES_PER_STORE);
  }

  /**
   * Opens (or creates) a security persistence layer with an explicit bound.
   *
   * @param storageDirectory   directory the embedded storage uses; will be
   *                           created if missing
   * @param maxEntriesPerStore upper bound on the entries of each
   *                           request-keyed store; at least 1. An installation
   *                           with more concurrent sessions or live tokens
   *                           than the default raises it here.
   * @return a started storage facade
   * @throws IllegalStateException as for {@link #openAt(Path)}
   * @since 00.84.00
   */
  public static EclipseStoreJCustosStorage openAt(Path storageDirectory, int maxEntriesPerStore) {
    return openAt(storageDirectory, maxEntriesPerStore, Clock.systemUTC());
  }

  /** Test seam for the clock a full store judges expiry with. */
  static EclipseStoreJCustosStorage openAt(Path storageDirectory, int maxEntriesPerStore,
                                           Clock clock) {
    requireNonNull(storageDirectory, "storageDirectory must not be null");
    CapacityBound.requirePositiveCapacity(maxEntriesPerStore);
    EmbeddedStorageManager manager = initStorageManager(storageDirectory);
    try {
      return new EclipseStoreJCustosStorage(manager, maxEntriesPerStore, clock);
    } catch (RuntimeException adoptFailure) {
      // release the directory lock; the failure of the adoption is what the caller needs
      try {
        manager.shutdown();
      } catch (RuntimeException secondary) {
        adoptFailure.addSuppressed(secondary);
      }
      throw adoptFailure;
    }
  }

  /**
   * Shared init pipeline — starts the Eclipse-Store
   * {@link EmbeddedStorageManager} for the supplied directory.
   * Package-private so {@link JCustosStorageFactory} can reuse the
   * same init shape for the framework half of a storage pair without
   * also triggering the root-bootstrap that the constructor performs.
   *
   * @param dir storage directory; will be created if missing
   * @return a started {@link EmbeddedStorageManager}
   */
  static EmbeddedStorageManager initStorageManager(Path dir) {
    // JS-SEC-038 (CWE-276): harden owner-only before EmbeddedStorage.start so the framework
    // store — session handles, role assignments, login-attempt records and token hashes — is
    // never group/other-readable under a default umask. Living in the shared init also covers
    // the factory-reuse path. RF (exit-review): the hardening is the single StorageTreeHardening
    // home now, not a private copy (was duplicated across factory + facade + events module).
    // JS-SEC-136 (CWE-276, CWE-732): an existing directory is restricted as well, and one that
    // cannot be - it belongs to another user - is refused instead of opened with a warning.
    // JS-SEC-136 (CWE-367, CWE-59): the storage starts at the real directory the check
    // resolved, not at a path it would resolve again; a symbolic link as storage directory is
    // refused.
    Path checked = StorageTreeHardening.requireOwnerOnlyDirectory(dir, STORAGE_PERMISSIONS_CODE,
        "the framework store holds session handles, roles and token hashes");
    EmbeddedStorageManager manager = EmbeddedStorage.start(checked);
    // what the start has just created carries the process umask; take the open rights away
    StorageTreeHardening.restrictStorageFiles(checked, STORAGE_PERMISSIONS_CODE);
    return manager;
  }

  // ── earlier layout ───────────────────────────────────────────────

  /**
   * JS-SEC-125: moves a root that was written by a release up to 00.83.x, or by 00.84.00 before
   * the layout changed, into {@link Tables}. The order of the entries is kept. Tables and
   * emptied maps are stored in one transaction, so a crash leaves either layout, never both.
   */
  private void migrateEarlierLayout(EclipseStoreJCustosRoot earlier) {
    Tables tables = new Tables();
    attach(tables);
    earlier.auditEnvelopes.values().forEach(tables.auditEnvelopes::append);
    earlier.sessions.forEach(tables.sessions::put);
    earlier.loginAttempts.forEach(tables.loginAttempts::put);
    earlier.roleAssignments.forEach(tables.roleAssignments::put);
    earlier.bootstrapStates.forEach(tables.bootstrapStates::put);
    earlier.rememberMeTokens.forEach(tables.rememberMeTokens::put);
    earlier.passwordResetTokens.forEach(tables.passwordResetTokens::put);
    earlier.emailVerificationTokens.forEach(tables.emailVerificationTokens::put);
    earlier.apiKeys.forEach(tables.apiKeys::put);
    earlier.refreshTokens.forEach(tables.refreshTokens::put);
    if (earlier.refreshTokenInvalidBefore != null) { // null in a root stored by 00.83.x
      earlier.refreshTokenInvalidBefore.forEach(tables.refreshTokenInvalidBefore::put);
    }
    earlier.rateLimitEvents.forEach((key, instants) -> {
      RateLimitBucket bucket = new RateLimitBucket();
      bucket.events.addAll(instants);
      bucket.events.sort(null);
      tables.rateLimitBuckets.put(key, bucket);
    });
    earlier.securityVersions.forEach(tables.securityVersions::put);
    int moved = tables.auditEnvelopes.size() + tables.sessions.size() + tables.loginAttempts.size()
        + tables.roleAssignments.size() + tables.bootstrapStates.size()
        + tables.rememberMeTokens.size() + tables.passwordResetTokens.size()
        + tables.emailVerificationTokens.size() + tables.apiKeys.size()
        + tables.refreshTokens.size() + tables.refreshTokenInvalidBefore.size()
        + tables.rateLimitBuckets.size() + tables.securityVersions.size();

    // a list, not a set: emptied maps are all equal to each other
    List<Object> emptied = new ArrayList<>();
    for (Map<?, ?> map : new Map<?, ?>[] {earlier.auditEnvelopes, earlier.sessions,
        earlier.loginAttempts, earlier.roleAssignments, earlier.bootstrapStates,
        earlier.rememberMeTokens, earlier.passwordResetTokens, earlier.emailVerificationTokens,
        earlier.apiKeys, earlier.refreshTokens, earlier.refreshTokenInvalidBefore,
        earlier.rateLimitEvents, earlier.securityVersions}) {
      if (map != null && !map.isEmpty()) {
        map.clear();
        emptied.add(map); // changed in place: storing the root alone would not write it
      }
    }
    earlier.tables = tables;
    changed.clear(); // the tables are new objects and are written through the root
    Storer storer = manager.createStorer();
    storer.store(earlier);
    emptied.forEach(storer::store);
    storer.commit();
    logger().info("persistence/storage-layout-migrated: {} entries of the security store were moved"
        + " to the layout of 00.84.00; releases before 00.84.00 cannot read this storage any more",
        moved);
  }

  private void attach(Tables tables) {
    tables.auditEnvelopes.attach(this::markChanged);
    tables.sessions.attach(this::markChanged, null);
    tables.loginAttempts.attach(this::markChanged, null);
    tables.roleAssignments.attach(this::markChanged, null);
    tables.bootstrapStates.attach(this::markChanged, null);
    tables.rememberMeTokens.attach(this::markChanged, RememberMeTokenRecord::expiresAt);
    tables.rememberMeRotated.attach(this::markChanged, trail -> trail.record().expiresAt());
    if (tables.rememberMeInvalidBefore == null) { // a storage written before the table existed
      tables.rememberMeInvalidBefore = new StoredTable<>();
      markChanged(tables);
    }
    tables.rememberMeInvalidBefore.attach(this::markChanged, null);
    tables.passwordResetTokens.attach(this::markChanged,
        record -> record.isConsumed() ? Instant.MIN : record.expiresAt());
    tables.emailVerificationTokens.attach(this::markChanged,
        record -> record.isConsumed() ? Instant.MIN : record.expiresAt());
    tables.apiKeys.attach(this::markChanged, null);
    tables.refreshTokens.attach(this::markChanged, RefreshTokenRecord::expiresAt);
    tables.refreshTokenInvalidBefore.attach(this::markChanged, null);
    tables.rateLimitBuckets.attach(this::markChanged, RateLimitBucket::deadAt);
    tables.securityVersions.attach(this::markChanged, null);
  }

  /**
   * Shuts the underlying {@link EmbeddedStorageManager} down. Safe to
   * call more than once; subsequent calls are no-ops.
   *
   * <p>R033: a {@code closed} guard (taken under the write lock, so it is
   * thread-safe and ordered against in-flight store writes) makes the second
   * and later calls genuine no-ops, matching this contract — previously a
   * second call hit an already-shut manager.
   */
  @Override
  public void close() {
    lock.writeLock().lock();
    try {
      if (closed) {
        return;
      }
      closed = true;
      manager.shutdown();
    } finally {
      lock.writeLock().unlock();
    }
  }

  /**
   * Exports a consistent full backup of the live storage into
   * {@code targetDirectory}: every channel data file, the transaction
   * logs and the persistence type dictionary — the result is a bootable
   * storage directory that {@code EmbeddedStorage.start(...)} can open
   * directly. The storage keeps serving while the export runs; Eclipse
   * Store guarantees the exported file set is consistent.
   *
   * <p>The target directory must be empty (or absent — it is created);
   * a non-empty target fails with the underlying storage exception.
   *
   * <p>JS-SEC-136 (CWE-276, CWE-530): the backup holds what the live store
   * holds — session handles, role assignments, login-attempt records and
   * token hashes. On POSIX the target is therefore created owner-only
   * ({@code 0700}), an existing empty target is restricted to its owner, and
   * the exported directories and files lose every right for group and
   * others; until 00.84.00 the copy was written with the process umask and
   * was usually readable for every local user. A target that belongs to
   * another user is refused. On a filesystem without POSIX attributes
   * owner-only permissions cannot be enforced (JS-SEC-016) — export into a
   * directory whose ACL is restricted.</p>
   *
   * @param targetDirectory directory the backup is exported into
   * @throws IllegalStateException when the storage is already closed, or
   *     {@code persistence/backup-permissions} when the target cannot be
   *     restricted to its owner
   * @since 00.82.00
   */
  public void issueFullBackup(Path targetDirectory) {
    requireNonNull(targetDirectory, "targetDirectory must not be null");
    lock.readLock().lock();
    try {
      if (closed) {
        throw new IllegalStateException("storage is closed — no backup possible");
      }
      // A target that already holds something is refused by the export itself; its
      // permissions are none of our business and stay untouched.
      if (!holdsEntries(targetDirectory)) {
        StorageTreeHardening.requireOwnerOnly(targetDirectory, BACKUP_PERMISSIONS_CODE,
            "the backup holds the session handles, roles and token hashes of the live store");
      }
      manager.issueFullBackup(
          NioFileSystem.New().ensureDirectory(targetDirectory));
      StorageTreeHardening.restrictStorageFiles(targetDirectory, BACKUP_PERMISSIONS_CODE);
    } finally {
      lock.readLock().unlock();
    }
  }

  private static boolean holdsEntries(Path directory) {
    if (!Files.isDirectory(directory)) {
      return false;
    }
    try (Stream<Path> entries = Files.list(directory)) {
      return entries.findAny().isPresent();
    } catch (IOException unreadable) {
      return false; // requireOwnerOnly judges it next
    }
  }

  // ── package-private accessors used by every store ────────────────

  EclipseStoreJCustosRoot root() {
    return root;
  }

  Tables tables() {
    return root.tables;
  }

  EmbeddedStorageManager manager() {
    return manager;
  }

  ReentrantReadWriteLock lock() {
    return lock;
  }

  /** @return bound of each request-keyed store */
  int maxEntries() {
    return maxEntries;
  }

  /** @return the instant a full store judges expiry against */
  Instant now() {
    return clock.instant();
  }

  /** Runs {@code operation} under the read lock. */
  <R> R read(Supplier<R> operation) {
    lock.readLock().lock();
    try {
      return operation.get();
    } finally {
      lock.readLock().unlock();
    }
  }

  /**
   * Runs {@code operation} under the write lock and stores what it changed in one
   * transaction (JS-SEC-125). What the operation changed before it threw is stored as well,
   * so that memory and disk do not part.
   */
  <R> R write(Supplier<R> operation) {
    lock.writeLock().lock();
    try {
      R result;
      try {
        result = operation.get();
      } catch (RuntimeException | Error failure) {
        try {
          storeChanged();
        } catch (RuntimeException storeFailure) {
          failure.addSuppressed(storeFailure);
        }
        throw failure;
      }
      storeChanged();
      return result;
    } finally {
      lock.writeLock().unlock();
    }
  }

  /** {@link #write(Supplier)} for an operation without a result. */
  void update(Runnable operation) {
    write(() -> {
      operation.run();
      return null;
    });
  }

  /**
   * Reports an object the running write operation changed in place. The tables report their
   * own segments and slots; an adapter reports a value it mutated instead of replacing —
   * Eclipse Store does not write an object again just because its container is stored (R002).
   */
  void markChanged(Object object) {
    changed.add(object);
  }

  /** Caller holds the write lock. A failed store keeps the objects for the next attempt. */
  private void storeChanged() {
    if (changed.isEmpty()) {
      return;
    }
    Storer storer = manager.createStorer();
    for (Object object : changed) {
      storer.store(object);
    }
    storer.commit();
    changed.clear();
  }

  // ── public store accessors ──────────────────────────────────────

  /**
   * Returns the Eclipse-Store-backed {@link AuditEventStore}.
   *
   * @return audit event store
   */
  public AuditEventStore auditEventStore() {
    return new EclipseStoreAuditEventStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link SessionStore}. Bounded: at the
   * bound a new session makes room by dropping the oldest expired record, or
   * else the oldest active one; a revoked record is kept for 30 days, and a
   * store full of such records refuses new sessions with
   * {@code persistence/session-store-capacity-exceeded} (JS-SEC-131).
   *
   * @return session store
   */
  public SessionStore sessionStore() {
    return new EclipseStoreSessionStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link LoginAttemptStore}. Bounded: a
   * live lockout is never evicted, a store full of live lockouts refuses
   * further keys (JS-SEC-122).
   *
   * @return login attempt store
   */
  public LoginAttemptStore loginAttemptStore() {
    return new EclipseStoreLoginAttemptStore(this, maxEntries);
  }

  /**
   * Returns the Eclipse-Store-backed {@link RoleAssignmentStore}.
   *
   * @return role assignment store
   */
  public RoleAssignmentStore roleAssignmentStore() {
    return new EclipseStoreRoleAssignmentStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link BootstrapStateStore}.
   *
   * @return bootstrap state store
   */
  public BootstrapStateStore bootstrapStateStore() {
    return new EclipseStoreBootstrapStateStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link RememberMeTokenStore}. It keeps
   * the trail of rotated tokens, so a replayed token is recognised across a
   * restart (JS-SEC-128). Bounded, live tokens and trail each: expired
   * entries go first, then the entry stored first.
   *
   * @return remember-me token store
   */
  public RememberMeTokenStore rememberMeTokenStore() {
    return new EclipseStoreRememberMeTokenStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link PasswordResetTokenStore}. Bounded:
   * at the bound consumed and expired records are dropped; when all records
   * are open, {@code save} fails with
   * {@code accountlifecycle/password-reset-token-store-capacity-exceeded}.
   *
   * @return password-reset token store
   */
  public PasswordResetTokenStore passwordResetTokenStore() {
    return new EclipseStorePasswordResetTokenStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link EmailVerificationTokenStore}.
   * Bounded like the password-reset store; a full store fails {@code save}
   * with {@code accountlifecycle/email-verification-token-store-capacity-exceeded}.
   *
   * @return email-verification token store
   */
  public EmailVerificationTokenStore emailVerificationTokenStore() {
    return new EclipseStoreEmailVerificationTokenStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link ApiKeyStore}.
   *
   * @return api key store
   */
  public ApiKeyStore apiKeyStore() {
    return new EclipseStoreApiKeyStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link RefreshTokenStore}. Bounded:
   * expired records go first, then the record stored first.
   *
   * @return refresh token store
   */
  public RefreshTokenStore refreshTokenStore() {
    return new EclipseStoreRefreshTokenStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link RateLimitStore}. Admission is
   * atomic (JS-SEC-118). Bounded in keys and in events per key: dead buckets
   * go first, then the key used least recently.
   *
   * @return rate limit store
   */
  public RateLimitStore rateLimitStore() {
    return new EclipseStoreRateLimitStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link JCustosVersionStore}.
   *
   * @return security version store
   */
  public JCustosVersionStore securityVersionStore() {
    return new EclipseStoreJCustosVersionStore(this);
  }
}
