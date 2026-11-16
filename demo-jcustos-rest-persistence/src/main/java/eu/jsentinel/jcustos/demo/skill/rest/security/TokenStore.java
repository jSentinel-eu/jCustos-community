package eu.jsentinel.jcustos.demo.skill.rest.security;

import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.session.JCustosVersion;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Bearer-token store. Demo-grade — in-memory only.
 *
 * <p>A token is bound to a <em>user id</em>, never to a copy of the
 * user: the resolver loads the user from the {@code UserDirectory} on
 * every request, so a deleted user loses access at once and a role
 * change takes effect at once (JS-SEC-132). The entry also keeps the
 * security-version snapshot taken at login (when a
 * {@code JCustosVersionStore} is registered) for the drift filter, and
 * the creation and last-activity times for the session policy.
 *
 * <p>The raw token is not kept: entries are keyed by its SHA-256, and a
 * session is named everywhere else — audit, session records, the
 * admin endpoint — by {@link SessionRef#of(String)}, which cannot be
 * used as a credential (JS-SEC-117).
 */
public final class TokenStore {

  /**
   * Hard upper bound of a token's life, matching the absolute lifetime of
   * the library's default session policy. The policy enforces idle and
   * absolute lifetime on every request; this bound only lets the store
   * forget entries nobody presents any more.
   */
  public static final Duration MAX_TOKEN_LIFETIME = Duration.ofHours(12);

  /** Singleton — one map per JVM. */
  public static final TokenStore INSTANCE = new TokenStore();

  private static final int TOKEN_BYTES = 32;

  private final ConcurrentHashMap<String, Entry> byTokenHash = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<String, String> tokenHashByReference = new ConcurrentHashMap<>();
  private final SecureRandom random = new SecureRandom();
  private volatile Clock clock = Clock.systemUTC();

  private TokenStore() {
  }

  /**
   * Issues a token for {@code userId}.
   *
   * @param snapshot security version at login, or {@code null} without drift detection
   * @return the token — handed to the client once, never stored or logged
   */
  public String issue(Long userId, JCustosVersion snapshot) {
    Objects.requireNonNull(userId, "userId");
    byte[] bytes = new byte[TOKEN_BYTES];
    random.nextBytes(bytes);
    String token = HexFormat.of().formatHex(bytes);
    Instant now = Instant.now(clock);
    String reference = SessionRef.of(token);
    String key = hash(token);
    byTokenHash.put(key, new Entry(userId, reference, snapshot, now, now));
    tokenHashByReference.put(reference, key);
    return token;
  }

  /** The live session of {@code token}, or empty when unknown or past {@link #MAX_TOKEN_LIFETIME}. */
  public Optional<Session> resolve(String token) {
    if (token == null || token.isBlank()) return Optional.empty();
    String key = hash(token);
    Entry entry = byTokenHash.get(key);
    if (entry == null) return Optional.empty();
    if (Instant.now(clock).isAfter(entry.createdAt.plus(MAX_TOKEN_LIFETIME))) {
      remove(key);
      return Optional.empty();
    }
    return Optional.of(entry.view());
  }

  /**
   * Marks the session as active now.
   *
   * @return the session as it was <em>before</em> this call, so the idle
   *         check sees the real gap
   */
  public Optional<Session> touch(String token) {
    if (token == null || token.isBlank()) return Optional.empty();
    Instant now = Instant.now(clock);
    Entry[] previous = new Entry[1];
    byTokenHash.computeIfPresent(hash(token), (k, current) -> {
      previous[0] = current;
      return new Entry(current.userId, current.reference, current.snapshot, current.createdAt, now);
    });
    return previous[0] == null ? Optional.empty() : Optional.of(previous[0].view());
  }

  public void revoke(String token) {
    if (token != null && !token.isBlank()) remove(hash(token));
  }

  /** Ends the session named by its {@link SessionRef}. */
  public boolean revokeByReference(String reference) {
    String key = reference == null ? null : tokenHashByReference.get(reference);
    return key != null && remove(key);
  }

  /** Ends every session of {@code userId}. */
  public void revokeAllOf(Long userId) {
    byTokenHash.entrySet().removeIf(e -> {
      boolean match = e.getValue().userId.equals(userId);
      if (match) tokenHashByReference.remove(e.getValue().reference);
      return match;
    });
  }

  /** Snapshot of the live sessions — references only, never tokens. */
  public List<Session> all() {
    return byTokenHash.values().stream().map(Entry::view).toList();
  }

  /** Test seam — the clock that stamps and ages tokens. */
  public void useClock(Clock replacement) {
    clock = Objects.requireNonNull(replacement, "replacement");
  }

  /** Test seam — forgets every session and restores the system clock. */
  public void clear() {
    byTokenHash.clear();
    tokenHashByReference.clear();
    clock = Clock.systemUTC();
  }

  private boolean remove(String key) {
    Entry removed = byTokenHash.remove(key);
    if (removed != null) {
      tokenHashByReference.remove(removed.reference);
    }
    return removed != null;
  }

  private static String hash(String token) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256")
          .digest(token.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  /**
   * Public view of a session.
   *
   * @param reference {@link SessionRef} of the token — the session's name
   * @param snapshot  security version at login, or {@code null}
   */
  public record Session(Long userId, String reference, JCustosVersion snapshot,
                        Instant createdAt, Instant lastActivityAt) {
  }

  private record Entry(Long userId, String reference, JCustosVersion snapshot,
                       Instant createdAt, Instant lastActivityAt) {
    Session view() {
      return new Session(userId, reference, snapshot, createdAt, lastActivityAt);
    }
  }
}
