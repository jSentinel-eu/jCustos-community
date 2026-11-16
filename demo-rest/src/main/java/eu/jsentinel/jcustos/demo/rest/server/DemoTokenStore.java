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
package eu.jsentinel.jcustos.demo.rest.server;

import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.logout.SubjectSessionRegistry;
import eu.jsentinel.jcustos.demo.rest.domain.DemoUser;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.SessionStore;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory demo token store. Demo-only — not a production token mechanism.
 * <p>
 * Production systems must use cryptographically signed tokens with expiry,
 * refresh, and revocation policies.
 *
 * <h2>Per-token lifetime metadata</h2>
 *
 * <p>Each issued token also carries a {@link Metadata} record:
 * <ul>
 *   <li>{@code createdAt} — set once on {@link #issue(DemoUser)}.</li>
 *   <li>{@code lastActivityAt} — bumped on {@link #markActivity(String)}
 *       to drive {@code SessionPolicy.evaluate(SessionMetadata)} idle
 *       timeouts.</li>
 * </ul>
 *
 * <p>The store doesn't enforce expiry by itself — the framework's
 * {@code SessionPolicy} does. The store only serves the timestamps.
 *
 * <h2>Session references, never tokens (JS-SEC-117, CWE-522)</h2>
 *
 * <p>A bearer token is the credential itself. Wherever a session is named outside this
 * store — the {@link SubjectSessionRegistry} index, the {@link SessionRecord} key, audit
 * events, log lines — it is named by its {@linkplain #sessionReference(String) session
 * reference} ({@link SessionRef#of(String)}), which cannot be presented as a token.
 * {@link #revokeSession(String)} ends a session by that reference.
 *
 * <h2>Session records (JS-SEC-131, CWE-613)</h2>
 *
 * <p>When the store is built with a {@link SessionStore}, every issued token is recorded
 * there under {@code SessionId.of(sessionReference(token))} before the token is handed
 * out, and the record is deleted when the token is revoked. The REST filters consult that
 * store on every request: a record an administrator or another node set to
 * {@link SessionStatus#REVOKED} ends the session, although the token is still known here.
 */
public final class DemoTokenStore implements SubjectSessionRegistry {

  /**
   * Per-token user + lifetime metadata. The {@code snapshot}
   * captures the {@link JCustosVersion} of the user's
   * authority at issuance time so the V00.70 Phase 4c drift
   * filter can detect changes that happened after login.
   */
  public record Metadata(DemoUser user,
                         Instant createdAt,
                         Instant lastActivityAt,
                         JCustosVersion snapshot) {
  }

  private final ConcurrentMap<String, Metadata> tokens = new ConcurrentHashMap<>();
  /** Session reference to token - lets {@link #revokeSession(String)} find the token. */
  private final ConcurrentMap<String, String> tokensByReference = new ConcurrentHashMap<>();
  /** Session references per subject; never tokens. */
  private final ConcurrentMap<SubjectId, Set<String>> sessionsByUser = new ConcurrentHashMap<>();
  private final SecureRandom random = new SecureRandom();
  private final Clock clock;
  private final SessionStore sessionStore;

  /** Default — uses {@link Clock#systemUTC()}, records no sessions. */
  public DemoTokenStore() {
    this(Clock.systemUTC());
  }

  /** Test seam: inject a fixed clock. Records no sessions. */
  public DemoTokenStore(Clock clock) {
    this(clock, null);
  }

  /**
   * @param clock        clock for the lifetime metadata; non-null
   * @param sessionStore store every issued token is recorded in, or {@code null} to
   *                     record nothing
   */
  public DemoTokenStore(Clock clock, SessionStore sessionStore) {
    this.clock = clock;
    this.sessionStore = sessionStore;
  }

  /**
   * The non-secret name of the session a token opened: {@link SessionRef#of(String)}.
   *
   * @param token bearer token; non-null
   * @return the session reference
   */
  public static String sessionReference(String token) {
    return SessionRef.of(token);
  }

  /**
   * Issues a token with the user's authority {@code snapshot}
   * captured at issuance time. The snapshot is what
   * {@link eu.jsentinel.jcustos.rest.RestJCustosVersionFilter}
   * compares against the current {@code JCustosVersionStore}
   * value to detect drift.
   */
  public String issue(DemoUser user, JCustosVersion snapshot) {
    byte[] bytes = new byte[16];
    random.nextBytes(bytes);
    String token = HexFormat.of().formatHex(bytes);
    Instant now = Instant.now(clock);
    JCustosVersion version = snapshot == null ? JCustosVersion.INITIAL : snapshot;
    String reference = sessionReference(token);
    SubjectId subjectId = SubjectId.of(user.username());
    if (sessionStore != null) {
      // JS-SEC-131: the record exists before the token leaves the server.
      sessionStore.save(new SessionRecord(SessionId.of(reference), subjectId, TenantId.DEFAULT,
          now, now, version, SessionStatus.ACTIVE));
    }
    tokens.put(token, new Metadata(user, now, now, version));
    tokensByReference.put(reference, token);
    sessionsByUser
        .computeIfAbsent(subjectId, k -> ConcurrentHashMap.newKeySet())
        .add(reference);
    return token;
  }

  /**
   * Convenience overload that issues with
   * {@link JCustosVersion#INITIAL}. Kept for tests and demo
   * code paths that don't need drift detection wired.
   */
  public String issue(DemoUser user) {
    return issue(user, JCustosVersion.INITIAL);
  }

  public Optional<DemoUser> resolve(String token) {
    if (token == null || token.isBlank()) {
      return Optional.empty();
    }
    Metadata metadata = tokens.get(token);
    return metadata == null ? Optional.empty() : Optional.of(metadata.user());
  }

  /**
   * Returns the token's {@link Metadata}, or empty if the token is unknown.
   * Used by the REST adapter to build {@code SessionMetadata} for
   * {@code SessionPolicy.evaluate(...)}.
   */
  public Optional<Metadata> resolveMetadata(String token) {
    if (token == null || token.isBlank()) {
      return Optional.empty();
    }
    return Optional.ofNullable(tokens.get(token));
  }

  /**
   * Bumps the {@code lastActivityAt} of a known token to "now" on the
   * configured clock. No-op for unknown tokens. Returns the previous
   * timestamp (or {@link Optional#empty()} if the token wasn't there
   * before) so callers can build {@code SessionMetadata} that reflects
   * the activity *before* this request — the policy's idle check
   * compares the previous activity against the current time.
   */
  public Optional<Instant> markActivity(String token) {
    if (token == null || token.isBlank()) {
      return Optional.empty();
    }
    Instant now = Instant.now(clock);
    final Instant[] previous = new Instant[1];
    Metadata updated = tokens.computeIfPresent(token, (k, current) -> {
      previous[0] = current.lastActivityAt();
      return new Metadata(current.user(), current.createdAt(), now, current.snapshot());
    });
    return updated == null ? Optional.empty() : Optional.ofNullable(previous[0]);
  }

  /**
   * Revokes a token and deletes its session record.
   *
   * @param token bearer token; {@code null} is ignored
   */
  public void revoke(String token) {
    if (token == null) {
      return;
    }
    Metadata removed = tokens.remove(token);
    if (removed == null) {
      return;
    }
    String reference = sessionReference(token);
    tokensByReference.remove(reference);
    Set<String> entries = sessionsByUser.get(SubjectId.of(removed.user().username()));
    if (entries != null) {
      entries.remove(reference);
    }
    if (sessionStore != null) {
      sessionStore.delete(SessionId.of(reference));
    }
  }

  /**
   * Revokes the session named by its {@linkplain #sessionReference(String) reference} -
   * the form in which {@link #sessionsOf(SubjectId)}, {@link #clearAll(SubjectId)} and the
   * logout listeners name sessions.
   *
   * @param sessionReference the session reference; {@code null} or unknown is ignored
   */
  public void revokeSession(String sessionReference) {
    if (sessionReference == null) {
      return;
    }
    String token = tokensByReference.get(sessionReference);
    if (token != null) {
      revoke(token);
    }
  }

  // ── SubjectSessionRegistry ────────────────────────────────────
  // Every session id that crosses this interface is a session reference, never a token.

  @Override
  public void register(SubjectId subjectId, String sessionId) {
    sessionsByUser
        .computeIfAbsent(subjectId, k -> ConcurrentHashMap.newKeySet())
        .add(sessionId);
  }

  @Override
  public void unregister(SubjectId subjectId, String sessionId) {
    Set<String> entries = sessionsByUser.get(subjectId);
    if (entries != null) {
      entries.remove(sessionId);
    }
  }

  @Override
  public Collection<String> sessionsOf(SubjectId subjectId) {
    Set<String> entries = sessionsByUser.get(subjectId);
    return entries == null ? List.of() : List.copyOf(entries);
  }

  @Override
  public Collection<String> clearAll(SubjectId subjectId) {
    Set<String> entries = sessionsByUser.remove(subjectId);
    return entries == null ? List.of() : List.copyOf(entries);
  }
}
