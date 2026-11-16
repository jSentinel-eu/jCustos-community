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
package eu.jsentinel.jcustos.session.vaadin;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.JCustosVersion;
import com.vaadin.flow.server.VaadinSession;

import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Per-{@link VaadinSession} carrier for the security-version
 * snapshot captured at login time. The
 * {@link JCustosVersionEnforcerListener Vaadin enforcer
 * listener} consults this context on every navigation; the
 * application records it once after a successful login via
 * {@link #record(SubjectId, TenantId, JCustosVersion, String) record}.
 *
 * <p>Stored as a single {@link Snapshot} object under the
 * {@link Snapshot} class key, so it survives session-id rotation
 * (the attribute lives on the {@code VaadinSession}, not on the
 * {@code WrappedSession}).
 *
 * <p>This class only reads and writes — it does not consult the
 * {@code JCustosVersionStore} itself. Apps that want
 * "capture-current-on-login" semantics pair this helper with a
 * call to
 * {@code versionStore.current(new JCustosVersionKey(tenant, subjectId))}
 * right before {@link #record record}.
 */
@ExperimentalJCustosApi
public final class VaadinJCustosVersionContext {

  private VaadinJCustosVersionContext() {
    // utility
  }

  /**
   * Records the snapshot on the supplied session. Replaces any
   * previously recorded snapshot.
   *
   * @param session   target session; non-null
   * @param subjectId authenticated subject; non-null
   * @param tenant    tenant scope; {@code null} becomes
   *                  {@link TenantId#DEFAULT}
   * @param snapshot  security version captured at login time;
   *                  non-null
   * @param sessionId non-secret session label for the {@code SessionStale}
   *                  event of a drift, typically {@code SessionRef.of(id)};
   *                  may be {@code null}. The enforcer listener reduces a
   *                  raw session id to its reference before it reaches an
   *                  event (JS-SEC-117)
   */
  public static void record(VaadinSession session,
                            SubjectId subjectId,
                            TenantId tenant,
                            JCustosVersion snapshot,
                            String sessionId) {
    requireNonNull(session, "session must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    requireNonNull(snapshot, "snapshot must not be null");
    session.setAttribute(Snapshot.class,
        new Snapshot(subjectId,
            tenant == null ? TenantId.DEFAULT : tenant,
            snapshot, sessionId));
  }

  /**
   * Convenience overload writing to {@link VaadinSession#getCurrent()}.
   * No-op when no session is bound.
   *
   * @param subjectId authenticated subject; non-null
   * @param tenant    tenant scope; {@code null} becomes
   *                  {@link TenantId#DEFAULT}
   * @param snapshot  security version captured at login time;
   *                  non-null
   * @param sessionId opaque session identifier; may be {@code null}
   */
  public static void record(SubjectId subjectId,
                            TenantId tenant,
                            JCustosVersion snapshot,
                            String sessionId) {
    VaadinSession session = VaadinSession.getCurrent();
    if (session == null) {
      return;
    }
    record(session, subjectId, tenant, snapshot, sessionId);
  }

  /**
   * Returns the recorded snapshot for {@code session}, or empty
   * when none was recorded.
   *
   * @param session session to query; {@code null} returns empty
   * @return recorded snapshot, if present
   */
  public static Optional<Snapshot> current(VaadinSession session) {
    if (session == null) {
      return Optional.empty();
    }
    return Optional.ofNullable(session.getAttribute(Snapshot.class));
  }

  /**
   * Reads the recorded snapshot from {@link VaadinSession#getCurrent()}.
   *
   * @return recorded snapshot, if present
   */
  public static Optional<Snapshot> current() {
    return current(VaadinSession.getCurrent());
  }

  /**
   * Removes the snapshot from {@code session}. No-op when no
   * snapshot was recorded.
   *
   * @param session session to clear; {@code null} is a no-op
   */
  public static void clear(VaadinSession session) {
    if (session == null) {
      return;
    }
    session.setAttribute(Snapshot.class, null);
  }

  /**
   * Removes the snapshot from {@link VaadinSession#getCurrent()}.
   */
  public static void clear() {
    clear(VaadinSession.getCurrent());
  }

  /**
   * Per-session security state captured at login time.
   *
   * @param subjectId authenticated subject; non-null
   * @param tenant    tenant scope; non-null
   * @param snapshot  captured version; non-null
   * @param sessionId optional session id (may be {@code null})
   */
  public record Snapshot(SubjectId subjectId,
                         TenantId tenant,
                         JCustosVersion snapshot,
                         String sessionId) {
    /** Validates the components. */
    public Snapshot {
      requireNonNull(subjectId, "subjectId must not be null");
      requireNonNull(tenant, "tenant must not be null");
      requireNonNull(snapshot, "snapshot must not be null");
    }
  }
}
