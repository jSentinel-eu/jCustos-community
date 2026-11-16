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
package eu.jsentinel.jcustos.session;

import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.audit.SessionStale;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Clock;

import static java.util.Objects.requireNonNull;

/**
 * Adapter-neutral enforcement layer on top of
 * {@link JCustosVersionCheck}. Adapters call
 * {@link #enforce(SubjectId, TenantId, JCustosVersion, String, String)
 * enforce(...)} per request with the subject + session snapshot and
 * pattern-match on the returned {@link EnforcementOutcome}:
 *
 * <ul>
 *   <li>{@link EnforcementOutcome.Continue} — request proceeds; the
 *       Vaadin {@code AuthorizationListener} or REST
 *       {@code RestAuthorizationFilter} runs next as usual.</li>
 *   <li>{@link EnforcementOutcome.SessionStale} — request must be
 *       refused. Vaadin reroutes to the login route; REST returns 401
 *       with {@code WWW-Authenticate: SessionStale}. The enforcer has
 *       already published the audit event when this is returned.</li>
 * </ul>
 *
 * <p>Audit failures are swallowed — a misbehaving sink cannot turn a
 * drift into a "Continue".
 *
 * <p>JS-SEC-117 (CWE-532, CWE-522): audit sinks keep events verbatim (ring
 * buffer, store-backed audit, integrity chain), so the {@link SessionStale}
 * event never carries the {@code sessionId} argument itself but its
 * {@link SessionRef} - the marker {@value SessionRef#PREFIX} and a truncated
 * SHA-256. The reduction is idempotent: the REST filter already hands over a
 * reference, which is stored unchanged. Until 00.84.00 the argument was stored
 * as passed, and the servlet session id the Vaadin listener passes reached
 * every sink but the logging one.
 */
@ExperimentalJCustosApi
public final class JCustosVersionEnforcer {

  private final JCustosVersionCheck check;
  private final JCustosAuditService auditService;
  private final Clock clock;

  /**
   * @param store        version store used to derive the current
   *                     value; non-null
   * @param auditService audit sink for {@link SessionStale} events;
   *                     non-null
   */
  public JCustosVersionEnforcer(JCustosVersionStore store,
                                 JCustosAuditService auditService) {
    this(new JCustosVersionCheck(store), auditService, Clock.systemUTC());
  }

  /**
   * Full constructor.
   *
   * @param check        version check; non-null
   * @param auditService audit sink for {@link SessionStale} events;
   *                     non-null
   * @param clock        time source for the audit timestamp; non-null
   */
  public JCustosVersionEnforcer(JCustosVersionCheck check,
                                 JCustosAuditService auditService,
                                 Clock clock) {
    this.check = requireNonNull(check, "check must not be null");
    this.auditService = requireNonNull(auditService,
        "auditService must not be null");
    this.clock = requireNonNull(clock, "clock must not be null");
  }

  /**
   * Runs the drift check and emits a {@link SessionStale} audit
   * event on drift.
   *
   * @param subjectId authenticated subject; non-null
   * @param tenant    tenant scope; {@code null} becomes
   *                  {@link TenantId#DEFAULT}
   * @param snapshot  session's
   *                  {@link SessionRecord#securityVersionAtLogin() captured version};
   *                  non-null
   * @param sessionId session identifier or reference for the audit event;
   *                  the event records its {@link SessionRef}, never the
   *                  value itself (JS-SEC-117); may be {@code null}
   * @param route     navigation route / REST path for the audit event;
   *                  may be {@code null}
   * @return enforcement outcome
   */
  public EnforcementOutcome enforce(SubjectId subjectId,
                                    TenantId tenant,
                                    JCustosVersion snapshot,
                                    String sessionId,
                                    String route) {
    requireNonNull(subjectId, "subjectId must not be null");
    requireNonNull(snapshot, "snapshot must not be null");
    TenantId effective = tenant == null ? TenantId.DEFAULT : tenant;
    JCustosVersionStatus status =
        check.check(new JCustosVersionKey(effective, subjectId), snapshot);
    return switch (status) {
      case JCustosVersionStatus.Current ignored -> EnforcementOutcome.CONTINUE;
      case JCustosVersionStatus.Drifted drifted -> {
        publishStale(subjectId, sessionId, route, drifted);
        yield new EnforcementOutcome.SessionStale(drifted);
      }
    };
  }

  private void publishStale(SubjectId subjectId,
                            String sessionId,
                            String route,
                            JCustosVersionStatus.Drifted drifted) {
    try {
      // JS-SEC-117 (CWE-532): the producer reduces, whatever the caller passed. The REST filter
      // hands in a reference already (idempotent); the Vaadin listener the servlet session id.
      auditService.publish(new SessionStale(
          clock.instant(),
          subjectId.value(),
          SessionRef.ofNullable(sessionId),
          route,
          drifted.snapshot().value(),
          drifted.current().value()));
    } catch (RuntimeException auditFailure) {
      // sinks must never block enforcement
    }
  }

  /**
   * Sealed outcome of an {@link #enforce} call.
   */
  public sealed interface EnforcementOutcome {

    /** Singleton shared "request continues" outcome. */
    Continue CONTINUE = new Continue();

    /**
     * @return {@code true} when this outcome refuses the request
     */
    default boolean isStale() {
      return this instanceof SessionStale;
    }

    /** The request continues — versions match. */
    record Continue() implements EnforcementOutcome {
    }

    /**
     * The request must be refused — session security version no
     * longer matches.
     *
     * @param status drift detail (snapshot + current)
     */
    record SessionStale(JCustosVersionStatus.Drifted status) implements EnforcementOutcome {
      /** Validates the component. */
      public SessionStale {
        requireNonNull(status, "status must not be null");
      }
    }
  }
}
