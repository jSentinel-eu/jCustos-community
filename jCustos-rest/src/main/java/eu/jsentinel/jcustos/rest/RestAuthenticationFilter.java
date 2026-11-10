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
package eu.jsentinel.jcustos.rest;

import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.audit.SessionExpired;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.session.SessionMetadata;
import eu.jsentinel.jcustos.session.SessionPolicy;
import eu.jsentinel.jcustos.session.SessionPolicyDecision;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

/**
 * Authenticated-only REST filter for endpoints that require any subject but
 * no specific permission.
 * <p>
 * Refuses the request with {@code 401} when no subject is resolved or when
 * the resolved session has exceeded its idle / absolute lifetime per the
 * configured {@link SessionPolicy}; delegates to the handler otherwise.
 * <p>
 * JS-SEC-086 (CWE-778): both refusals render through the mapper a bootstrap
 * published to {@link RestDecisionContext} (falling back to
 * {@link HttpStatusDecisionMapper}), so the configured error-body strategy
 * and the {@code WWW-Authenticate} challenge apply here as they do in
 * {@link RestAuthorizationFilter}. Both leave an audit event: a missing
 * subject an {@link AccessDenied} with reason
 * {@code Unauthenticated:no-subject}, an expired session a
 * {@link SessionExpired}. The handler never runs on a refusal, whatever the
 * mapper returns.
 */
public final class RestAuthenticationFilter {

  private final RestSubjectResolver subjectResolver;

  public RestAuthenticationFilter(RestSubjectResolver subjectResolver) {
    this.subjectResolver = subjectResolver;
  }

  public void requireAuthenticated(RestRequest request, RestResponse response, RestHandler handler) {
    Optional<JCustosSubject> subject = subjectResolver.resolveSubject(request);
    if (subject.isEmpty()) {
      // JS-SEC-086 (CWE-778): render through the published mapper (status, challenge, body
      // strategy) and leave an AccessDenied in the audit trail - the anonymous request used to
      // be answered with a bare "Unauthorized" and no audit event at all.
      auditDenied(request, "Unauthenticated:no-subject");
      RestDecisionContext.mapperOrDefault()
          .apply(AuthorizationDecision.unauthenticated("no-subject"), response);
      return;
    }
    Optional<SessionMetadata> metadata = subjectResolver.resolveSessionMetadata(request);
    if (metadata.isPresent()) {
      SessionPolicy<Object> policy = JCustosServiceResolver.sessionPolicy();
      SessionPolicyDecision decision = policy.evaluate(metadata.get());
      if (!(decision instanceof SessionPolicyDecision.Active)) {
        auditExpired(metadata.get(), subject.orElse(null), decision);
        RestDecisionContext.mapperOrDefault()
            .apply(AuthorizationDecision.unauthenticated("session-expired"), response);
        return;
      }
    }
    handler.handle(request, response);
  }

  private static void auditDenied(RestRequest request, String reason) {
    JCustosAuditService sink = JCustosServiceResolver.securityAuditService();
    try {
      sink.publish(new AccessDenied(
          Instant.now(Clock.systemUTC()), null, request == null ? null : request.path(), reason));
    } catch (RuntimeException auditFailure) {
      // never block the filter because the audit sink failed
    }
  }

  private static void auditExpired(SessionMetadata metadata,
                                   JCustosSubject subject,
                                   SessionPolicyDecision decision) {
    String reason = switch (decision) {
      case SessionPolicyDecision.Active ignored -> "Active";
      case SessionPolicyDecision.IdleTimeout ignored -> SessionExpired.REASON_IDLE_TIMEOUT;
      case SessionPolicyDecision.AbsoluteLifetimeExceeded ignored -> SessionExpired.REASON_ABSOLUTE_LIFETIME;
    };
    JCustosAuditService sink = JCustosServiceResolver.securityAuditService();
    try {
      sink.publish(new SessionExpired(
          Instant.now(Clock.systemUTC()),
          metadata.subjectId() == null ? "" : metadata.subjectId(),
          null,
          reason));
    } catch (RuntimeException auditFailure) {
      // never block the filter because the audit sink failed
    }
  }
}
