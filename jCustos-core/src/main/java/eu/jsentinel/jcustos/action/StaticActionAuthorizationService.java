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
package eu.jsentinel.jcustos.action;

import eu.jsentinel.jcustos.audit.ActionDenied;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.AccessDeniedException;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionMatcher;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

/**
 * Default {@link ActionAuthorizationService} that checks an
 * {@link ActionPermission} against the subject's permission set obtained
 * via the configured {@link AuthorizationService}.
 * <p>
 * The action's {@link ActionPermission#name() name} is matched
 * case-sensitively against the {@link PermissionName#value() value} of
 * each permission returned by
 * {@link AuthorizationService#permissionsFor(Object)}, so applications
 * can keep a single string vocabulary across both APIs while opting
 * into the typed action layer.
 * <p>
 * On {@code requireAllowed} denial, this implementation emits an
 * {@link ActionDenied} audit event before throwing.
 *
 * @param <U> subject type
 */
public final class StaticActionAuthorizationService<U> implements ActionAuthorizationService<U> {

  private final AuthorizationService<U> authorizationService;
  private final JCustosAuditService auditService;
  private final SubjectIdResolver<U> subjectIdResolver;

  /**
   * Builds a service that resolves the {@link AuthorizationService} via
   * {@link JCustosServiceResolver}. Audit events are routed to
   * {@link JCustosServiceResolver#securityAuditService()} at check time.
   *
   * @param subjectType compile-time helper — kept on the constructor so
   *                    the generic parameter is inferable; not stored
   */
  @SuppressWarnings("unused")
  public StaticActionAuthorizationService(Class<U> subjectType) {
    this(JCustosServiceResolver.<U>authorizationService(), null);
  }

  /**
   * @param authorizationService the application's authorization service
   * @param auditService         audit sink, or {@code null} to resolve
   *                             from {@link JCustosServiceResolver}
   *                             at each check
   */
  public StaticActionAuthorizationService(
      AuthorizationService<U> authorizationService,
      JCustosAuditService auditService) {
    this(authorizationService, auditService, null);
  }

  /**
   * @param authorizationService source of the subject's permissions; non-null
   * @param auditService         audit sink, or {@code null} to resolve from
   *                             {@link JCustosServiceResolver} on each event
   * @param subjectIdResolver    resolver for the audit subject id (JS-SEC-083), or
   *                             {@code null} to use the one registered with
   *                             {@link JCustosServiceResolver}
   * @since 00.84.00
   */
  public StaticActionAuthorizationService(
      AuthorizationService<U> authorizationService,
      JCustosAuditService auditService,
      SubjectIdResolver<U> subjectIdResolver) {
    this.authorizationService = Objects.requireNonNull(
        authorizationService, "authorizationService");
    this.auditService = auditService;
    this.subjectIdResolver = subjectIdResolver;
  }

  @Override
  public boolean isAllowed(U subject, ActionPermission permission) {
    if (subject == null || permission == null) {
      return false;
    }
    // R027: match via PermissionMatcher (wildcard-aware) so a granted wildcard
    // like "doc:*" authorizes "doc:delete" here exactly as it does on the
    // annotation / enforcer path — exact String.equals() silently denied it.
    PermissionName required = new PermissionName(permission.name());
    return authorizationService.permissionsFor(subject).permissionNames().stream()
        .anyMatch(granted -> PermissionMatcher.matches(granted, required));
  }

  @Override
  public void requireAllowed(U subject, ActionPermission permission) {
    if (isAllowed(subject, permission)) {
      return;
    }

    String actionName = permission == null ? "<null>" : permission.name();
    auditDenied(subject, actionName);
    throw new AccessDeniedException("Missing action permission: " + actionName);
  }

  private void auditDenied(U subject, String actionName) {
    JCustosAuditService sink = auditService != null
        ? auditService
        : JCustosServiceResolver.securityAuditService();
    try {
      sink.publish(new ActionDenied(
          Instant.now(Clock.systemUTC()), subjectIdOf(subject), actionName));
    } catch (RuntimeException auditFailure) {
      // never block the AccessDeniedException because the audit sink failed
    }
  }

  /**
   * JS-SEC-083 (CWE-778): {@code ActionDenied} must correlate with the login and session
   * events, which go through the {@link SubjectIdResolver} (JS-SEC-004); an identity hash
   * changes per object and {@code toString()} is a PII source. The explicit resolver wins,
   * then the registered one; without either (or with a blank result) the non-PII identity
   * handle remains.
   */
  private String subjectIdOf(U subject) {
    if (subject == null) {
      return null;
    }
    SubjectIdResolver<U> resolver = subjectIdResolver != null
        ? subjectIdResolver
        : JCustosServiceResolver.<U>findSubjectIdResolver().orElse(null);
    if (resolver != null) {
      try {
        String resolved = resolver.resolve(subject).value();
        if (resolved != null && !resolved.isBlank()) {
          return resolved;
        }
      } catch (RuntimeException ignored) {
        // fall through to the identity handle
      }
    }
    return subject.getClass().getSimpleName()
        + "@" + Integer.toHexString(System.identityHashCode(subject));
  }
}
