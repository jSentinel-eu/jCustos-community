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
package eu.jsentinel.jcustos.authorization.impl;

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import com.vaadin.flow.router.BeforeEnterEvent;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Creates core {@link AccessContext} instances from Vaadin navigation
 * events.
 * <p>
 * Reads the current authenticated subject (via {@link SubjectStores}) and
 * adapts it to a {@link JCustosSubject} so generic
 * {@code AuthorizationEvaluator} implementations (such as
 * {@code RequiresRoleEvaluator} and {@code RequiresPermissionEvaluator}
 * shipped in {@code security-core}) see the subject's roles and
 * permissions through {@link AccessContext#subject()}.
 * <p>
 * The legacy {@code RoleBasedAccessEvaluator} family reads the subject
 * directly from {@link SubjectStores} and is unaffected by this change.
 */
public final class VaadinAccessContextFactory {

  /** Creates a new factory. */
  public VaadinAccessContextFactory() {
  }

  /**
   * Creates an access context from a Vaadin event.
   *
   * @param event the before-enter event
   * @return access context
   */
  public AccessContext create(BeforeEnterEvent event) {
    Map<String, Object> attributes = new LinkedHashMap<>();
    attributes.put("location", event.getLocation());
    attributes.put("path", event.getLocation().getPath());
    attributes.put("target", event.getNavigationTarget());
    return new AccessContext(
        currentJCustosSubject(),
        "vaadin-view",
        event.getNavigationTarget().getSimpleName(),
        "navigate",
        Map.copyOf(attributes));
  }

  /**
   * Builds a {@link JCustosSubject} snapshot for the current
   * Vaadin-session subject so generic evaluators can read roles and
   * permissions from the {@link AccessContext}. Returns
   * {@link Optional#empty()} if no subject is authenticated or the
   * security services are not (yet) wired.
   */
  @SuppressWarnings({"rawtypes", "unchecked"})
  private static Optional<JCustosSubject> currentJCustosSubject() {
    Class subjectType;
    try {
      AuthenticationService<?, ?> authentication = JCustosServiceResolver.authenticationService();
      if (authentication == null) return Optional.empty();
      subjectType = authentication.subjectType();
      if (subjectType == null) return Optional.empty();
    } catch (RuntimeException e) {
      return Optional.empty();
    }
    Optional<Object> subjectOpt = SubjectStores.subjectStore().currentSubject(subjectType);
    if (subjectOpt.isEmpty()) return Optional.empty();
    Object subject = subjectOpt.get();

    AuthorizationService<Object> authorization;
    try {
      authorization = JCustosServiceResolver.authorizationService();
      if (authorization == null) return Optional.empty();
    } catch (RuntimeException e) {
      return Optional.empty();
    }

    Set<RoleName> roles;
    Set<PermissionName> permissions;
    try {
      roles = authorization.rolesFor(subject).roleNames().stream()
          .collect(Collectors.toUnmodifiableSet());
      permissions = authorization.permissionsFor(subject).permissionNames().stream()
          .collect(Collectors.toUnmodifiableSet());
    } catch (RuntimeException e) {
      return Optional.empty();
    }

    String subjectId = subjectIdOf(subject);
    return Optional.of(new JCustosSubject(subjectId, subjectId, roles, permissions));
  }

  /**
   * JS-SEC-083 (CWE-778, CWE-532): the subject id of {@code AccessGranted} /
   * {@code AccessDenied} / {@code StepUpChallenged} must correlate with
   * {@code LoginSucceeded} and {@code SessionExpired}, which already go through the
   * registered {@link SubjectIdResolver} (JS-SEC-004); an identity hash changes per
   * object. The display name is the same value - never {@code subject.toString()},
   * the PII source every evaluator would otherwise see in its {@code AccessContext}.
   * Without a resolver (or with a blank result) the non-PII identity handle remains.
   */
  private static String subjectIdOf(Object subject) {
    Optional<SubjectIdResolver<Object>> resolver = JCustosServiceResolver.findSubjectIdResolver();
    if (resolver.isPresent()) {
      try {
        String resolved = resolver.get().resolve(subject).value();
        if (resolved != null && !resolved.isBlank()) {
          return resolved;
        }
      } catch (RuntimeException ignored) {
        // fall through to the identity handle
      }
    }
    return subject.getClass().getSimpleName() + "@"
        + Integer.toHexString(System.identityHashCode(subject));
  }
}
