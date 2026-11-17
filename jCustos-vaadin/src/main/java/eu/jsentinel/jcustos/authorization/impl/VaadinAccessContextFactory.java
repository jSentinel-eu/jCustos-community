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

import eu.jsentinel.jcustos.authorization.api.CurrentSubject;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import com.vaadin.flow.router.BeforeEnterEvent;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Creates core {@link AccessContext} instances from Vaadin navigation
 * events.
 * <p>
 * Reads the current authenticated subject (via {@link CurrentSubject}) and
 * adapts it to a {@link JCustosSubject} so generic
 * {@code AuthorizationEvaluator} implementations (such as
 * {@code RequiresRoleEvaluator} and {@code RequiresPermissionEvaluator}
 * shipped in {@code security-core}) see the subject's roles and
 * permissions through {@link AccessContext#subject()}.
 * <p>
 * The legacy {@code RoleBasedAccessEvaluator} family reads the subject
 * directly from the {@code SubjectStore} and is unaffected by this change.
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
   * Builds a {@link JCustosSubject} snapshot for the current Vaadin-session subject so
   * generic evaluators can read roles and permissions from the {@link AccessContext}.
   * Returns {@link Optional#empty()} if no subject is authenticated or the security services
   * are not (yet) wired.
   * <p>
   * JS-SEC-083 / JS-SEC-097 (CWE-778, CWE-532, CWE-1041): the subject id of
   * {@code AccessGranted} / {@code AccessDenied} / {@code StepUpChallenged} comes from
   * {@link CurrentSubject#subjectIdOf(Object)} - the registered {@code SubjectIdResolver},
   * otherwise the identity handle - so it is the id the lifetime listener, the login rotation
   * and the secured components derive for the same subject. The display name is the same
   * value, never {@code subject.toString()}.
   */
  private static Optional<JCustosSubject> currentJCustosSubject() {
    return CurrentSubject.currentJCustosSubject();
  }
}
