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
package eu.jsentinel.jcustos.components;

import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.permissions.HasPermissions;
import eu.jsentinel.jcustos.authorization.api.roles.HasRoles;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-097 (CWE-1041, CWE-636): the SPI-backed lookup of {@link SecuredVisibility} goes
 * through {@code CurrentSubject.currentJCustosSubject()}. Roles and permissions are resolved
 * before the view is handed out, so an {@code AuthorizationService} that fails denies the
 * affordance. Until 00.84.00 the view resolved them lazily inside {@code isAllowed}, and the
 * failure escaped from {@code apply(...)} - and from the constructor of every secured
 * component.
 */
@DisplayName("JS-SEC-097 - SecuredVisibility resolves the subject through CurrentSubject")
class SecuredVisibilitySubjectLookupTest {

  private static final RoleName ADMIN = new RoleName("ADMIN");

  private final InMemorySubjectStore subjects = new InMemorySubjectStore();

  @BeforeEach
  void wire() {
    JCustosServiceResolver.resetAll();
    SubjectStores.setSubjectStore(subjects);
    subjects.setCurrentSubject("alice", String.class);
    JCustosServiceResolver.setAuthenticationService(FakeAuthenticationService.forType(String.class));
  }

  @AfterEach
  void reset() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("control: an authorised subject is admitted through the SPI lookup")
  void authorisedSubject_admitted() {
    JCustosServiceResolver.setAuthorizationService(
        new FakeAuthorizationService<String>().putRoles("alice", Set.of(ADMIN)));
    SecuredVisibilityTest.RecordingTarget target = new SecuredVisibilityTest.RecordingTarget();
    target.visible = false;

    SecuredVisibility.apply(target, SecuredVisibility.Requirement.role(ADMIN), SecuredVisibilityMode.HIDE);

    assertTrue(target.visible);
  }

  @Test
  @DisplayName("a failing AuthorizationService denies the affordance instead of escaping from apply()")
  void failingAuthorization_denies() {
    JCustosServiceResolver.setAuthorizationService(new FailingAuthorization());
    SecuredVisibilityTest.RecordingTarget target = new SecuredVisibilityTest.RecordingTarget();

    assertDoesNotThrow(() -> SecuredVisibility.apply(target,
        SecuredVisibility.Requirement.role(ADMIN), SecuredVisibilityMode.HIDE));

    assertFalse(target.visible, "no role view, no affordance");
  }

  @Test
  @DisplayName("a secured button over a failing AuthorizationService is built disabled, not thrown")
  void failingAuthorization_securedButtonDisabled() {
    JCustosServiceResolver.setAuthorizationService(new FailingAuthorization());

    SecuredButton button = assertDoesNotThrow(
        () -> new SecuredButton("Delete", SecuredVisibility.Requirement.role(ADMIN)));

    assertTrue(button.isVisible());
    assertFalse(button.isEnabled());
  }

  private static final class FailingAuthorization implements AuthorizationService<String> {
    @Override
    public HasRoles rolesFor(String subject) {
      throw new IllegalStateException("role backend unreachable");
    }

    @Override
    public HasPermissions permissionsFor(String subject) {
      throw new IllegalStateException("permission backend unreachable");
    }
  }
}
