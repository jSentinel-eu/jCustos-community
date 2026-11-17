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
package eu.jsentinel.jcustos.starter.ui;

import eu.jsentinel.jcustos.authorization.api.CurrentSubject;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.components.SecuredVisibility;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.policy.api.Policy;
import eu.jsentinel.jcustos.policy.impl.InMemoryPolicyRegistry;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import com.vaadin.flow.component.html.Div;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-097 (CWE-1041, CWE-532), acceptance of ER30, starter half: the same subject yields
 * the same subject id in the policy context of {@code SecuredUi.requiresPolicy(...)} as
 * {@link CurrentSubject#subjectIdOf(Object)} - with a registered {@code SubjectIdResolver} the
 * resolver value, without one the identity handle - and {@link SecuredVisibility} decides on
 * that subject's roles. Neither carries the subject's {@code toString()}. Since exit review
 * RF17 the view of {@code SecuredVisibility} carries no subject id: no requirement reads one.
 * <p>
 * The navigation context, the session-lifetime listener and the login rotation are compared
 * with {@code SecuredVisibility} and {@code CurrentSubject} in jCustos-vaadin's
 * {@code SubjectIdParityTest}: a {@code UI} and a {@code VaadinSession} need the servlet API,
 * which the starter's test classpath does not carry.
 * <p>
 * Until 00.84.00 the policy context fell back to {@code String.valueOf(user)}, so the
 * password in this subject's {@code toString()} reached every policy as its subject id.
 */
@DisplayName("JS-SEC-097 - one subject id in secured components and policies")
class SubjectIdParityTest {

  private static final String SECRET = "pw-SECRET-4711";
  private static final String POLICY = "er30-parity";

  /** An application user whose toString() carries a credential - the leak shape. */
  record PiiUser(String email, String password) {
    @Override
    public String toString() {
      return "PiiUser[email=" + email + ", password=" + password + "]";
    }
  }

  private final PiiUser alice = new PiiUser("alice@example.test", SECRET);
  private final List<JCustosSubject> policySubjects = new ArrayList<>();

  @BeforeEach
  void wireSecurity() {
    JCustosServiceResolver.resetAll();
    InMemorySubjectStore subjects = new InMemorySubjectStore();
    SubjectStores.setSubjectStore(subjects);
    subjects.setCurrentSubject(alice, PiiUser.class);
    JCustosServiceResolver.setAuthenticationService(FakeAuthenticationService.forType(PiiUser.class));
    FakeAuthorizationService<PiiUser> authorization = new FakeAuthorizationService<>();
    authorization.putRoles(alice, Set.of(new RoleName("ADMIN")));
    JCustosServiceResolver.setAuthorizationService(authorization);

    InMemoryPolicyRegistry policies = new InMemoryPolicyRegistry();
    policies.register(Policy.named(POLICY)
        .allowIf(context -> {
          context.subject().ifPresent(policySubjects::add);
          return true;
        })
        .build());
    JCustosServiceResolver.setPolicyRegistry(policies);
  }

  @AfterEach
  void resetSecurity() {
    JCustosServiceResolver.resetAll();
  }

  @ParameterizedTest(name = "resolver registered: {0}")
  @ValueSource(booleans = {true, false})
  @DisplayName("the policy context derives the subject id of CurrentSubject; SecuredVisibility sees the same subject")
  void sameSubjectIdEverywhere(boolean withResolver) {
    if (withResolver) {
      JCustosServiceResolver.<PiiUser>setSubjectIdResolver(user -> SubjectId.of("user-7"));
    }
    String expected = withResolver
        ? "user-7"
        : PiiUser.class.getSimpleName() + "@" + Integer.toHexString(System.identityHashCode(alice));

    Map<String, String> ids = new LinkedHashMap<>();
    Map<String, String> displayNames = new LinkedHashMap<>();

    // 1. the view SecuredButton / SecuredRouterLink / SecuredMenuItem decide on: the roles of
    // the facade's subject, without a subject id since RF17
    SecuredVisibility.JCustosView view = SecuredVisibility.currentJCustosView().orElseThrow();
    CurrentSubject.RolesAndPermissions secured = assertInstanceOf(
        CurrentSubject.RolesAndPermissions.class, view.roles(),
        "the components decide on the facade's subject");
    assertEquals(Set.of(new RoleName("ADMIN")), secured.roles());

    // 2. the context a policy of SecuredUi.requiresPolicy(...) sees
    Div guarded = SecuredUi.component(new Div()).requiresPolicy(POLICY).bind();
    assertTrue(guarded.isVisible(), "precondition: the policy ran and allowed");
    JCustosSubject policy = policySubjects.getFirst();
    ids.put("PolicyVisibility", policy.subjectId());
    displayNames.put("PolicyVisibility", policy.displayName());

    ids.forEach((site, id) -> assertEquals(expected, id, site + " derived a different subject id"));
    displayNames.forEach((site, name) -> assertEquals(expected, name,
        site + ": the display name is the subject id, never toString()"));
    assertEquals(expected, CurrentSubject.subjectIdOf(alice));
    for (Object subject : List.of(secured, policy)) {
      assertFalse(subject.toString().contains(SECRET), "the credential in toString() leaked: " + subject);
      assertFalse(subject.toString().contains("alice@example.test"), "the e-mail leaked: " + subject);
    }
  }
}
