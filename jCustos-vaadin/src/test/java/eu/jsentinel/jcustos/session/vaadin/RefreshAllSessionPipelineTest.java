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

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.impl.StubAuthorizationService;
import eu.jsentinel.jcustos.authorization.vaadin.VaadinSessionSubjectStore;
import eu.jsentinel.jcustos.components.SecuredButton;
import eu.jsentinel.jcustos.components.SecuredVisibility;
import eu.jsentinel.jcustos.components.SecuredVisibility.Requirement;
import com.vaadin.browserless.internal.SessionObjects;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.internal.CurrentInstance;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exit review RF19: {@link SecuredVisibility#refreshAll(UI)} evaluated the bindings against the
 * subject of the calling thread's session, not against the subject of {@code ui}'s session. An
 * administrator's request that took a user's session lock and refreshed that user's UI showed
 * the user the controls of the administrator's roles. Two sessions of a real
 * {@code VaadinServletService} with session-backed subjects; no mocking framework.
 */
@DisplayName("RF19 - refreshAll(ui) decides on the subject of ui's session, not the caller's")
class RefreshAllSessionPipelineTest {

  private static final RoleName ADMIN = new RoleName("ADMIN");

  private RequestPipeline pipeline;
  /** Strong reference: Vaadin's CurrentInstance holds sessions weakly. */
  private VaadinSession userSession;
  private SessionObjects admin;
  private final VaadinSessionSubjectStore subjects = new VaadinSessionSubjectStore();

  @BeforeEach
  void start() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    StubAuthorizationService.clear();
    SubjectStores.setSubjectStore(subjects);
    StubAuthorizationService.put("bob", Set.of(), Set.of());
    StubAuthorizationService.put("alice", Set.of(ADMIN), Set.of());
    pipeline = RequestPipeline.start(Clock.systemUTC(), UserView.class);
    userSession = pipeline.session();
    subjects.setCurrentSubject("bob", String.class);
  }

  @AfterEach
  void stop() {
    try {
      CurrentInstance.clearAll();
      pipeline.close();
    } finally {
      JCustosServiceResolver.resetAll();
      SubjectStores.reset();
      StubAuthorizationService.clear();
    }
  }

  @Test
  @DisplayName("an administrator's request refreshes bob's UI: bob's controls follow bob's roles")
  void refreshFromAnotherSession_usesTheUisSubject() {
    UserView view = pipeline.navigate(UserView.class);
    UI userUi = pipeline.ui();
    assertFalse(view.delete.isEnabled(), "precondition: bob does not hold the role");
    admin = pipeline.newSession();
    pipeline.releaseLock();
    actAs(admin);
    subjects.setCurrentSubject("alice", String.class);
    assertTrue(subjects.currentSubject(String.class).isPresent(),
        "precondition: the administrator's request runs with alice's session current");

    // the administrator's code takes bob's session lock and refreshes bob's UI
    userSession.getLockInstance().lock();
    try {
      assertEquals(1, SecuredVisibility.refreshAll(userUi));
      assertFalse(view.delete.isEnabled(),
          "evaluated against alice's roles, bob would see the administrator's control");
      assertSame(admin.getSession(), VaadinSession.getCurrent(),
          "the caller's current session is restored afterwards");
    } finally {
      userSession.getLockInstance().unlock();
    }
  }

  @Test
  @DisplayName("without the session lock of ui the refresh is refused")
  void withoutTheLock_refused() {
    pipeline.navigate(UserView.class);
    UI userUi = pipeline.ui();
    pipeline.releaseLock();

    IllegalStateException refused = assertThrows(IllegalStateException.class,
        () -> SecuredVisibility.refreshAll(userUi));

    assertTrue(refused.getMessage().contains("ui.access"), refused.getMessage());
    pipeline.reacquireLock();
  }

  private static void actAs(SessionObjects other) {
    CurrentInstance.clearAll();
    VaadinSession.setCurrent(other.getSession());
    CurrentInstance.set(VaadinRequest.class, other.getRequest());
  }

  @Route("rf19/user")
  public static class UserView extends Div {
    final SecuredButton delete = new SecuredButton("Delete", Requirement.role(ADMIN));

    public UserView() {
      add(delete);
    }
  }
}
