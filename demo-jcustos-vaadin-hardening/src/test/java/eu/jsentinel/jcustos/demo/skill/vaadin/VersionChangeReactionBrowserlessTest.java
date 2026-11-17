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
package eu.jsentinel.jcustos.demo.skill.vaadin;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap.JCustosBootstrapInitListener;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.User;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.services.VersionBumper;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.JCustosVersionStore;
import eu.jsentinel.jcustos.session.ObservableJCustosVersionStore;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.VaadinService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * R8 (JS-SEC-167) and JS-SEC-168: the hardening layer registers its version store as an
 * {@link ObservableJCustosVersionStore}, {@link VersionBumper} bumps through it, and the
 * starter's one-call service initialisation in the layer-1 listener subscribes the bridge that
 * ends the user's open session at once. The end-to-end reaction of the bridge is shown in
 * jCustos-vaadin ({@code VaadinJCustosVersionChangeBridgePipelineTest}).
 */
@DisplayName("R8 - hardening demo: the version store is observable and the bumper goes through it")
class VersionChangeReactionBrowserlessTest extends BrowserlessTest {

  private static final User ALICE = new User(4711L, "alice", Set.of());

  @BeforeAll
  static void isolateStorage() {
    TestDirectories.isolateStorage();
  }

  @BeforeEach
  void setUp() {
    SkillDemoTestSupport.runDemoBootstrap();
  }

  @AfterEach
  void tearDown() {
    UserDirectoryProvider.setDirectory(TestDirectories.fresh());
    JCustosServiceResolver.resetAll();
  }

  private static ObservableJCustosVersionStore registeredStore() {
    JCustosVersionStore store = JCustosServiceResolver.findJCustosVersionStore().orElseThrow();
    return assertInstanceOf(ObservableJCustosVersionStore.class, store,
        "HardeningBootstrapExtension registers the store wrapped in the observable decorator");
  }

  @Test
  @DisplayName("VersionBumper's increment reaches the listeners of the registered store")
  void bump_isObservable() {
    ObservableJCustosVersionStore store = registeredStore();
    List<JCustosVersionKey> heard = new ArrayList<>();
    store.addListener((key, version) -> heard.add(key));

    long bumped = VersionBumper.bump(ALICE).orElseThrow();

    JCustosVersionKey key = new JCustosVersionKey(TenantId.DEFAULT, new SubjectId("4711"));
    assertEquals(List.of(key), heard);
    assertEquals(new JCustosVersion(bumped), store.current(key));
  }

  @Test
  @DisplayName("the layer-1 listener's service init subscribes the bridge to the demo's store")
  void serviceInit_subscribesTheBridge() {
    ObservableJCustosVersionStore store = registeredStore();
    int before = store.listenerCount();

    new JCustosBootstrapInitListener().serviceInit(new ServiceInitEvent(VaadinService.getCurrent()));

    assertEquals(before + 1, store.listenerCount(), "VaadinJCustosStarter.serviceInit installs the bridge");
  }
}
