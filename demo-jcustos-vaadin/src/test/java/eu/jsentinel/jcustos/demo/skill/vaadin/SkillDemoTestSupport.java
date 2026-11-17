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
import eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap.JCustosBootstrapInitListener;
import com.vaadin.browserless.internal.MockVaadin;
import com.vaadin.browserless.mocks.MockHttpSession;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinService;
import com.vaadin.flow.server.VaadinServletService;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.WrappedHttpSession;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/**
 * Shared helpers of the demo's browserless tests. No mocks: the demo's own bootstrap
 * listener, views and stores run against a real {@code VaadinServletService} of the
 * browserless harness.
 */
public final class SkillDemoTestSupport {

  private SkillDemoTestSupport() {
  }

  /**
   * Runs the demo's real bootstrap chain - {@link JCustosBootstrapInitListener} with every
   * registered {@code BootstrapExtension} - on a freshly reset resolver. The listener runs
   * once per JVM in production; the test resets that guard so every test starts from the
   * configuration the application ships with. Call it with a current
   * {@code VaadinService} (inside a browserless test), so the route checks see the
   * registered routes.
   */
  public static void runDemoBootstrap() {
    try {
      var done = JCustosBootstrapInitListener.class.getDeclaredField("DONE");
      done.setAccessible(true);
      ((AtomicBoolean) done.get(null)).set(false);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError("cannot reset the bootstrap guard: " + e);
    }
    JCustosServiceResolver.resetAll();
    // the bootstrap only; the per-service part ran when the browserless service started
    JCustosBootstrapInitListener.bootstrapOnce();
  }

  /**
   * Another browser's session of the same service, as the servlet container leaves it
   * between two requests: registered, unlocked, known to the session-init listeners.
   */
  public static VaadinSession openSecondSession() {
    VaadinServletService service = (VaadinServletService) VaadinService.getCurrent();
    MockHttpSession http = MockHttpSession.Companion.create(service.getServlet().getServletContext());
    VaadinSession session = new VaadinSession(service);
    ReentrantLock lock = new ReentrantLock();
    lock.lock();
    try {
      http.setAttribute(service.getServiceName() + ".lock", lock);
      http.setAttribute(VaadinSession.class.getName() + "." + service.getServiceName(), session);
      session.refreshTransients(new WrappedHttpSession(http), service);
      MockVaadin.fireSessionInit(service, session, VaadinRequest.getCurrent());
    } finally {
      lock.unlock();
    }
    return session;
  }

  /** Reads or writes state of a session under that session's lock. */
  public static <T> T inSession(VaadinSession session, Supplier<T> action) {
    session.getLockInstance().lock();
    try {
      return action.get();
    } finally {
      session.getLockInstance().unlock();
    }
  }
}
