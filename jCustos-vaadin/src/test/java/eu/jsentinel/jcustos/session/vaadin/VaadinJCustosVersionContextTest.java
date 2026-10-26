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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.JCustosVersion;
import com.vaadin.flow.internal.CurrentInstance;
import com.vaadin.flow.server.VaadinSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("VaadinJCustosVersionContext")
class VaadinJCustosVersionContextTest {

  /**
   * Strong reference to the session bound by {@link #bindSession()} —
   * {@code CurrentInstance} only holds a {@code WeakReference}, so without it
   * a GC pause can make {@code VaadinSession.getCurrent()} return {@code null}.
   */
  private InMemoryVaadinSession boundSession;

  private static final SubjectId ALICE = new SubjectId("alice");

  @BeforeEach
  void clear() {
    CurrentInstance.clearAll();
  }

  @AfterEach
  void teardown() {
    CurrentInstance.clearAll();
  }

  @Test
  @DisplayName("record + current round-trip on the bound session")
  void roundTripOnBoundSession() {
    InMemoryVaadinSession session = bindSession();

    VaadinJCustosVersionContext.record(
        ALICE, TenantId.DEFAULT, new JCustosVersion(7L), "sid-1");

    Optional<VaadinJCustosVersionContext.Snapshot> snap =
        VaadinJCustosVersionContext.current();
    assertTrue(snap.isPresent());
    assertEquals(ALICE, snap.get().subjectId());
    assertEquals(TenantId.DEFAULT, snap.get().tenant());
    assertEquals(new JCustosVersion(7L), snap.get().snapshot());
    assertEquals("sid-1", snap.get().sessionId());
  }

  @Test
  @DisplayName("record without a bound session is a safe no-op")
  void recordWithoutSessionIsNoOp() {
    VaadinJCustosVersionContext.record(ALICE, TenantId.DEFAULT,
        JCustosVersion.INITIAL, "sid-x");
    assertTrue(VaadinJCustosVersionContext.current().isEmpty());
  }

  @Test
  @DisplayName("current on a session without snapshot returns empty")
  void emptyOnFreshSession() {
    bindSession();
    assertTrue(VaadinJCustosVersionContext.current().isEmpty());
  }

  @Test
  @DisplayName("null tenant normalises to DEFAULT")
  void nullTenantBecomesDefault() {
    bindSession();
    VaadinJCustosVersionContext.record(ALICE, null,
        JCustosVersion.INITIAL, "sid");
    assertEquals(TenantId.DEFAULT,
        VaadinJCustosVersionContext.current().orElseThrow().tenant());
  }

  @Test
  @DisplayName("record on an explicit session writes to that session")
  void recordOnExplicitSession() {
    InMemoryVaadinSession session = new InMemoryVaadinSession();
    VaadinJCustosVersionContext.record(session, ALICE, TenantId.DEFAULT,
        new JCustosVersion(3L), null);

    Optional<VaadinJCustosVersionContext.Snapshot> snap =
        VaadinJCustosVersionContext.current(session);
    assertTrue(snap.isPresent());
    assertEquals(new JCustosVersion(3L), snap.get().snapshot());
    // The current thread has no bound session — global lookup must be empty
    assertTrue(VaadinJCustosVersionContext.current().isEmpty());
  }

  @Test
  @DisplayName("clear removes the recorded snapshot")
  void clearRemovesSnapshot() {
    bindSession();
    VaadinJCustosVersionContext.record(ALICE, TenantId.DEFAULT,
        JCustosVersion.INITIAL, "sid");
    assertTrue(VaadinJCustosVersionContext.current().isPresent());

    VaadinJCustosVersionContext.clear();
    assertTrue(VaadinJCustosVersionContext.current().isEmpty());

    // clear without a snapshot or without a bound session is a no-op
    VaadinJCustosVersionContext.clear();
    CurrentInstance.clearAll();
    VaadinJCustosVersionContext.clear();
  }

  @Test
  @DisplayName("null arguments are rejected by the session-explicit overload")
  void rejectNulls() {
    InMemoryVaadinSession session = bindSession();
    assertThrows(NullPointerException.class, () -> VaadinJCustosVersionContext.record(
        (VaadinSession) null, ALICE, TenantId.DEFAULT, JCustosVersion.INITIAL, "sid"));
    assertThrows(NullPointerException.class, () -> VaadinJCustosVersionContext.record(
        session, null, TenantId.DEFAULT, JCustosVersion.INITIAL, "sid"));
    assertThrows(NullPointerException.class, () -> VaadinJCustosVersionContext.record(
        session, ALICE, TenantId.DEFAULT, null, "sid"));
    assertThrows(NullPointerException.class,
        () -> new VaadinJCustosVersionContext.Snapshot(null, TenantId.DEFAULT,
            JCustosVersion.INITIAL, "sid"));
  }

  private InMemoryVaadinSession bindSession() {
    InMemoryVaadinSession session = new InMemoryVaadinSession();
    boundSession = session;
    VaadinSession.setCurrent(session);
    assertSame(session, VaadinSession.getCurrent());
    return session;
  }

  /** Mirrors the {@code VaadinSessionSubjectStoreTest} pattern. */
  static final class InMemoryVaadinSession extends VaadinSession {
    private final Map<Object, Object> attributes = new HashMap<>();

    InMemoryVaadinSession() {
      super(null);
    }

    @Override
    public void setAttribute(String name, Object value) {
      if (value == null) attributes.remove(name); else attributes.put(name, value);
    }

    @Override
    public <T> void setAttribute(Class<T> type, T value) {
      if (value == null) attributes.remove(type); else attributes.put(type, value);
    }

    @Override
    public Object getAttribute(String name) {
      return attributes.get(name);
    }

    @Override
    public <T> T getAttribute(Class<T> type) {
      return type.cast(attributes.get(type));
    }
  }
}
