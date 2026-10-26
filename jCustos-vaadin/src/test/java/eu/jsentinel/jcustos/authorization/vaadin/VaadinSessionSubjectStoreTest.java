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
package eu.jsentinel.jcustos.authorization.vaadin;

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

@DisplayName("VaadinSessionSubjectStore")
class VaadinSessionSubjectStoreTest {

  /**
   * Strong reference to the session bound by {@link #bindSession()} —
   * {@code CurrentInstance} only holds a {@code WeakReference}, so without it
   * a GC pause can make {@code VaadinSession.getCurrent()} return {@code null}.
   */
  private InMemoryVaadinSession boundSession;

  private final VaadinSessionSubjectStore store = new VaadinSessionSubjectStore();

  @BeforeEach
  void clear() {
    CurrentInstance.clearAll();
  }

  @AfterEach
  void teardown() {
    CurrentInstance.clearAll();
  }

  // ── No active session ─────────────────────────────────────────

  @Test
  @DisplayName("currentSubject returns empty when no VaadinSession is bound")
  void currentSubject_noSession() {
    assertTrue(store.currentSubject(String.class).isEmpty());
  }

  @Test
  @DisplayName("setCurrentSubject without an active session throws")
  void setCurrentSubject_noSession_throws() {
    assertThrows(NullPointerException.class,
        () -> store.setCurrentSubject("alice", String.class));
  }

  @Test
  @DisplayName("setCurrentSubject rejects null subject")
  void setCurrentSubject_rejectsNullSubject() {
    bindSession();
    assertThrows(NullPointerException.class,
        () -> store.setCurrentSubject(null, String.class));
  }

  @Test
  @DisplayName("deleteCurrentSubject without an active session is a safe no-op")
  void deleteCurrentSubject_noSession_isNoOp() {
    store.deleteCurrentSubject(String.class);
  }

  // ── Active session ────────────────────────────────────────────

  @Test
  @DisplayName("setCurrentSubject + currentSubject round-trip stores by class type")
  void roundTrip() {
    InMemoryVaadinSession session = bindSession();

    store.setCurrentSubject("alice", String.class);
    Optional<String> resolved = store.currentSubject(String.class);

    assertTrue(resolved.isPresent());
    assertEquals("alice", resolved.get());
  }

  @Test
  @DisplayName("currentSubject returns empty for an unset class type")
  void currentSubject_unsetType_returnsEmpty() {
    bindSession();
    assertTrue(store.currentSubject(String.class).isEmpty());
  }

  @Test
  @DisplayName("deleteCurrentSubject with active session removes the stored subject")
  void deleteCurrentSubject_activeSession_removes() {
    bindSession();
    store.setCurrentSubject("alice", String.class);

    store.deleteCurrentSubject(String.class);

    assertTrue(store.currentSubject(String.class).isEmpty());
  }

  @Test
  @DisplayName("subjects keyed by different class types do not collide")
  void differentClassTypesAreIndependent() {
    bindSession();
    store.setCurrentSubject("alice", String.class);
    store.setCurrentSubject(42, Integer.class);

    assertEquals("alice", store.currentSubject(String.class).orElseThrow());
    assertEquals(42, store.currentSubject(Integer.class).orElseThrow());
  }

  @Test
  @DisplayName("hasSubject default reflects setCurrentSubject + deleteCurrentSubject")
  void hasSubjectReflectsRoundTrip() {
    bindSession();
    assertTrue(!store.hasSubject(String.class));

    store.setCurrentSubject("alice", String.class);
    assertTrue(store.hasSubject(String.class));

    store.deleteCurrentSubject(String.class);
    assertTrue(!store.hasSubject(String.class));
  }

  // ── Helpers ───────────────────────────────────────────────────

  private InMemoryVaadinSession bindSession() {
    InMemoryVaadinSession session = new InMemoryVaadinSession();
    boundSession = session;
    VaadinSession.setCurrent(session);
    assertSame(session, VaadinSession.getCurrent(),
        "precondition: stub session should be bound to the current thread");
    return session;
  }

  /**
   * In-memory {@link VaadinSession} stub — overrides every attribute
   * accessor to read/write a {@code Map}, so the production code path
   * (setAttribute / getAttribute / null-check) executes without touching
   * Vaadin's actual session machinery.
   */
  private static final class InMemoryVaadinSession extends VaadinSession {
    private final Map<Object, Object> attributes = new HashMap<>();

    private InMemoryVaadinSession() {
      super(null);
    }

    @Override
    public void setAttribute(String name, Object value) {
      if (value == null) attributes.remove(name);
      else attributes.put(name, value);
    }

    @Override
    public <T> void setAttribute(Class<T> type, T value) {
      if (value == null) attributes.remove(type);
      else attributes.put(type, value);
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
