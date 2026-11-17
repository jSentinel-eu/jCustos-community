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
package eu.jsentinel.jcustos.session;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R8 (JS-SEC-167, CWE-613): the observable decorator reports every stored change and keeps a
 * failing listener away from the caller. Real stores, hand-written listeners.
 */
@DisplayName("R8 - ObservableJCustosVersionStore")
class ObservableJCustosVersionStoreTest {

  private static final JCustosVersionKey ALICE =
      new JCustosVersionKey(TenantId.DEFAULT, new SubjectId("alice"));

  private final InMemoryJCustosVersionStore backing = new InMemoryJCustosVersionStore();
  private final ObservableJCustosVersionStore store = new ObservableJCustosVersionStore(backing);

  /** A change as a listener saw it, with the version the store held at that moment. */
  record Seen(JCustosVersionKey key, JCustosVersion version, JCustosVersion storedAtNotification) { }

  private final class Recorder implements JCustosVersionChangeListener {
    final List<Seen> seen = new ArrayList<>();

    @Override
    public void onChange(JCustosVersionKey key, JCustosVersion version) {
      seen.add(new Seen(key, version, backing.current(key)));
    }
  }

  @Test
  @DisplayName("increment notifies with the new version, after it is stored")
  void increment_notifiesAfterStoring() {
    Recorder recorder = new Recorder();
    store.addListener(recorder);

    JCustosVersion returned = store.increment(ALICE);

    assertEquals(new JCustosVersion(1), returned);
    assertEquals(List.of(new Seen(ALICE, returned, returned)), recorder.seen,
        "one notification, with the returned version, and the store already holds it");
  }

  @Test
  @DisplayName("reset notifies with INITIAL, after it is stored")
  void reset_notifiesInitial() {
    store.increment(ALICE);
    Recorder recorder = new Recorder();
    store.addListener(recorder);

    store.reset(ALICE);

    assertEquals(List.of(new Seen(ALICE, JCustosVersion.INITIAL, JCustosVersion.INITIAL)), recorder.seen);
  }

  @Test
  @DisplayName("current reads through and notifies nothing")
  void current_notifiesNothing() {
    backing.increment(ALICE);
    Recorder recorder = new Recorder();
    store.addListener(recorder);

    assertEquals(new JCustosVersion(1), store.current(ALICE));
    assertTrue(recorder.seen.isEmpty());
  }

  @Test
  @DisplayName("a listener that throws does not affect increment, and the next listener still hears of it")
  void failingListener_isIsolated() {
    store.addListener((key, version) -> {
      throw new IllegalStateException("listener secret-detail");
    });
    Recorder recorder = new Recorder();
    store.addListener(recorder);

    String log = capturingStdErr(() -> assertEquals(new JCustosVersion(1), store.increment(ALICE)));

    assertEquals(new JCustosVersion(1), backing.current(ALICE), "the change is stored");
    assertEquals(1, recorder.seen.size(), "the second listener is notified");
    assertTrue(log.contains("failed with " + IllegalStateException.class.getName()),
        "the failure is logged; stderr was: " + log);
    assertFalse(log.contains("secret-detail"), "the exception message is not logged: " + log);
  }

  @Test
  @DisplayName("a listener that throws does not affect reset")
  void failingListener_resetStands() {
    store.increment(ALICE);
    store.addListener((key, version) -> {
      throw new IllegalStateException("boom");
    });

    capturingStdErr(() -> store.reset(ALICE));

    assertEquals(JCustosVersion.INITIAL, backing.current(ALICE));
  }

  @Test
  @DisplayName("a change the wrapped store refuses is not reported")
  void refusedChange_notReported() {
    ObservableJCustosVersionStore refusing = new ObservableJCustosVersionStore(new RefusingStore());
    List<JCustosVersionKey> seen = new ArrayList<>();
    refusing.addListener((key, version) -> seen.add(key));

    assertThrows(IllegalStateException.class, () -> refusing.increment(ALICE));
    assertThrows(IllegalStateException.class, () -> refusing.reset(ALICE));

    assertTrue(seen.isEmpty());
  }

  @Test
  @DisplayName("a removed listener hears nothing; a listener registered twice is called once")
  void removeAndDuplicate() {
    Recorder recorder = new Recorder();
    store.addListener(recorder);
    store.addListener(recorder);
    assertEquals(1, store.listenerCount());

    store.increment(ALICE);
    store.removeListener(recorder);
    store.increment(ALICE);

    assertEquals(1, recorder.seen.size());
    assertEquals(0, store.listenerCount());
  }

  @Test
  @DisplayName("null arguments are rejected")
  void nulls() {
    assertThrows(NullPointerException.class, () -> new ObservableJCustosVersionStore(null));
    assertThrows(NullPointerException.class, () -> store.addListener(null));
    assertSame(backing, store.delegate());
  }

  /** A store whose writes always fail - a backend that is down. */
  private static final class RefusingStore implements JCustosVersionStore {
    @Override
    public JCustosVersion current(JCustosVersionKey key) {
      return JCustosVersion.INITIAL;
    }

    @Override
    public JCustosVersion increment(JCustosVersionKey key) {
      throw new IllegalStateException("backend unavailable");
    }

    @Override
    public void reset(JCustosVersionKey key) {
      throw new IllegalStateException("backend unavailable");
    }
  }

  private static String capturingStdErr(Runnable action) {
    PrintStream original = System.err;
    ByteArrayOutputStream captured = new ByteArrayOutputStream();
    System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
    try {
      action.run();
    } finally {
      System.setErr(original);
    }
    return captured.toString(StandardCharsets.UTF_8);
  }
}
