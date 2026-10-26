/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.credential.propagation.vaadin;

import eu.jsentinel.jcustos.credential.propagation.BearerToken;
import eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore;
import com.vaadin.flow.internal.CurrentInstance;
import com.vaadin.flow.server.VaadinSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("VaadinSessionTokenCredentialStore")
class VaadinSessionTokenCredentialStoreTest {

  /**
   * Strong reference to the session bound by {@link #bindSession()} —
   * {@code CurrentInstance} only holds a {@code WeakReference}, so without it
   * a GC pause can make {@code VaadinSession.getCurrent()} return {@code null}.
   */
  private InMemoryVaadinSession boundSession;

  private final TokenCredentialStore store = new VaadinSessionTokenCredentialStore();

  @BeforeEach
  void clear() { CurrentInstance.clearAll(); }

  @AfterEach
  void teardown() { CurrentInstance.clearAll(); }

  @Test
  @DisplayName("current() returns empty without an active session")
  void currentNoSession() {
    assertTrue(store.current().isEmpty());
  }

  @Test
  @DisplayName("bind without an active session throws IllegalStateException")
  void bindNoSessionThrows() {
    assertThrows(IllegalStateException.class,
        () -> store.bind(new BearerToken("abc")));
  }

  @Test
  @DisplayName("bind / current / clear cycle round-trips inside a session")
  void roundTripInsideSession() {
    InMemoryVaadinSession session = bindSession();
    BearerToken token = new BearerToken("abc");

    store.bind(token);
    assertEquals(token, store.current().orElseThrow());

    store.clear();
    assertTrue(store.current().isEmpty());
    assertNull(session.getAttribute(VaadinSessionTokenCredentialStore.ATTR_KEY));
  }

  @Test
  @DisplayName("Re-bind replaces the previous entry")
  void rebindReplaces() {
    bindSession();
    store.bind(new BearerToken("first"));
    store.bind(new BearerToken("second"));
    assertEquals("second", ((BearerToken) store.current().orElseThrow()).value());
  }

  @Test
  @DisplayName("clear without an active session is a no-op")
  void clearNoSession() {
    store.clear();
  }

  private InMemoryVaadinSession bindSession() {
    InMemoryVaadinSession session = new InMemoryVaadinSession();
    boundSession = session;
    VaadinSession.setCurrent(session);
    assertSame(session, VaadinSession.getCurrent());
    return session;
  }

  private static final class InMemoryVaadinSession extends VaadinSession {
    private final Map<Object, Object> attributes = new HashMap<>();

    InMemoryVaadinSession() { super(null); }

    @Override public void setAttribute(String name, Object value) {
      if (value == null) attributes.remove(name); else attributes.put(name, value);
    }
    @Override public Object getAttribute(String name) {
      return attributes.get(name);
    }
  }
}
