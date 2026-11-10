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
package eu.jsentinel.jcustos.credential.propagation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * V00.74 Phase-1 smoke test — composes the four Phase-1 building
 * blocks (TokenCredential / TokenCredentialStore / OutboundTokenStrategy
 * / PassThroughStrategy) end-to-end against the InMemory store.
 * Adapter-specific composition tests live in their own modules.
 */
@DisplayName("V00.74 Phase-1 — InMemory store + PassThroughStrategy end-to-end")
class Phase1SmokeTest {

  private static final OutboundCall CALL =
      new OutboundCall("DocumentClient", "load", "api.example.com", Map.of());

  @Test
  @DisplayName("InMemoryTokenCredentialStore + PassThroughStrategy → Authorization header")
  void bearerEndToEnd() {
    TokenCredentialStore store = new InMemoryTokenCredentialStore();
    // JS-SEC-151: CALL declares the audience "api.example.com"; pass-through forwards only a
    // token that is known to be issued for it.
    BearerToken token = new BearerToken("inbound-bearer-value",
        Optional.empty(), Optional.of("api.example.com"), Optional.empty());
    store.bind(token);

    Optional<HeaderValue> header = PassThroughStrategy.INSTANCE
        .resolve(CALL, store.current());

    HeaderValue h = header.orElseThrow();
    assertEquals("Authorization", h.name());
    assertEquals("Bearer inbound-bearer-value", h.value());

    store.clear();
    assertTrue(store.current().isEmpty());
  }

  @Test
  @DisplayName("Empty store → strategy returns empty (no header sent)")
  void emptyStoreNoHeader() {
    TokenCredentialStore store = new InMemoryTokenCredentialStore();
    assertTrue(PassThroughStrategy.INSTANCE
        .resolve(CALL, store.current()).isEmpty());
  }

  @Test
  @DisplayName("RefreshToken in the store → never forwarded by pass-through")
  void refreshNotForwarded() {
    TokenCredentialStore store = new InMemoryTokenCredentialStore();
    store.bind(new RefreshToken("rt-value", Optional.empty(), Optional.empty(), Optional.empty()));
    assertTrue(PassThroughStrategy.INSTANCE
        .resolve(CALL, store.current()).isEmpty());
  }

  @Test
  @DisplayName("InMemoryTokenCredentialStore is NOT marked thread-safe")
  void inMemoryNotThreadSafe() {
    TokenCredentialStore store = new InMemoryTokenCredentialStore();
    assertFalse(store instanceof ThreadSafeTokenCredentialStore,
        "InMemoryTokenCredentialStore is single-slot single-thread and must not "
            + "claim the ThreadSafe marker (Konzept §6.5).");
  }
}
