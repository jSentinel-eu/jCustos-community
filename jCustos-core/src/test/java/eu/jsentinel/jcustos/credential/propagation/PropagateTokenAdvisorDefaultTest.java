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

import eu.jsentinel.jcustos.annotations.PropagateToken;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("PropagateTokenAdvisor.Default")
class PropagateTokenAdvisorDefaultTest {

  private static final OutboundCall CALL =
      new OutboundCall("DocumentClient", "load", "api.example.com", Map.of());

  private final TokenCredentialStore store = new InMemoryTokenCredentialStore();

  @BeforeEach
  void resetStrategies() { JCustosServiceResolver.resetAll(); }

  @AfterEach
  void cleanup() { JCustosServiceResolver.resetAll(); store.clear(); }

  @Test
  @DisplayName("Registered pass-through strategy + bearer token → Authorization header")
  void registeredStrategyHappyPath() {
    JCustosServiceResolver.registerOutboundTokenStrategy(
        PassThroughStrategy.NAME, PassThroughStrategy.INSTANCE);
    // JS-SEC-151: CALL declares the audience "api.example.com"; pass-through forwards only a
    // token that is known to be issued for it.
    store.bind(new BearerToken("abc", Optional.empty(), Optional.of("api.example.com"), Optional.empty()));

    Optional<HeaderValue> h = PropagateTokenAdvisor.Default.INSTANCE
        .adviseFor(annotation("pass-through", "", "", ""), CALL, store);
    assertEquals("Authorization", h.orElseThrow().name());
    assertEquals("Bearer abc", h.orElseThrow().value());
  }

  @Test
  @DisplayName("Unregistered strategy → empty, no exception")
  void unregisteredStrategyReturnsEmpty() {
    store.bind(new BearerToken("abc"));
    Optional<HeaderValue> h = PropagateTokenAdvisor.Default.INSTANCE
        .adviseFor(annotation("exchange", "", "", ""), CALL, store);
    assertTrue(h.isEmpty());
  }

  @Test
  @DisplayName("Empty store + registered strategy → empty")
  void emptyStoreReturnsEmpty() {
    JCustosServiceResolver.registerOutboundTokenStrategy(
        PassThroughStrategy.NAME, PassThroughStrategy.INSTANCE);
    Optional<HeaderValue> h = PropagateTokenAdvisor.Default.INSTANCE
        .adviseFor(annotation("pass-through", "", "", ""), CALL, store);
    assertTrue(h.isEmpty());
  }

  @Test
  @DisplayName("header() override rewrites the header name, value preserved")
  void headerOverride() {
    JCustosServiceResolver.registerOutboundTokenStrategy(
        PassThroughStrategy.NAME, PassThroughStrategy.INSTANCE);
    // JS-SEC-151: CALL declares the audience "api.example.com"; pass-through forwards only a
    // token that is known to be issued for it.
    store.bind(new BearerToken("abc", Optional.empty(), Optional.of("api.example.com"), Optional.empty()));

    Optional<HeaderValue> h = PropagateTokenAdvisor.Default.INSTANCE
        .adviseFor(annotation("pass-through", "", "X-Service-Token", ""), CALL, store);
    assertEquals("X-Service-Token", h.orElseThrow().name());
    assertEquals("Bearer abc", h.orElseThrow().value());
  }

  private static PropagateToken annotation(String strategy, String audience,
                                            String header, String service) {
    return new PropagateToken() {
      @Override public Class<? extends Annotation> annotationType() { return PropagateToken.class; }
      @Override public String strategy() { return strategy; }
      @Override public String audience() { return audience; }
      @Override public String header() { return header; }
      @Override public String service() { return service; }
    };
  }
}
