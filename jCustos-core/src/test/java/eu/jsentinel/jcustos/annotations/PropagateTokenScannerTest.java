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
package eu.jsentinel.jcustos.annotations;

import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.impl.JCustosAnnotationScanner;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code @PropagateToken} is bound through {@code @JCustosAnnotation} to a token-propagation
 * advisor, not to an evaluator. The restriction scanner therefore does not take it for a
 * restriction (since 00.84.00): it neither restricts an element on its own nor counts as a
 * second restriction next to a real one. The propagation paths read the annotation directly.
 */
@DisplayName("@PropagateToken — not a restriction for the scanner")
class PropagateTokenScannerTest {

  private final JCustosAnnotationScanner scanner = new JCustosAnnotationScanner();

  @Test
  @DisplayName("Class-level @PropagateToken is no restriction, but stays readable")
  void classLevelIsNoRestriction() {
    assertTrue(scanner.scan(ClassLevelClient.class).isEmpty());
    assertEquals("pass-through",
        ClassLevelClient.class.getAnnotation(PropagateToken.class).strategy());
  }

  @Test
  @DisplayName("Method-level @PropagateToken is no restriction, but stays readable")
  void methodLevelIsNoRestriction() throws NoSuchMethodException {
    Method method = MethodLevelClient.class.getMethod("archive", String.class);
    assertTrue(scanner.scan(method).isEmpty());
    PropagateToken ann = method.getAnnotation(PropagateToken.class);
    assertEquals("exchange", ann.strategy());
    assertEquals("api.example.com", ann.audience());
  }

  @Test
  @DisplayName("A restriction next to @PropagateToken is found, and is the only one")
  void restrictionNextToPropagateTokenIsFound() throws NoSuchMethodException {
    var classLevel = scanner.scan(GuardedClient.class).orElseThrow();
    assertTrue(classLevel.annotation() instanceof RequiresRole);
    Method method = GuardedClient.class.getMethod("load", String.class);
    var methodLevel = scanner.scan(method, GuardedClient.class).orElseThrow();
    assertEquals("ADMIN", ((RequiresRole) methodLevel.annotation()).value()[0]);
  }

  @Test
  @DisplayName("Class without @PropagateToken returns empty")
  void notAnnotated() {
    assertTrue(scanner.scan(NotAnnotated.class).isEmpty());
  }

  @PropagateToken
  interface ClassLevelClient {
    String load(String id);
  }

  interface MethodLevelClient {
    String load(String id);

    @PropagateToken(strategy = "exchange", audience = "api.example.com")
    void archive(String id);
  }

  @PropagateToken
  @RequiresRole("USER")
  interface GuardedClient {
    @PropagateToken(strategy = "exchange", audience = "api.example.com")
    @RequiresRole("ADMIN")
    String load(String id);
  }

  interface NotAnnotated {
    String load(String id);
  }
}
