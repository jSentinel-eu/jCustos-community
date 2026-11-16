/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.dx.runtime;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase-1 end-to-end smoke (Konzept-V00.74.10 §4.2 / Implementierungsplan
 * Prompt 007). Builds a representative {@link JCustosRuntime} snapshot,
 * exercises all four V00.74.10 tooling methods together, and uses Jackson
 * (test-scope only) as an independent JSON parser to cross-validate that
 * {@link JCustosRuntime#toJson()} agrees structurally with
 * {@link JCustosRuntime#toMap()}.
 * <p>
 * Jackson is permitted on test scope only — the Maven Enforcer rule in
 * {@code jCustos-dx/pom.xml} blocks it on compile / runtime to enforce
 * Konzept §3 invariant 1 (no JSON library on the DX runtime classpath).
 */
@DisplayName("JCustosRuntime Phase-1 smoke (V00.74.10 / Prompt 007)")
class JCustosRuntimePhase1SmokeTest {

  @Test
  void allFourMethodsAgreeOnTheSameSnapshot() throws Exception {
    JCustosRuntime runtime = new JCustosRuntime(
        List.of(
            new RegisteredJCustosService(CharSequence.class, String.class, "ServiceLoader", false),
            new RegisteredJCustosService(Number.class, Integer.class, "default", true)),
        List.of(
            new JCustosBootstrapWarning(Severity.INFO, "audit/missing-service",
                "no audit service registered", "register one"),
            new JCustosBootstrapWarning(Severity.WARNING, "audit/noop-fallback",
                "no audit service configured; events are dropped",
                "call .audit(a -> a.logging())")),
        JCustosBootstrapMode.PRODUCTION);

    // 1. summary aggregates the same counts.
    assertEquals("OK | 2 services | 0 errors | 1 warnings | 1 INFO", runtime.summary());

    // 2. toMap surfaces the same shape that toJson serialises.
    Map<String, Object> snapshot = runtime.toMap();
    assertEquals(2, snapshot.get("serviceCount"));
    assertEquals(2, snapshot.get("warningCount"));

    // 3. toJson round-trips through Jackson (test-scope only — see class
    //    Javadoc) and matches toMap structurally key-by-key.
    String json = runtime.toJson();
    ObjectMapper jackson = new ObjectMapper();
    Map<?, ?> parsed = jackson.readValue(json, Map.class);
    assertEquals(snapshot.get("mode"), parsed.get("mode"));
    assertEquals(snapshot.get("serviceCount"), parsed.get("serviceCount"));
    assertEquals(snapshot.get("warningCount"), parsed.get("warningCount"));
    assertEquals(((List<?>) snapshot.get("services")).size(),
        ((List<?>) parsed.get("services")).size());
    assertEquals(((List<?>) snapshot.get("warnings")).size(),
        ((List<?>) parsed.get("warnings")).size());

    // Key-order discipline: services key list before warnings key list.
    List<?> keys = List.copyOf(parsed.keySet());
    assertTrue(keys.indexOf("services") < keys.indexOf("warnings"),
        "deterministic JSON key order — services precedes warnings");

    // 4. healthCheck classifies WARNING-without-ERROR as DEGRADED and
    //    reflects the snapshot's service count.
    HealthStatus health = runtime.healthCheck();
    assertEquals(Health.DEGRADED, health.overall());
    assertEquals(2, health.registeredServices());
    assertEquals(2, health.findings().size());
    assertEquals(1, health.findingsBySeverity(Severity.INFO).size());
    assertEquals(1, health.findingsBySeverity(Severity.WARNING).size());
  }
}
