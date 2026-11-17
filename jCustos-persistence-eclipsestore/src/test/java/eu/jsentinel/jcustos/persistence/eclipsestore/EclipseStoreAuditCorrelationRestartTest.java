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
package eu.jsentinel.jcustos.persistence.eclipsestore;

import eu.jsentinel.jcustos.audit.AuditCorrelation;
import eu.jsentinel.jcustos.audit.AuditEnvelope;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.audit.StoreBackedJCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.net.ClientAddressResolver;
import eu.jsentinel.jcustos.net.ClientRequestView;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * R5 (JS-SEC-066, CWE-778): the correlation id a request carries is persisted with the audit
 * envelope and survives a restart of the Eclipse-Store storage; an event recorded outside a
 * request keeps none. The id comes through the real path: resolver, scope, store-backed audit
 * service and Eclipse-Store audit store.
 */
@DisplayName("EclipseStoreAuditEventStore — correlation id survives a restart (R5)")
class EclipseStoreAuditCorrelationRestartTest {

  private static final String PROXY = "127.0.0.1";
  private static final String PROXY_ID = "caddy-4f1c2b9e-77aa-4c3e-9d0b-6a1f0c2d3e4f";
  private static final Instant T0 = Instant.parse("2026-11-17T10:00:00Z");

  @TempDir
  Path tempDir;

  @AfterEach
  void reset() {
    JCustosServiceResolver.resetAll();
  }

  private static ClientRequestView request(String peer) {
    return ClientRequestView.of(peer,
        name -> "X-Request-ID".equalsIgnoreCase(name) ? List.of(PROXY_ID) : List.of());
  }

  @Test
  @DisplayName("the proxy's id and a server-side UUID are on disk; an event outside a request has none")
  void correlationIdsSurviveRestart() {
    JCustosServiceResolver.setClientAddressResolver(ClientAddressResolver.trustedProxies(PROXY));
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(tempDir)) {
      StoreBackedJCustosAuditService audit =
          new StoreBackedJCustosAuditService(storage.auditEventStore());
      try (AuditCorrelation.Scope ignored = AuditCorrelation.openFor(request(PROXY))) {
        audit.publish(new LoginFailed(T0, "via-proxy", PROXY, "bad-credentials"));
      }
      try (AuditCorrelation.Scope ignored = AuditCorrelation.openFor(request("203.0.113.5"))) {
        audit.publish(new LoginFailed(T0, "direct", "203.0.113.5", "bad-credentials"));
      }
      audit.publish(new LoginFailed(T0, "background", null, "bad-credentials"));
    }

    try (EclipseStoreJCustosStorage reopened = EclipseStoreJCustosStorage.openAt(tempDir)) {
      List<AuditEnvelope> stored =
          reopened.auditEventStore().query(TenantId.DEFAULT, AuditQuery.all());
      assertEquals(3, stored.size());
      assertEquals(PROXY_ID, stored.get(0).correlationId(),
          "the trusted proxy's request id must survive the restart");
      String generated = stored.get(1).correlationId();
      assertNotEquals(PROXY_ID, generated, "an untrusted peer's header is never taken over");
      assertEquals(36, generated.length(), "a server-side UUID: " + generated);
      assertNull(stored.get(2).correlationId(), "no id is invented outside a request");
    }
  }
}
