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
package eu.jsentinel.jcustos.audit;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("AuditEnvelope correlation id (R5, JS-SEC-066)")
class AuditEnvelopeCorrelationTest {

  private static final AuditEvent EVENT =
      new LoginFailed(Instant.parse("2026-11-17T10:00:00Z"), "alice", "203.0.113.5", "bad");

  @Test
  @DisplayName("the three-argument constructor leaves the correlation id empty")
  void compatibilityConstructor() {
    AuditEnvelope envelope = new AuditEnvelope("id-1", null, EVENT);
    assertNull(envelope.correlationId());
    assertEquals(TenantId.DEFAULT, envelope.tenant());
    assertEquals(new AuditEnvelope("id-1", TenantId.DEFAULT, EVENT, null), envelope);
  }

  @Test
  @DisplayName("a well-formed correlation id is kept and takes part in equality")
  void wellFormedIdIsKept() {
    AuditEnvelope envelope = new AuditEnvelope("id-1", TenantId.DEFAULT, EVENT, "req-1");
    assertEquals("req-1", envelope.correlationId());
    assertFalse(envelope.equals(new AuditEnvelope("id-1", TenantId.DEFAULT, EVENT)));
  }

  @Test
  @DisplayName("a malformed correlation id is refused without echoing it")
  void malformedIdIsRefused() {
    IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
        () -> new AuditEnvelope("id-1", TenantId.DEFAULT, EVENT, "x\nAUDIT forged"));
    assertFalse(refused.getMessage().contains("forged"), refused.getMessage());
  }

  @Test
  @DisplayName("isValidCorrelationId: 1 to 128 characters from [A-Za-z0-9._:-]")
  void validationRule() {
    for (String good : List.of("a", "Z", "0", "req-1", "a.b_c:d-e",
        "4f1c2b9e-77aa-4c3e-9d0b-6a1f0c2d3e4f", "x".repeat(128))) {
      assertTrue(AuditEnvelope.isValidCorrelationId(good), good);
    }
    for (String bad : List.of("", " ", "a b", "a\tb", "a\nb", "a\u0085b", "a b", "a​b",
        "a,b", "a;b", "a=b", "a/b", "é", "\ud800", "x".repeat(129))) {
      assertFalse(AuditEnvelope.isValidCorrelationId(bad), bad);
    }
    assertFalse(AuditEnvelope.isValidCorrelationId(null));
  }
}
