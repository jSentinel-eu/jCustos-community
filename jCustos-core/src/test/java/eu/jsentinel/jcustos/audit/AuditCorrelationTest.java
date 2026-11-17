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

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.net.ClientRequestView;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("AuditCorrelation (R5, JS-SEC-066)")
class AuditCorrelationTest {

  @AfterEach
  void reset() {
    JCustosServiceResolver.resetAll();
    assertTrue(AuditCorrelation.current().isEmpty(), "a test left a correlation scope open");
  }

  @Test
  @DisplayName("outside a scope there is no correlation id - none is invented")
  void emptyOutsideAScope() {
    assertEquals(Optional.empty(), AuditCorrelation.current());
  }

  @Test
  @DisplayName("an open scope makes its id current; closing it clears the thread")
  void openAndClose() {
    try (AuditCorrelation.Scope scope = AuditCorrelation.open("req-1")) {
      assertEquals("req-1", scope.correlationId());
      assertEquals(Optional.of("req-1"), AuditCorrelation.current());
    }
    assertEquals(Optional.empty(), AuditCorrelation.current());
  }

  @Test
  @DisplayName("a nested scope restores the previous id when it closes")
  void nestedScopeRestoresThePreviousValue() {
    try (AuditCorrelation.Scope outer = AuditCorrelation.open("outer")) {
      try (AuditCorrelation.Scope inner = AuditCorrelation.open("inner")) {
        assertEquals(Optional.of("inner"), AuditCorrelation.current());
      }
      assertEquals(Optional.of("outer"), AuditCorrelation.current());
    }
    assertEquals(Optional.empty(), AuditCorrelation.current());
  }

  @Test
  @DisplayName("closing twice has no effect; closing the outer scope first also ends the inner one")
  void closeIsIdempotentAndOrderTolerant() {
    AuditCorrelation.Scope outer = AuditCorrelation.open("outer");
    AuditCorrelation.Scope inner = AuditCorrelation.open("inner");
    outer.close();
    assertEquals(Optional.empty(), AuditCorrelation.current(),
        "closing the enclosing scope must not leave the inner id behind");
    inner.close();
    outer.close();
    assertEquals(Optional.empty(), AuditCorrelation.current(),
        "a late close of the inner scope must not bring the outer id back");
  }

  @Test
  @DisplayName("a scope closed on another thread does not clear the opening thread, which still can")
  void foreignThreadCloseLeavesTheOwnerAlone() throws InterruptedException {
    AuditCorrelation.Scope scope = AuditCorrelation.open("owned");
    AtomicReference<Optional<String>> seenThere = new AtomicReference<>();
    Thread other = new Thread(() -> {
      seenThere.set(AuditCorrelation.current());
      scope.close();
    });
    other.start();
    other.join();
    assertEquals(Optional.empty(), seenThere.get(), "the id is not visible on another thread");
    assertEquals(Optional.of("owned"), AuditCorrelation.current());
    scope.close();
    assertEquals(Optional.empty(), AuditCorrelation.current());
  }

  @Test
  @DisplayName("open refuses null, blank, over-long and malformed ids")
  void openRejectsMalformedIds() {
    assertThrows(NullPointerException.class, () -> AuditCorrelation.open(null));
    for (String bad : List.of("", " ", "a b", "line\nbreak", "x".repeat(129), "café",
        "a,b", "<script>")) {
      assertThrows(IllegalArgumentException.class, () -> AuditCorrelation.open(bad), bad);
    }
    assertEquals(Optional.empty(), AuditCorrelation.current());
  }

  @Test
  @DisplayName("newId is a fresh, well-formed UUID")
  void newIdIsAUuid() {
    String first = AuditCorrelation.newId();
    assertTrue(AuditEnvelope.isValidCorrelationId(first));
    assertEquals(36, first.length());
    assertNotEquals(first, AuditCorrelation.newId());
  }

  @Test
  @DisplayName("openFor asks the registered resolver")
  void openForUsesTheRegisteredResolver() {
    JCustosServiceResolver.setCorrelationIdResolver(request -> "from-resolver");
    try (AuditCorrelation.Scope scope =
             AuditCorrelation.openFor(ClientRequestView.of("203.0.113.5", name -> List.of()))) {
      assertEquals("from-resolver", scope.correlationId());
    }
  }

  @Test
  @DisplayName("openFor replaces a throwing resolver or a malformed result with a UUID")
  void openForFallsBackForAMisbehavingResolver() {
    ClientRequestView request = ClientRequestView.of("203.0.113.5", name -> List.of());

    JCustosServiceResolver.setCorrelationIdResolver(view -> {
      throw new IllegalStateException("broken resolver");
    });
    try (AuditCorrelation.Scope scope = AuditCorrelation.openFor(request)) {
      assertEquals(36, scope.correlationId().length());
    }

    JCustosServiceResolver.setCorrelationIdResolver(view -> "user=admin\nAUDIT forged");
    try (AuditCorrelation.Scope scope = AuditCorrelation.openFor(request)) {
      assertTrue(AuditEnvelope.isValidCorrelationId(scope.correlationId()));
      assertEquals(36, scope.correlationId().length());
    }

    JCustosServiceResolver.setCorrelationIdResolver(view -> null);
    try (AuditCorrelation.Scope scope = AuditCorrelation.openFor(request)) {
      assertEquals(36, scope.correlationId().length());
    }
  }
}
