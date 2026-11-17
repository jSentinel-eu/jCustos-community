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

import eu.jsentinel.jcustos.authorization.api.CountingServiceClassLoader;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.net.ClientRequestView;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exit review RF22: {@code JCustosContext.correlationIdResolver()} was documented "never throws"
 * but threw for two {@code META-INF/services} entries - and scanned the class path again on
 * every request, since nothing was cached. {@link AuditCorrelation} fell back to a UUID and
 * warned once, naming the resolver "(unavailable)". Now the lookup reports the ambiguity as
 * documented, remembers it until a set or a reset, and the warning names the registered
 * implementations. The class path is a real {@link java.net.URLClassLoader} that counts the
 * service lookups.
 */
@DisplayName("RF22 - two CorrelationIdResolver registrations: one scan, a UUID per request, the ambiguity reported")
class CorrelationIdResolverAmbiguityTest {

  private static final int REQUESTS = 100;
  private static final Pattern AMBIGUITY_WARNING = Pattern.compile(
      "audit/correlation-resolver-failure: no correlation-id resolver can be resolved");

  @TempDir
  Path classPath;

  private final ClientRequestView request = ClientRequestView.of("203.0.113.5", name -> List.of());

  @BeforeEach
  void reset() {
    JCustosServiceResolver.resetAll();
    AuditCorrelation.resetResolverFailureWarning();
  }

  @AfterEach
  void resetAfter() {
    JCustosServiceResolver.resetAll();
    assertTrue(AuditCorrelation.current().isEmpty(), "a test left a correlation scope open");
  }

  @Test
  @DisplayName("100 requests: one class-path scan, a UUID each, one warning naming both implementations")
  void ambiguousRegistration() throws IOException {
    try (CountingServiceClassLoader loader = CountingServiceClassLoader.registering(classPath,
        CorrelationIdResolver.class, FirstResolver.class, SecondResolver.class)) {

      String log = capturingStdErr(() -> loader.run(() -> {
        for (int i = 0; i < REQUESTS; i++) {
          try (AuditCorrelation.Scope scope = AuditCorrelation.openFor(request)) {
            assertEquals(36, scope.correlationId().length(), "a server-side UUID: " + scope.correlationId());
          }
        }
        return null;
      }));

      assertEquals(1, loader.lookups(), "the ambiguity is remembered, not scanned per request");
      Matcher warning = AMBIGUITY_WARNING.matcher(log);
      assertTrue(warning.find(), "the warning reports the ambiguity: " + log);
      assertTrue(!warning.find(), "reported once per JVM: " + log);
      assertTrue(log.contains(FirstResolver.class.getName()) && log.contains(SecondResolver.class.getName()),
          "the warning names the registered implementations: " + log);

      IllegalStateException thrown = assertThrows(IllegalStateException.class,
          () -> loader.run(JCustosServiceResolver::correlationIdResolver),
          "documented: the lookup reports the ambiguity instead of picking one");
      assertTrue(thrown.getMessage().contains("multiple implementations"), thrown.getMessage());
      assertThrows(IllegalStateException.class,
          () -> loader.run(JCustosServiceResolver::findCorrelationIdResolver));
      assertEquals(1, loader.lookups());

      JCustosServiceResolver.setCorrelationIdResolver(view -> "set-by-bootstrap");
      try (AuditCorrelation.Scope scope = loader.run(() -> AuditCorrelation.openFor(request))) {
        assertEquals("set-by-bootstrap", scope.correlationId(), "a set resolver replaces the ambiguity");
      }
      JCustosServiceResolver.setCorrelationIdResolver(null);
      assertThrows(IllegalStateException.class,
          () -> loader.run(JCustosServiceResolver::correlationIdResolver));
      assertEquals(2, loader.lookups(), "clearing the resolver makes the next lookup scan again");

      JCustosServiceResolver.resetAll();
      assertThrows(IllegalStateException.class,
          () -> loader.run(JCustosServiceResolver::correlationIdResolver));
      assertEquals(3, loader.lookups(), "resetAll() forgets the ambiguity");
    }
  }

  @Test
  @DisplayName("control: one registration is used, and also looked up only once")
  void singleRegistration() throws IOException {
    try (CountingServiceClassLoader loader = CountingServiceClassLoader.registering(classPath,
        CorrelationIdResolver.class, FirstResolver.class)) {
      for (int i = 0; i < REQUESTS; i++) {
        try (AuditCorrelation.Scope scope = loader.run(() -> AuditCorrelation.openFor(request))) {
          assertEquals(FirstResolver.ID, scope.correlationId());
        }
      }
      assertEquals(1, loader.lookups());
    }
  }

  /** Runs {@code action} and returns what slf4j-simple wrote to {@code System.err} meanwhile. */
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

  // ── providers, loaded by ServiceLoader through their public no-argument constructor ──

  /** A correlation-id resolver registered through {@code META-INF/services}. */
  public static class FirstResolver implements CorrelationIdResolver {
    static final String ID = "first-resolver-id";

    @Override
    public String resolve(ClientRequestView request) {
      return ID;
    }
  }

  /** A second registration of the same SPI. */
  public static final class SecondResolver extends FirstResolver {
  }
}
