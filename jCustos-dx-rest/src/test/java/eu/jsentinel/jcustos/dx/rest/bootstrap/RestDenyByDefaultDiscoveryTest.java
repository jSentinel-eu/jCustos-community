package eu.jsentinel.jcustos.dx.rest.bootstrap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.dx.bootstrap.JCustosBootstrapException;
import eu.jsentinel.jcustos.dx.rest.handlers.ClassScanningRestHandlerDiscovery;
import eu.jsentinel.jcustos.dx.rest.handlers.RestHandlerDiscovery;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;

import java.util.Optional;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * CWE-862: an unannotated REST handler is refused at runtime under
 * deny-by-default, but until V00.82 nothing said so at startup — REST has no
 * router to enumerate, so the diagnostic was Vaadin-only and the fault showed
 * up on the first request instead.
 */
@DisplayName("REST deny-by-default — startup handler enumeration (CWE-862)")
class RestDenyByDefaultDiscoveryTest {

  @BeforeEach
  @AfterEach
  void resetGlobals() {
    JCustosServiceResolver.setDenyByDefault(false);
    JCustosServiceResolver.setAuthenticationService((AuthenticationService<?, ?>) null);
    JCustosServiceResolver.setAuthorizationService((AuthorizationService<?>) null);
  }

  private RestJCustosBootstrap bootstrapWithServices() {
    return RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver((RestSubjectResolver) request -> Optional.empty());
  }

  @Test
  @DisplayName("JS-SEC-085: STRICT without deny-by-default refuses to boot with authorization/allow-by-omission")
  void strictWithoutDenyByDefault_refusesToBoot() {
    JCustosBootstrapException ex = assertThrows(JCustosBootstrapException.class, () ->
        bootstrapWithServices()
            .audit(a -> a.logging())
            .mode(JCustosBootstrapMode.STRICT)
            .install());

    assertTrue(ex.warnings().stream()
            .anyMatch(w -> "authorization/allow-by-omission".equals(w.code())
                && w.severity() == Severity.ERROR),
        "STRICT must not boot green while every unannotated handler is public, got: " + ex.warnings());
  }

  @Test
  @DisplayName("JS-SEC-085: STRICT with .denyByDefault(true) and fully annotated handlers boots")
  void strictWithDenyByDefaultBuilder_boots() {
    JCustosRuntime runtime = bootstrapWithServices()
        .denyByDefault(true)
        .audit(a -> a.logging())
        .discoverHandlers(new ClassScanningRestHandlerDiscovery(ProtectedHandlers.class))
        .mode(JCustosBootstrapMode.STRICT)
        .install();

    assertTrue(JCustosServiceResolver.isDenyByDefault(), "the builder value must reach the resolver");
    assertTrue(runtime.services().stream()
            .anyMatch(s -> s.source().contains("bootstrap-deny-by-default=true")),
        "the flag is listed among the registered services, got: " + runtime.services());
    assertFalse(runtime.warnings().stream()
        .anyMatch(w -> "authorization/allow-by-omission".equals(w.code())));
  }

  @Test
  @DisplayName("JS-SEC-085: PRODUCTION without deny-by-default records a WARNING and boots; DEVELOPMENT stays silent")
  void productionWithoutDenyByDefault_warns() {
    JCustosRuntime production = bootstrapWithServices()
        .audit(a -> a.logging())
        .mode(JCustosBootstrapMode.PRODUCTION)
        .install();
    assertTrue(production.warnings().stream()
        .anyMatch(w -> "authorization/allow-by-omission".equals(w.code())
            && w.severity() == Severity.WARNING));

    JCustosServiceResolver.setAuthenticationService((AuthenticationService<?, ?>) null);
    JCustosServiceResolver.setAuthorizationService((AuthorizationService<?>) null);
    JCustosRuntime development = bootstrapWithServices()
        .audit(a -> a.logging())
        .mode(JCustosBootstrapMode.DEVELOPMENT)
        .install();
    assertFalse(development.warnings().stream()
        .anyMatch(w -> "authorization/allow-by-omission".equals(w.code())));
  }

  @Test
  @DisplayName("STRICT refuses to boot when a handler carries no security annotation")
  void strictRefusesUnannotatedHandler() {
    JCustosServiceResolver.setDenyByDefault(true);

    JCustosBootstrapException ex = assertThrows(JCustosBootstrapException.class, () ->
        bootstrapWithServices()
            .discoverHandlers(new ClassScanningRestHandlerDiscovery(UnprotectedHandlers.class))
            .mode(JCustosBootstrapMode.STRICT)
            .install());

    assertTrue(ex.warnings().stream()
            .anyMatch(w -> "deny-by-default/unannotated-handler".equals(w.code())
                && w.message().contains("open")),
        "the finding must name the offending handler, got: " + ex.warnings());
  }

  @Test
  @DisplayName("PRODUCTION records the same finding instead of refusing")
  void productionRecordsFinding() {
    JCustosServiceResolver.setDenyByDefault(true);

    JCustosRuntime runtime = bootstrapWithServices()
        .discoverHandlers(new ClassScanningRestHandlerDiscovery(UnprotectedHandlers.class))
        .mode(JCustosBootstrapMode.PRODUCTION)
        .install();

    assertTrue(runtime.warnings().stream()
            .anyMatch(w -> "deny-by-default/unannotated-handler".equals(w.code())),
        "PRODUCTION must still report it");
  }

  @Test
  @DisplayName("an annotated or public handler produces no finding")
  void protectedHandlersAreClean() {
    JCustosServiceResolver.setDenyByDefault(true);

    JCustosRuntime runtime = bootstrapWithServices()
        .discoverHandlers(new ClassScanningRestHandlerDiscovery(ProtectedHandlers.class))
        .mode(JCustosBootstrapMode.PRODUCTION)
        .install();

    assertFalse(runtime.warnings().stream()
            .anyMatch(w -> w.code().startsWith("deny-by-default/unannotated")),
        "annotated and @PublicRoute handlers are not findings, got: " + runtime.warnings());
  }

  @Test
  @DisplayName("without deny-by-default the enumeration is not consulted")
  void noFindingWhenDenyByDefaultIsOff() {
    // Flag stays off — an unannotated handler is served by design here.
    JCustosRuntime runtime = bootstrapWithServices()
        .discoverHandlers(new ClassScanningRestHandlerDiscovery(UnprotectedHandlers.class))
        .mode(JCustosBootstrapMode.PRODUCTION)
        .install();

    assertFalse(runtime.warnings().stream().anyMatch(w -> w.code().startsWith("deny-by-default/")),
        "reporting handlers that are meant to be open would be noise");
  }

  @Test
  @DisplayName("a discovery that cannot enumerate is an error, not a clean result")
  void unavailableDiscoveryIsAnError() {
    JCustosServiceResolver.setDenyByDefault(true);
    RestHandlerDiscovery blind = new RestHandlerDiscovery() {
      @Override
      public Stream<String> discoverUnannotatedHandlerNames() {
        return Stream.empty();
      }

      @Override
      public boolean handlersAvailable() {
        return false;
      }
    };

    JCustosRuntime runtime = bootstrapWithServices()
        .discoverHandlers(blind)
        .mode(JCustosBootstrapMode.PRODUCTION)
        .install();

    assertTrue(runtime.warnings().stream()
            .anyMatch(w -> "deny-by-default/discovery-unavailable".equals(w.code())),
        "an empty result from a blind discovery must not pass as 'nothing unprotected'");
  }

  @Test
  @DisplayName("deny-by-default without any discovery is reported as a blind spot")
  void missingDiscoveryIsReported() {
    JCustosServiceResolver.setDenyByDefault(true);

    JCustosRuntime runtime = bootstrapWithServices()
        .mode(JCustosBootstrapMode.PRODUCTION)
        .install();

    assertEquals(1, runtime.warnings().stream()
            .filter(w -> "deny-by-default/discovery-disabled".equals(w.code()))
            .count(),
        "the application should learn that the startup check is not running");
  }

  // ── fixtures ────────────────────────────────────────────────────

  static final class UnprotectedHandlers {
    public void open() {
      // no annotation — refused at runtime, and now reported at startup
    }
  }

  static final class ProtectedHandlers {
    @RequiresPermission("document:read")
    public void read() {
    }

    @PublicRoute
    public void health() {
    }
  }
}
