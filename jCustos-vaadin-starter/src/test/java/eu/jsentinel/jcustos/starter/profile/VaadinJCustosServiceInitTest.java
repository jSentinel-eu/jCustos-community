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
package eu.jsentinel.jcustos.starter.profile;

import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.oidc.api.SessionRegistry;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import eu.jsentinel.jcustos.session.ObservableJCustosVersionStore;
import eu.jsentinel.jcustos.session.vaadin.JCustosVersionEnforcerListener;
import eu.jsentinel.jcustos.starter.errors.JCustosErrorHandler;
import eu.jsentinel.jcustos.starter.profile.VaadinJCustosServiceInit.Options;
import eu.jsentinel.jcustos.starter.profile.VaadinJCustosServiceInit.Part;
import com.vaadin.browserless.internal.MockVaadin;
import com.vaadin.browserless.internal.Routes;
import com.vaadin.browserless.mocks.MockHttpSession;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.server.ErrorHandler;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinService;
import com.vaadin.flow.server.VaadinServletService;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.WrappedHttpSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReentrantLock;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-168 (CWE-1188): {@code VaadinJCustosStarter.serviceInit(...)} wires each part whose
 * prerequisite is there and skips the others. A real Vaadin service; the parts are checked by
 * what they do or by what they registered on the service and the init event.
 */
@DisplayName("JS-SEC-168 - VaadinJCustosStarter.serviceInit wires each part and skips absent optional ones")
class VaadinJCustosServiceInitTest {

  private VaadinServletService service;

  @BeforeEach
  void start() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    MockVaadin.setup(new Routes());
    service = (VaadinServletService) VaadinService.getCurrent();
  }

  @AfterEach
  void stop() {
    MockVaadin.tearDown();
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
  }

  private static List<JCustosVersionEnforcerListener> enforcers(ServiceInitEvent event) {
    return event.getAddedRequestHandlers()
        .filter(JCustosVersionEnforcerListener.class::isInstance)
        .map(JCustosVersionEnforcerListener.class::cast)
        .toList();
  }

  @Test
  @DisplayName("no version store registered: only the error handler; no enforcer, no bridge")
  void noVersionStore_errorHandlerOnly() {
    ServiceInitEvent event = new ServiceInitEvent(service);

    Set<Part> parts = VaadinJCustosStarter.serviceInit(event, LoginTarget.class);

    assertEquals(EnumSet.of(Part.ERROR_HANDLER), parts);
    assertTrue(enforcers(event).isEmpty());
    assertInstanceOf(JCustosErrorHandler.class, errorHandlerOfANewSession(),
        "every session created afterwards gets the reference error handler");
  }

  @Test
  @DisplayName("a plain version store: the enforcer on every request path, no bridge")
  void plainVersionStore_enforcerOnly() {
    JCustosServiceResolver.setJCustosVersionStore(new InMemoryJCustosVersionStore());
    ServiceInitEvent event = new ServiceInitEvent(service);

    Set<Part> parts = VaadinJCustosStarter.serviceInit(event, LoginTarget.class);

    assertEquals(EnumSet.of(Part.VERSION_ENFORCER, Part.ERROR_HANDLER), parts);
    assertEquals(1, enforcers(event).size(), "the request handler for UIDL requests and downloads");
    assertTrue(event.getAddedVaadinRequestInterceptor().anyMatch(JCustosVersionEnforcerListener.class::isInstance),
        "the request interceptor for push messages");
  }

  @Test
  @DisplayName("an observable version store: the bridge subscribes, and unsubscribes when the service ends")
  void observableVersionStore_bridgeSubscribed() {
    ObservableJCustosVersionStore observable = new ObservableJCustosVersionStore(new InMemoryJCustosVersionStore());
    JCustosServiceResolver.setJCustosVersionStore(observable);
    ServiceInitEvent event = new ServiceInitEvent(service);

    Set<Part> parts = VaadinJCustosStarter.serviceInit(event, LoginTarget.class);

    assertEquals(EnumSet.of(Part.VERSION_ENFORCER, Part.VERSION_CHANGE_BRIDGE, Part.ERROR_HANDLER), parts);
    assertEquals(1, observable.listenerCount());
    MockVaadin.tearDown();
    assertEquals(0, observable.listenerCount(), "the service-destroy listener removes the subscription");
    MockVaadin.setup(new Routes());
  }

  @Test
  @DisplayName("withoutErrorHandler(): the application keeps its own error handler")
  void withoutErrorHandler_noHandlerInstalled() {
    ServiceInitEvent event = new ServiceInitEvent(service);

    Set<Part> parts = VaadinJCustosStarter.serviceInit(event, LoginTarget.class,
        Options.defaults().withoutErrorHandler());

    assertTrue(parts.isEmpty(), parts.toString());
    assertFalse(errorHandlerOfANewSession() instanceof JCustosErrorHandler);
  }

  @Test
  @DisplayName("an OIDC session registry with the module on the class path: the cleanup forgets destroyed sessions")
  void oidcRegistry_cleanupRegistered() {
    RecordingSessionRegistry registry = new RecordingSessionRegistry();
    ServiceInitEvent event = new ServiceInitEvent(service);

    Set<Part> parts = VaadinJCustosStarter.serviceInit(event, LoginTarget.class,
        Options.defaults().withOidcSessionRegistry(registry));

    assertTrue(parts.contains(Part.OIDC_SESSION_REGISTRY_CLEANUP), parts.toString());
    VaadinSession session = openSecondSession();
    String sessionId = inSession(session, () -> session.getSession().getId());
    service.fireSessionDestroy(session);
    assertTrue(registry.unregistered.contains(SessionRef.of(sessionId)), registry.unregistered.toString());
  }

  @Test
  @DisplayName("an OIDC session registry without the module: skipped and reported, nothing fails")
  void oidcRegistry_moduleAbsent_skipped() {
    ServiceInitEvent event = new ServiceInitEvent(service);

    String log = capturingStdErr(() -> assertFalse(VaadinJCustosServiceInit.installSessionRegistryCleanup(
        event, new RecordingSessionRegistry(), "eu.jsentinel.jcustos.identity.oidc.vaadin.NotOnTheClassPath")));

    assertTrue(log.contains("starter/oidc-cleanup-skipped"), log);
  }

  @Test
  @DisplayName("null arguments are rejected")
  void nulls() {
    ServiceInitEvent event = new ServiceInitEvent(service);
    assertThrows(NullPointerException.class, () -> VaadinJCustosStarter.serviceInit(null, LoginTarget.class));
    assertThrows(NullPointerException.class, () -> VaadinJCustosStarter.serviceInit(event, null));
    assertThrows(NullPointerException.class, () -> VaadinJCustosStarter.serviceInit(event, LoginTarget.class, null));
    assertThrows(NullPointerException.class, () -> Options.defaults().withOidcSessionRegistry(null));
  }

  // ── support ────────────────────────────────────────────────────

  private ErrorHandler errorHandlerOfANewSession() {
    VaadinSession session = openSecondSession();
    return inSession(session, session::getErrorHandler);
  }

  /** A new browser's session of the service: registered, unlocked, known to the session-init listeners. */
  private VaadinSession openSecondSession() {
    MockHttpSession http = MockHttpSession.Companion.create(service.getServlet().getServletContext());
    VaadinSession session = new VaadinSession(service);
    ReentrantLock lock = new ReentrantLock();
    lock.lock();
    try {
      http.setAttribute(service.getServiceName() + ".lock", lock);
      http.setAttribute(VaadinSession.class.getName() + "." + service.getServiceName(), session);
      session.refreshTransients(new WrappedHttpSession(http), service);
      MockVaadin.fireSessionInit(service, session, VaadinRequest.getCurrent());
    } finally {
      lock.unlock();
    }
    return session;
  }

  private static <T> T inSession(VaadinSession session, java.util.function.Supplier<T> action) {
    session.getLockInstance().lock();
    try {
      return action.get();
    } finally {
      session.getLockInstance().unlock();
    }
  }

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

  /** The application's registry of OIDC sessions, recording what the cleanup forgets. */
  private static final class RecordingSessionRegistry implements SessionRegistry {
    final List<String> unregistered = new CopyOnWriteArrayList<>();

    @Override
    public void register(String issuer, String subject, Optional<String> sid, String sessionId) {
    }

    @Override
    public Set<String> terminate(String issuer, Optional<String> subject, Optional<String> sid) {
      return Set.of();
    }

    @Override
    public void unregister(String sessionId) {
      unregistered.add(sessionId);
    }
  }

  /** The reroute target. */
  public static class LoginTarget extends Div {
  }
}
