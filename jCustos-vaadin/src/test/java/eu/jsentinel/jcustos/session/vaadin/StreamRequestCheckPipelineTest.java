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
package eu.jsentinel.jcustos.session.vaadin;

import eu.jsentinel.jcustos.audit.SessionExpired;
import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.audit.SessionStale;
import eu.jsentinel.jcustos.authorization.LoginListeners;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import eu.jsentinel.jcustos.session.InMemorySessionStore;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionEnforcer;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.TimeoutSessionPolicy;
import eu.jsentinel.jcustos.session.vaadin.JCustosVersionEnforcerPipelineTest.DriftLoginView;
import eu.jsentinel.jcustos.session.vaadin.RequestPipeline.Exchange;
import eu.jsentinel.jcustos.session.vaadin.SessionLifetimePipelineTest.LockRecordingSubjectStore;
import eu.jsentinel.jcustos.session.vaadin.SessionLifetimePipelineTest.MovableClock;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.flow.component.html.Anchor;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.VaadinSessionState;
import com.vaadin.flow.server.streams.DownloadHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static com.svenruppert.dependencies.core.net.HttpStatus.FORBIDDEN;
import static com.svenruppert.dependencies.core.net.HttpStatus.OK;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exit review XR03 (CWE-613): downloads, uploads and {@code StreamResource}s travel through
 * Vaadin's {@code StreamRequestHandler}, not through the UIDL handler. Until the fix the
 * per-request checks returned early for every non-UIDL request, so a download link kept
 * working for a session past its idle timeout, a session revoked on another node and a
 * session whose roles had been withdrawn. The requests run through
 * {@code VaadinService.handleRequest} on a thread without the session lock, with Vaadin's own
 * stream handler and a real {@link DownloadHandler} behind an {@link Anchor}.
 */
@DisplayName("XR03 - downloads are checked like every other request of the session")
class StreamRequestCheckPipelineTest {

  private static final Duration IDLE = Duration.ofMinutes(30);
  private static final Duration ABSOLUTE = Duration.ofHours(12);
  private static final SubjectId ALICE = new SubjectId("alice");
  private static final JCustosVersionKey ALICE_KEY = new JCustosVersionKey(TenantId.DEFAULT, ALICE);
  private static final String REPORT = "quarterly report";

  private final RecordingAuditSink audit = new RecordingAuditSink();
  private final MovableClock clock = new MovableClock(Instant.now());
  private final LockRecordingSubjectStore subjects = new LockRecordingSubjectStore();
  private final InMemorySessionStore sessionStore = new InMemorySessionStore();
  private final InMemoryJCustosVersionStore versionStore = new InMemoryJCustosVersionStore();

  private RequestPipeline pipeline;
  /** Strong reference: Vaadin's CurrentInstance holds sessions weakly. */
  private VaadinSession session;
  private FilesView view;
  private String reportHref;

  @BeforeEach
  void start() {
    JCustosServiceResolver.resetAll();
    LoginListeners.reset();
    SubjectStores.reset();
    VaadinSessionRevocation.reset();
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.<String>setSubjectIdResolver(SubjectId::of);
    JCustosServiceResolver.setSessionPolicy(new TimeoutSessionPolicy<>(
        new TimeoutSessionPolicy.Config(IDLE, ABSOLUTE, true, "/login"), clock, audit));
    SubjectStores.setSubjectStore(subjects);
    VaadinSessionRevocation.useSessionStore(sessionStore);
    FilesView.DOWNLOADS.set(0);
    FilesView.ACTIONS.set(0);

    JCustosVersionEnforcerListener drift = new JCustosVersionEnforcerListener(
        new JCustosVersionEnforcer(versionStore, audit), DriftLoginView.class);
    pipeline = RequestPipeline.start(clock, List.of(drift::register), FilesView.class, DriftLoginView.class);
    session = pipeline.session();
    view = pipeline.navigate(FilesView.class);
    reportHref = view.report.getHref();

    // alice logs in: subject, security-version snapshot and the session record under its reference
    subjects.setCurrentSubject("alice", String.class);
    VaadinJCustosVersionContext.record(session, ALICE, TenantId.DEFAULT, JCustosVersion.INITIAL,
        SessionRef.of(pipeline.httpSessionId()));
    Instant now = clock.instant();
    sessionStore.save(new SessionRecord(SessionId.of(SessionRef.of(pipeline.httpSessionId())), ALICE,
        TenantId.DEFAULT, now, now, JCustosVersion.INITIAL, SessionStatus.ACTIVE));
    audit.clear();
  }

  @AfterEach
  void stop() {
    try {
      pipeline.close();
    } finally {
      JCustosServiceResolver.resetAll();
      LoginListeners.reset();
      SubjectStores.reset();
      VaadinSessionRevocation.reset();
    }
  }

  @Test
  @DisplayName("a live session downloads: the handler runs and the content is served")
  void liveSession_downloadIsServed() {
    assertTrue(reportHref.startsWith("VAADIN/dynamic/resource/"), reportHref);

    Exchange download = pipeline.download(reportHref);

    assertNull(download.failure());
    assertEquals(OK.code(), download.status(), String.valueOf(download.errorMessage()));
    assertEquals(REPORT, download.body());
    assertEquals(1, FilesView.DOWNLOADS.get());
    assertEquals(VaadinSessionState.OPEN, session.getState());
    assertTrue(audit.events().isEmpty());
  }

  @Test
  @DisplayName("idle timeout: the download is refused with 403 and the session ends")
  void idleSession_downloadIsRefused() {
    clock.advance(IDLE.plusMinutes(1));

    Exchange download = pipeline.download(reportHref);

    assertRefused(download);
    assertEquals(SessionExpired.REASON_IDLE_TIMEOUT, audit.single(SessionExpired.class).reason());
  }

  @Test
  @DisplayName("revoked on another node: the download is refused with 403 and the session ends")
  void revokedElsewhere_downloadIsRefused() {
    SessionId key = SessionId.of(SessionRef.of(pipeline.httpSessionId()));
    sessionStore.save(sessionStore.findById(key).orElseThrow().withStatus(SessionStatus.REVOKED));

    Exchange download = pipeline.download(reportHref);

    assertRefused(download);
    SessionInvalidated invalidated = audit.single(SessionInvalidated.class);
    assertEquals(VaadinSessionRevocation.REASON_REVOKED, invalidated.reason());
    assertEquals("alice", invalidated.subjectId());
  }

  @Test
  @DisplayName("roles withdrawn (security-version drift): the download is refused with 403 and the session ends")
  void driftedSession_downloadIsRefused() {
    versionStore.increment(ALICE_KEY);

    Exchange download = pipeline.download(reportHref);

    assertRefused(download);
    assertEquals("alice", audit.single(SessionStale.class).subjectId());
    assertTrue(VaadinJCustosVersionContext.current(session).isEmpty(), "the stale snapshot is cleared");
  }

  @Test
  @DisplayName("a request-type parameter on a download path does not exempt it from the check")
  void heartbeatParameterOnADownloadPath_isChecked() {
    clock.advance(IDLE.plusMinutes(1));

    Exchange download = pipeline.download(reportHref, "heartbeat");

    assertRefused(download);
  }

  @Test
  @DisplayName("a download is checked but is no user activity: it does not postpone the idle timeout")
  void download_doesNotAdvanceTheActivity() {
    assertFalse(pipeline.fire(view, "work").sessionExpired());
    clock.advance(Duration.ofMinutes(20));
    assertEquals(OK.code(), pipeline.download(reportHref).status());
    clock.advance(Duration.ofMinutes(15));

    assertTrue(pipeline.fire(view, "work").sessionExpired(),
        "35 minutes after the last interaction the session is idle, the download in between notwithstanding");
    assertEquals(1, FilesView.ACTIONS.get());
    assertEquals(1, FilesView.DOWNLOADS.get());
  }

  private void assertRefused(Exchange download) {
    assertNull(download.failure(), "the request must not fail");
    assertEquals(FORBIDDEN.code(), download.status());
    assertEquals(SessionTermination.SESSION_EXPIRED_MESSAGE, download.errorMessage());
    assertEquals("", download.body(), "nothing of the download may reach the client");
    assertEquals(0, FilesView.DOWNLOADS.get(), "the download handler of an ended session must not run");
    assertTrue(subjects.currentSubject(String.class).isEmpty(), "the subject is dropped");
    assertNotEquals(VaadinSessionState.OPEN, session.getState(), "the Vaadin session is closed");
    assertNull(session.getSession(), "the HTTP session is invalidated");
    assertFalse(subjects.lockHeldOnAccess.contains(Boolean.FALSE),
        "the check runs under the session lock");
  }

  /** A view with one download link, the way applications offer files. */
  @Route("xr03-files")
  public static class FilesView extends Div {
    static final AtomicInteger DOWNLOADS = new AtomicInteger();
    static final AtomicInteger ACTIONS = new AtomicInteger();

    final Anchor report;

    public FilesView() {
      DownloadHandler handler = event -> {
        DOWNLOADS.incrementAndGet();
        event.getOutputStream().write(REPORT.getBytes(StandardCharsets.UTF_8));
      };
      report = new Anchor(handler, "Report");
      add(report);
      getElement().addEventListener("work", event -> ACTIONS.incrementAndGet());
    }
  }
}
