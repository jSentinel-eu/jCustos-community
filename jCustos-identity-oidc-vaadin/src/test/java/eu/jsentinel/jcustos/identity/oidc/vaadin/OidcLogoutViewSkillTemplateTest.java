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
package eu.jsentinel.jcustos.identity.oidc.vaadin;

import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.vaadin.VaadinSessionSubjectStore;
import eu.jsentinel.jcustos.identity.oidc.RpInitiatedLogoutInitiator;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.oidc.api.LogoutInitiator;
import eu.jsentinel.jcustos.oidc.api.LogoutRequest;
import eu.jsentinel.jcustos.oidc.api.PostLogoutRedirectValidator;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.internal.MockVaadin;
import com.vaadin.browserless.internal.Routes;
import com.vaadin.browserless.mocks.MockService;
import com.vaadin.browserless.mocks.MockVaadinServlet;
import com.vaadin.browserless.mocks.MockedUI;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.internal.PendingJavaScriptInvocation;
import com.vaadin.flow.function.DeploymentConfiguration;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.ServiceException;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinServletContext;
import com.vaadin.flow.server.VaadinServletService;
import com.vaadin.flow.server.VaadinSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * RF02 (JS-SEC-089, CWE-601, CWE-613): the logout view of the {@code jcustos-vaadin-oidc} skill
 * reaches the identity provider. Since ER22 the default initiator of
 * {@link AbstractOidcLogoutView} refuses every {@code post_logout_redirect_uri}; the template
 * sent one and did not override {@code initiator()}, so a generated application ended only the
 * local session and left the provider's session open. {@link TemplateLogoutView} is the
 * template with its placeholders filled in; the second test pins the template text, so that
 * the view here and the generated one stay the same. Browserless Vaadin, no mocking framework.
 */
@DisplayName("RF02 — the OIDC logout view of the skill template reaches the provider with its post-logout target")
class OidcLogoutViewSkillTemplateTest {

  private static final URI END_SESSION = URI.create("https://idp.example/realms/app/logout");
  /** The template's {@code OidcClients.POST_LOGOUT_URI}, filled in with the skill's example. */
  private static final String POST_LOGOUT_URI = "https://app.example.com/";
  /** The template's {@code OidcCallbackView.ID_TOKEN_ATTRIBUTE}. */
  private static final String ID_TOKEN_ATTRIBUTE = "oidc.id_token";

  private static final Path TEMPLATE = Path.of("docs", "skills", "claude", "jcustos-vaadin-oidc",
      "references", "OidcLogoutView.java.tmpl");

  private final RecordingAuditSink audit = new RecordingAuditSink();
  private final VaadinSessionSubjectStore subjects = new VaadinSessionSubjectStore();
  /** Strong reference: Vaadin's CurrentInstance holds sessions weakly. */
  private VaadinSession session;
  private UI ui;

  @BeforeEach
  void start() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.setAuthenticationService(FakeAuthenticationService.<String, String>forType(String.class));
    JCustosServiceResolver.<String>setSubjectIdResolver(SubjectId::of);
    SubjectStores.setSubjectStore(subjects);

    Routes routes = new Routes();
    routes.getRoutes().add(TemplateLogoutView.class);
    MockVaadin.setup(MockedUI::new, new PlainSessionServlet(routes));
    session = VaadinSession.getCurrent();
    ui = UI.getCurrent();

    subjects.setCurrentSubject("alice", String.class);
    session.setAttribute(ID_TOKEN_ATTRIBUTE, "ID-TOKEN");
  }

  @AfterEach
  void stop() {
    try {
      MockVaadin.tearDown();
    } finally {
      JCustosServiceResolver.resetAll();
      SubjectStores.reset();
    }
  }

  @Test
  @DisplayName("a view configured like the template redirects to the end-session endpoint with the encoded post_logout_redirect_uri")
  void templateView_reachesTheProvider() {
    ui.navigate(AbstractOidcLogoutView.logoutLocation(TemplateLogoutView.class));

    String location = redirectLocation();
    assertNotNull(location, "the logout must send the browser somewhere");
    assertTrue(location.startsWith(END_SESSION + "?"),
        "until the exit review the template's view went to the local login route: " + location);
    assertTrue(location.contains("id_token_hint=ID-TOKEN"), location);
    assertTrue(location.contains("post_logout_redirect_uri="
        + URLEncoder.encode(POST_LOGOUT_URI, StandardCharsets.UTF_8)), location);
    assertNull(session.getAttribute(String.class), "the local session ends as well");
  }

  @Test
  @DisplayName("the template overrides initiator() with an allowlist of exactly the target its logoutRequest() sends")
  void template_allowsTheTargetItSends() throws IOException {
    String template = Files.readString(templatePath());

    assertEquals(1, count(template, "Optional.of(URI.create(OidcClients.POST_LOGOUT_URI))"),
        "logoutRequest() sends OidcClients.POST_LOGOUT_URI");
    Matcher initiator = Pattern.compile(
        "@Override\\s+protected LogoutInitiator initiator\\(\\)\\s*\\{\\s*return\\s+new\\s+"
            + "RpInitiatedLogoutInitiator\\(\\s*PostLogoutRedirectValidator\\.allowOnly\\("
            + "URI\\.create\\(OidcClients\\.POST_LOGOUT_URI\\)\\)\\);\\s*}").matcher(template);
    assertTrue(initiator.find(), "the template must override initiator() with "
        + "allowOnly(URI.create(OidcClients.POST_LOGOUT_URI)) - the view of this test does the same");
    for (String type : List.of(RpInitiatedLogoutInitiator.class, LogoutInitiator.class,
        PostLogoutRedirectValidator.class).stream().map(Class::getName).toList()) {
      assertTrue(template.contains("import " + type + ";"), "the template imports " + type);
    }
  }

  // ── helpers ────────────────────────────────────────────────────

  /**
   * The template in the source tree: the module's tests run in the module directory, the
   * template lives in the repository's {@code docs}. Outside a checkout of the repository the
   * test is skipped.
   */
  private static Path templatePath() {
    for (Path dir = Path.of("").toAbsolutePath(); dir != null; dir = dir.getParent()) {
      Path candidate = dir.resolve(TEMPLATE);
      if (Files.isRegularFile(candidate)) {
        return candidate;
      }
    }
    return Assumptions.abort("the skill template is not part of this source tree: " + TEMPLATE);
  }

  private static int count(String text, String needle) {
    int count = 0;
    for (int at = text.indexOf(needle); at >= 0; at = text.indexOf(needle, at + needle.length())) {
      count++;
    }
    return count;
  }

  /** The URL of the {@code Page.setLocation} call the UI would send with its next response. */
  private String redirectLocation() {
    for (PendingJavaScriptInvocation pending : ui.getInternals().dumpPendingJavaScriptInvocations()) {
      if (pending.getInvocation().getExpression().contains("window.open")) {
        return String.valueOf(pending.getInvocation().getParameters().get(0));
      }
    }
    return null;
  }

  /**
   * {@code OidcLogoutView.java.tmpl} with {@code OidcClients} replaced by the constants above:
   * the same {@code logoutRequest()} and the same {@code initiator()} override.
   */
  @PublicRoute
  @Route("rf02/logout")
  public static class TemplateLogoutView extends AbstractOidcLogoutView {

    @Override
    protected URI endSessionEndpoint() {
      return END_SESSION;
    }

    @Override
    protected LogoutRequest logoutRequest() {
      Object stored = VaadinSession.getCurrent().getAttribute(ID_TOKEN_ATTRIBUTE);
      String idTokenHint = stored == null ? "" : stored.toString();
      return new LogoutRequest(
          idTokenHint,
          Optional.of(URI.create(POST_LOGOUT_URI)),
          Optional.empty());
    }

    @Override
    protected LogoutInitiator initiator() {
      return new RpInitiatedLogoutInitiator(
          PostLogoutRedirectValidator.allowOnly(URI.create(POST_LOGOUT_URI)));
    }
  }

  /** The real servlet service, creating plain sessions instead of self-recreating ones. */
  private static final class PlainSessionServlet extends MockVaadinServlet {
    PlainSessionServlet(Routes routes) {
      super(routes, MockedUI::new);
    }

    @Override
    protected VaadinServletService createServletService(DeploymentConfiguration configuration) {
      VaadinServletService service = new MockService(this, configuration, MockedUI::new) {
        @Override
        protected VaadinSession createVaadinSession(VaadinRequest request) {
          return new VaadinSession(this);
        }
      };
      try {
        service.init();
      } catch (ServiceException e) {
        throw new IllegalStateException(e);
      }
      getRoutes().register((VaadinServletContext) service.getContext());
      return service;
    }
  }
}
