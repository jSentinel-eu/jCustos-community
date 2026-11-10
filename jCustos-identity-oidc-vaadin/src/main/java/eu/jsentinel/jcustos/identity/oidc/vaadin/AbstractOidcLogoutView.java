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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.LogoutPerformed;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore;
import eu.jsentinel.jcustos.identity.oidc.RpInitiatedLogoutInitiator;
import eu.jsentinel.jcustos.logout.LogoutScope;
import eu.jsentinel.jcustos.oidc.api.LogoutInitiator;
import eu.jsentinel.jcustos.oidc.api.LogoutRequest;
import eu.jsentinel.jcustos.session.SessionContext;
import eu.jsentinel.jcustos.session.vaadin.VaadinJCustosVersionContext;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterObserver;
import com.vaadin.flow.router.RouteConfiguration;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.WrappedSession;

import java.io.Serial;
import java.io.Serializable;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Reusable base for the Vaadin OIDC RP-initiated-logout route (V00.78). The
 * consumer maps it to a {@code @Route} (e.g. {@code "logout"}) and supplies the
 * {@code end_session_endpoint} + {@link LogoutRequest}.
 *
 * <p><strong>What a logout does (JS-SEC-147, CWE-613, CWE-460).</strong> The view builds the
 * end-session redirect while the subject is still bound (a consumer may derive the
 * {@code id_token_hint} from it) and then ends the local session <em>in any case</em> - also
 * when {@link #endSessionEndpoint()}, {@link #logoutRequest()}, the initiator or
 * {@link #onBeforeLogout()} throws:
 * <ol>
 *   <li>{@code SessionPolicy.onLogout} is notified,</li>
 *   <li>the subject is removed from the {@code SubjectStore} (JS-SEC-028),</li>
 *   <li>a bound token credential and the security-version snapshot are cleared,</li>
 *   <li>{@code LogoutPerformed} is audited,</li>
 *   <li>{@link #onBeforeLogout()} runs,</li>
 *   <li>the browser is sent to the provider's end-session URL - or, when that URL could not
 *       be computed, to {@link #localLogoutTarget()} with a WARN in the log,</li>
 *   <li>the Vaadin session is closed and the HTTP session invalidated.</li>
 * </ol>
 * Until 00.84.00 the redirect was requested through {@code getUI()}, which is empty while the
 * view is being entered, so the provider was never reached; the local teardown removed the
 * subject only and was skipped altogether when a step before it threw.
 *
 * <p><strong>Who may trigger it (JS-SEC-147, CWE-352).</strong> Merely navigating to the route
 * logs nobody out: a foreign page could send the browser there and end both the local and
 * the single-sign-on session. The view performs the logout only when the request carries a
 * single-use token that was minted for this session - link to the route with
 * {@link #logoutLocation(Class)}:
 * <pre>{@code
 *   Button signOut = new Button("Sign out",
 *       click -> UI.getCurrent().navigate(AbstractOidcLogoutView.logoutLocation(OidcLogoutView.class)));
 * }</pre>
 * Without a valid token the view shows a confirmation button; its click is an ordinary
 * Vaadin RPC, which a foreign page cannot forge.
 */
public abstract class AbstractOidcLogoutView extends Div implements BeforeEnterObserver, HasLogger {

  /** Query parameter that carries the single-use logout token. */
  public static final String LOGOUT_TOKEN_PARAMETER = "logout-token";

  /** Element id of the confirmation button shown when no valid token arrived. */
  public static final String CONFIRM_BUTTON_ID = "oidc-logout-confirm";

  /** How many unused logout tokens a session keeps; the oldest is dropped beyond that. */
  static final int MAX_PENDING_TOKENS = 8;

  private static final SecureRandom RANDOM = new SecureRandom();

  private final LogoutInitiator initiator = new RpInitiatedLogoutInitiator();

  /** @return the OP {@code end_session_endpoint} (from discovery / config). */
  protected abstract URI endSessionEndpoint();

  /** @return the logout parameters (id_token_hint, post_logout_redirect_uri, state). */
  protected abstract LogoutRequest logoutRequest();

  /**
   * Additional teardown hook, run after the default local teardown of subject, token
   * credential and snapshot and before the session is closed (default: no-op).
   *
   * @implSpec The base class already ends the local session (JS-SEC-028, JS-SEC-147) so a
   *     logout never leaves the RP session authenticated after the OP session ends. Override
   *     this for <em>extra</em> teardown - removing a {@code SessionStore} record, say; do not
   *     treat it as the <em>only</em> teardown path. A {@code RuntimeException} thrown here is
   *     logged and does not stop the logout.
   */
  protected void onBeforeLogout() {
  }

  /**
   * Where the browser goes when the provider's end-session URL cannot be computed - the
   * provider publishes no {@code end_session_endpoint}, the {@code post_logout_redirect_uri}
   * is refused, the request cannot be built. The local session is ended in any case; this
   * only decides what the user sees afterwards.
   *
   * @return a location for {@code Page.setLocation}; the default is the login route,
   *     {@code "/" + JCustosServiceResolver.loginRouteName()}
   * @since 00.84.00
   */
  protected String localLogoutTarget() {
    return "/" + JCustosServiceResolver.loginRouteName();
  }

  /** @return the text above the confirmation button. */
  protected String confirmationMessage() {
    return "Do you want to sign out?";
  }

  /** @return the caption of the confirmation button. */
  protected String confirmationButtonText() {
    return "Sign out";
  }

  /**
   * JS-SEC-147 (CWE-352): the location of a logout route including a fresh single-use token
   * bound to the current session. Use it for every link or button that is meant to log the
   * user out without a further click. The result is relative to the application's base URL,
   * as {@code UI.navigate(String)} and {@code RouterLink} expect it.
   *
   * @param logoutView the application's logout route
   * @return for example {@code logout?logout-token=…}
   * @throws IllegalStateException when no Vaadin session is bound to the thread
   * @since 00.84.00
   */
  public static String logoutLocation(Class<? extends AbstractOidcLogoutView> logoutView) {
    Objects.requireNonNull(logoutView, "logoutView");
    String route = RouteConfiguration.forSessionScope().getUrl(logoutView);
    return route + "?" + LOGOUT_TOKEN_PARAMETER + "=" + mintLogoutToken();
  }

  /**
   * JS-SEC-147 (CWE-352): mints a single-use logout token for the current session. The value
   * is URL-safe. A session keeps at most {@value #MAX_PENDING_TOKENS} unused tokens.
   *
   * @return the token to pass as the {@value #LOGOUT_TOKEN_PARAMETER} query parameter
   * @throws IllegalStateException when no Vaadin session is bound to the thread
   * @since 00.84.00
   */
  public static String mintLogoutToken() {
    VaadinSession session = VaadinSession.getCurrent();
    if (session == null) {
      throw new IllegalStateException(
          "No active VaadinSession - a logout token is bound to the session it is minted in");
    }
    byte[] random = new byte[32];
    RANDOM.nextBytes(random);
    String token = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
    PendingLogoutTokens pending = session.getAttribute(PendingLogoutTokens.class);
    if (pending == null) {
      pending = new PendingLogoutTokens();
      session.setAttribute(PendingLogoutTokens.class, pending);
    }
    pending.add(token);
    return token;
  }

  @Override
  public void beforeEnter(BeforeEnterEvent event) {
    List<String> tokens = event.getLocation().getQueryParameters().getParameters()
        .get(LOGOUT_TOKEN_PARAMETER);
    String token = tokens == null || tokens.isEmpty() ? null : tokens.get(0);
    if (consumeLogoutToken(token)) {
      // JS-SEC-147 (CWE-613): the component is not attached while it is being entered, so
      // getUI() is empty here - the UI of the navigation event is the one to redirect.
      performLogout(event.getUI());
      return;
    }
    // JS-SEC-147 (CWE-352): no proof that this session asked for the logout - ask.
    showConfirmation();
  }

  private void showConfirmation() {
    removeAll();
    Button confirm = new Button(confirmationButtonText(),
        click -> performLogout(click.getSource().getUI().orElseGet(UI::getCurrent)));
    confirm.setId(CONFIRM_BUTTON_ID);
    add(new Paragraph(confirmationMessage()), confirm);
  }

  private static boolean consumeLogoutToken(String token) {
    if (token == null || token.isBlank()) {
      return false;
    }
    VaadinSession session = VaadinSession.getCurrent();
    if (session == null) {
      return false;
    }
    PendingLogoutTokens pending = session.getAttribute(PendingLogoutTokens.class);
    return pending != null && pending.consume(token);
  }

  /**
   * JS-SEC-147 (CWE-613, CWE-460): the redirect is computed first, the local teardown is in
   * the {@code finally} - whatever the computation does, the session ends.
   */
  private void performLogout(UI ui) {
    VaadinSession session = VaadinSession.getCurrent();
    String redirect = null;
    try {
      // RF02: build the OP logout request while the subject is still bound.
      redirect = initiator.buildLogoutUri(endSessionEndpoint(), logoutRequest()).toString();
    } catch (RuntimeException redirectFailure) {
      logger().warn("OIDC logout: the end-session redirect could not be computed ({}). The local "
          + "session is ended and the browser is sent to the local logout target instead of the "
          + "identity provider.", redirectFailure.toString());
    } finally {
      tearDownLocalIdentity(session);
      sendBrowserTo(ui, redirect);
      closeAndInvalidate(session);
    }
  }

  private void sendBrowserTo(UI ui, String redirect) {
    try {
      String target = redirect;
      if (target == null) {
        target = localLogoutTarget();
      }
      if (ui != null && target != null) {
        ui.getPage().setLocation(target);
      }
    } catch (RuntimeException navigationFailure) {
      logger().warn("OIDC logout: sending the browser on failed: {}", navigationFailure.toString());
    }
  }

  /** The steps of {@code VaadinLogoutService}, each one guarded: none may stop the others. */
  @SuppressWarnings({"rawtypes", "unchecked"})
  private void tearDownLocalIdentity(VaadinSession session) {
    SubjectStore store = null;
    Class subjectType = null;
    Object subject = null;
    try {
      store = SubjectStores.findSubjectStore().orElse(null);
      subjectType = JCustosServiceResolver.<Object, Object>authenticationService().subjectType();
      if (store != null && subjectType != null) {
        subject = store.currentSubject(subjectType).orElse(null);
      }
    } catch (RuntimeException ignored) {
      // without a subject there is still a session to end
    }
    String subjectId = subjectIdOf(subject);
    String sessionId = sessionIdOf(session);
    Instant now = Instant.now();

    try {
      JCustosServiceResolver.sessionPolicy().onLogout(
          new SessionContext<>(subject, sessionId, now, now, null, Map.of()));
    } catch (RuntimeException ignored) {
      // never block the logout flow
    }
    try {
      if (store != null && subjectType != null) {
        store.deleteCurrentSubject(subjectType);
      }
    } catch (RuntimeException ignored) {
      // the session is closed below regardless
    }
    try {
      JCustosServiceResolver.findTokenCredentialStore().ifPresent(TokenCredentialStore::clear);
    } catch (RuntimeException ignored) {
      // the session is closed below regardless
    }
    try {
      VaadinJCustosVersionContext.clear(session);
    } catch (RuntimeException ignored) {
      // the session is closed below regardless
    }
    try {
      if (subject != null) {
        JCustosServiceResolver.securityAuditService().publish(
            new LogoutPerformed(now, subjectId, sessionId, LogoutScope.CurrentSession));
      }
    } catch (RuntimeException ignored) {
      // never block the logout flow
    }
    try {
      onBeforeLogout();
    } catch (RuntimeException hookFailure) {
      logger().warn("OIDC logout: onBeforeLogout() failed, the logout continues: {}",
          hookFailure.toString());
    }
  }

  private static void closeAndInvalidate(VaadinSession session) {
    if (session == null) {
      return;
    }
    WrappedSession wrapped = null;
    try {
      wrapped = session.getSession();
      session.close();
    } catch (RuntimeException ignored) {
      // continue with the HTTP session
    }
    try {
      if (wrapped != null) {
        wrapped.invalidate();
      }
    } catch (RuntimeException alreadyInvalidated) {
      // nothing left to invalidate
    }
  }

  /** The audit id of the subject; never {@code subject.toString()} (JS-SEC-004). */
  private static String subjectIdOf(Object subject) {
    if (subject == null) {
      return "";
    }
    try {
      Optional<SubjectIdResolver<Object>> resolver = JCustosServiceResolver.findSubjectIdResolver();
      String resolved = resolver.map(r -> r.resolve(subject).value()).orElse("");
      return resolved == null ? "" : resolved;
    } catch (RuntimeException ignored) {
      return "";
    }
  }

  private static String sessionIdOf(VaadinSession session) {
    try {
      WrappedSession wrapped = session == null ? null : session.getSession();
      return wrapped == null ? null : wrapped.getId();
    } catch (RuntimeException ignored) {
      return null;
    }
  }

  /** The unused logout tokens of one session; bounded, single-use, compared in constant time. */
  static final class PendingLogoutTokens implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private final Deque<String> tokens = new ArrayDeque<>();

    void add(String token) {
      tokens.addLast(token);
      while (tokens.size() > MAX_PENDING_TOKENS) {
        tokens.removeFirst();
      }
    }

    boolean consume(String candidate) {
      byte[] presented = candidate.getBytes(StandardCharsets.UTF_8);
      boolean found = false;
      for (Iterator<String> it = tokens.iterator(); it.hasNext();) {
        if (MessageDigest.isEqual(it.next().getBytes(StandardCharsets.UTF_8), presented)) {
          it.remove();
          found = true;
        }
      }
      return found;
    }

    int size() {
      return tokens.size();
    }
  }
}
