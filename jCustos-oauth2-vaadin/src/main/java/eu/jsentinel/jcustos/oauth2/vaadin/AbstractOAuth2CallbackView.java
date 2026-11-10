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
package eu.jsentinel.jcustos.oauth2.vaadin;

/*-
 * #%L
 * jCustos OAuth2 — Vaadin callback adapter
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.authorization.LoginSessionRotation;
import eu.jsentinel.jcustos.oauth2.api.AuthorizationCodeFlow;
import eu.jsentinel.jcustos.oauth2.api.CallbackResult;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.session.vaadin.VaadinSessionRevocation;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterObserver;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Reusable base for the Vaadin OAuth2 redirect-callback route (Konzept §6.5,
 * V00.77). The consumer maps it to a {@code @Route} (e.g. {@code "oauth2/callback"})
 * and supplies the {@link AuthorizationCodeFlow}, a token sink and the post-login
 * navigation target. On entry it reads {@code code} + {@code state} (or
 * {@code error}) from the query string, drives the flow (single-use state + PKCE
 * exchange) and forwards to {@link #successTarget()} or {@link #errorTarget()} —
 * tokens are never rendered into the page.
 *
 * <p><strong>Session fixation (JS-SEC-146, CWE-384).</strong> After a successful
 * {@link #onTokens(CallbackResult)} the view runs
 * {@link LoginSessionRotation#afterLogin(LoginSessionRotation.RotationHook)}, the same
 * sequence {@code LoginView} runs: the HTTP session id is rotated, the {@code SessionPolicy}
 * observes the login, the rotation is audited, {@link #onSessionRotated(String, String)} is
 * called and the security-version snapshot is recorded. Until 00.84.00 the callback bound
 * the tokens into the session the browser had arrived with and kept its id, so an attacker
 * who had planted that id in the victim's browser was logged in as the victim. The rotation
 * is not optional and the view <em>fails closed</em>: when the id cannot be rotated, the
 * login is undone - subject, snapshot and token credential cleared, {@code SessionInvalidated}
 * audited with the reason {@value #REASON_ROTATION_FAILED}, the session closed and the HTTP
 * session invalidated - and the view forwards to {@link #errorTarget()}.
 */
public abstract class AbstractOAuth2CallbackView extends Div
    implements BeforeEnterObserver, HasLogger {

  /** Audit reason when the login is undone because the session id could not be rotated. */
  public static final String REASON_ROTATION_FAILED = "RotationAfterLoginFailed";

  /** @return the configured authorization-code flow (state store + token client). */
  protected abstract AuthorizationCodeFlow flow();

  /**
   * Binds the callback outcome (e.g. into the session / subject store). JS-SEC-059: the argument is
   * a {@link CallbackResult} — {@code result.tokens()} plus the stored {@code nonce()} and
   * {@code resumeTarget()} — so an overriding view that validates the {@code id_token} can enforce
   * the nonce via {@code IdTokenExpectations.of(issuer, audience, result.nonce())}.
   */
  protected abstract void onTokens(CallbackResult result);

  /** @return the route to forward to after a successful login. */
  protected abstract String successTarget();

  /** @return the route to forward to on any callback failure (default: the app root). */
  protected String errorTarget() {
    return "";
  }

  /**
   * Called once per successful login after the HTTP session id has rotated, with the id the
   * session had before and the id it carries now (JS-SEC-146, CWE-384). Override it to create
   * or re-key anything that is keyed by the session id - a {@code SessionStore} record, a
   * {@code SubjectSessionRegistry} entry - so revocation by id reaches the live session.
   * Records written inside {@link #onTokens(CallbackResult)} carry the pre-rotation id and
   * must be moved here. Exceptions are logged and never block the login. The default does
   * nothing.
   *
   * @param previousSessionId the id before the rotation
   * @param currentSessionId  the surviving id
   * @since 00.84.00
   */
  protected void onSessionRotated(String previousSessionId, String currentSessionId) {
    // default: nothing to re-key
  }

  @Override
  public void beforeEnter(BeforeEnterEvent event) {
    Map<String, List<String>> query = event.getLocation().getQueryParameters().getParameters();
    String state = first(query, "state");
    if (state == null || state.isBlank()) {
      event.forwardTo(errorTarget());
      return;
    }
    // JS-SEC-150 (CWE-346, RFC 9207): the issuer of the response goes to the flow, which
    // compares it with the expected issuer before it consumes the state or exchanges the
    // code. A response naming several issuers is not the response of one authorisation server.
    List<String> issuers = query.getOrDefault("iss", List.of());
    if (issuers.size() > 1) {
      event.forwardTo(errorTarget());
      return;
    }
    AuthorizationCodeFlow.CallbackParams params = new AuthorizationCodeFlow.CallbackParams(
        opt(first(query, "code")), state, opt(first(query, "error")),
        opt(first(query, "error_description")), opt(first(query, "iss")));

    Result<CallbackResult, OAuth2Error> result = flow().handleCallback(params);
    if (result.isSuccess()) {
      onTokens(result.toOptional().orElseThrow());
      // JS-SEC-146 (CWE-384): a federated login rotates the session id like every other
      // login - unconditionally, and before the user reaches the application.
      LoginSessionRotation.Outcome rotation = LoginSessionRotation.afterLogin(this::onSessionRotated);
      if (!rotation.rotated()) {
        // Fail closed: tokens bound to a session id an attacker may know are worse than a
        // failed login.
        logger().warn("OAuth2 login aborted: the session id could not be rotated after the "
            + "callback, so the login would have stayed on its pre-login session id.");
        VaadinSessionRevocation.endCurrentSession(REASON_ROTATION_FAILED);
        event.forwardTo(errorTarget());
        return;
      }
      event.forwardTo(successTarget());
    } else {
      event.forwardTo(errorTarget());
    }
  }

  private static String first(Map<String, List<String>> query, String key) {
    List<String> values = query.get(key);
    return (values == null || values.isEmpty()) ? null : values.get(0);
  }

  private static Optional<String> opt(String value) {
    return (value == null || value.isBlank()) ? Optional.empty() : Optional.of(value);
  }
}
