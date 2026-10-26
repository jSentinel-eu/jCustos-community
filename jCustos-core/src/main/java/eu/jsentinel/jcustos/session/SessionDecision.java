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
package eu.jsentinel.jcustos.session;

/**
 * Outcome of a {@link SessionPolicy#beforeNavigation(SessionContext)}
 * decision.
 * <p>
 * Adapters interpret the result:
 * <ul>
 *   <li>{@link Continue} — let the navigation proceed.</li>
 *   <li>{@link RequireLogin} — drop the subject (if any) and forward to
 *       {@code loginRoute}. Used for "your session has expired —
 *       sign in again" situations.</li>
 *   <li>{@link Invalidate} — drop the subject, invalidate the session
 *       (HTTP / Vaadin), and forward to {@code loginRoute}. Used when
 *       the policy actively wants to destroy the session, not just
 *       force re-authentication.</li>
 * </ul>
 */
public sealed interface SessionDecision
    permits SessionDecision.Continue,
            SessionDecision.RequireLogin,
            SessionDecision.Invalidate {

  /** The navigation may proceed unchanged. */
  record Continue() implements SessionDecision {

    /** Shared singleton — there is only one shape of {@code Continue}. */
    public static final Continue INSTANCE = new Continue();
  }

  /**
   * The subject must re-authenticate. The session itself can stay alive
   * — only the subject snapshot must be dropped.
   *
   * @param loginRoute target route to forward to (e.g. {@code "/login"})
   */
  record RequireLogin(String loginRoute) implements SessionDecision {
  }

  /**
   * The session must be invalidated. Interpretation depends on the
   * lifecycle hook that returned the decision:
   * <ul>
   *   <li>From {@link SessionPolicy#beforeNavigation(SessionContext)} —
   *       the session is expired/destroyed; drop the subject, invalidate
   *       the session, forward to {@code loginRoute}.</li>
   *   <li>From {@link SessionPolicy#onLogin(SessionContext)} —
   *       session-fixation rotation. Since 00.84.00 (JS-SEC-060) the Vaadin
   *       adapter rotates the id through
   *       {@code HttpServletRequest.changeSessionId()} <em>before</em> it
   *       calls {@code onLogin}, so the decision only contributes the audit
   *       reason; the just-bound subject survives and the flow continues to
   *       the original post-login navigation target. {@code loginRoute} is
   *       ignored in this context.</li>
   * </ul>
   *
   * @param reason     short, generic reason (safe for logs)
   * @param loginRoute target route to forward to after invalidation
   *                   (ignored when returned from {@code onLogin})
   */
  record Invalidate(String reason, String loginRoute) implements SessionDecision {
  }

  /**
   * Returns the shared {@link Continue} singleton. Convenience for the
   * common case in {@link SessionPolicy} implementations.
   *
   * @return the singleton continue decision
   */
  static Continue cont() {
    return Continue.INSTANCE;
  }
}
