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
package eu.jsentinel.jcustos.rest;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Process-wide holder for the decision mapper a bootstrap configured.
 *
 * <p>Exists because the two layers cannot see each other directly: the
 * enforcing {@code RestAuthorizationFilter} lives in {@code jCustos-rest}
 * and applications construct it themselves, while
 * {@code RestJCustosBootstrap.decisionMapper(...)} lives one module up in
 * {@code jCustos-dx-rest}. Before V00.83 a configured mapper was recorded
 * for diagnostics and never reached the filter (JS-SEC-026); publishing
 * it here closes that gap without inverting the module dependency.
 *
 * <p>The filter reads this holder <strong>per request</strong> rather
 * than snapshotting it at construction, so an application may build its
 * filter before running the bootstrap — a real ordering, since
 * {@code DemoHttpRouter} holds its filter in a constructor field.
 *
 * <p>This is process-global state, and the most recent bootstrap owns it.
 * That matches how the framework treats every other pluggable service —
 * {@code JCustosServiceResolver.setSessionPolicy} and friends replace
 * rather than refuse — and it keeps repeated installs in one JVM (tests,
 * redeploys) working. It differs from {@code RestCorsContext}, which
 * compares record values and can therefore detect a genuine conflict; a
 * mapper is a service instance with no value identity, so every install
 * would look like a conflict.
 *
 * @since 00.83.00
 */
public final class RestDecisionContext {

  private static final AtomicReference<RestDecisionMapping> MAPPER =
      new AtomicReference<>();

  private RestDecisionContext() {
  }

  /**
   * Publishes the mapper the enforcement path should use, replacing any
   * previously published one.
   *
   * @param mapper the configured mapper (non-null)
   */
  public static void publish(RestDecisionMapping mapper) {
    MAPPER.set(java.util.Objects.requireNonNull(mapper, "mapper"));
  }

  /**
   * @return the published mapper, or empty when no bootstrap configured one
   */
  public static Optional<RestDecisionMapping> mapper() {
    return Optional.ofNullable(MAPPER.get());
  }

  /**
   * The published mapper, or the {@link HttpStatusDecisionMapper} default (JS-SEC-086):
   * every denial path of the REST adapter that has no explicit mapper of its own renders
   * through this one seam — {@link RestAuthorizationFilter}, {@link RestAuthenticationFilter}
   * and {@link RestJCustosVersionFilter} alike. Read per request, never cached, so a filter
   * built before the bootstrap ran still picks up the configured mapper.
   *
   * <p>Public since 00.84.00, so that a refusal an application writes itself - a login
   * handler's 401, an adapter of its own - goes through the same seam instead of repeating
   * {@code mapper().orElseGet(HttpStatusDecisionMapper::new)}: the configured error-body
   * strategy and the {@code WWW-Authenticate} challenge then apply there as well.
   *
   * @return the published mapper or a fresh {@link HttpStatusDecisionMapper}; never
   *         {@code null}
   * @since 00.84.00
   */
  @ExperimentalJCustosApi
  public static RestDecisionMapping mapperOrDefault() {
    return mapper().orElseGet(HttpStatusDecisionMapper::new);
  }

  /** Clears the holder. Intended for tests and redeploys. */
  public static void reset() {
    MAPPER.set(null);
  }
}
