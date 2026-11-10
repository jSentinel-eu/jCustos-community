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
package eu.jsentinel.jcustos.policy.spi;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.policy.api.Policy;
import eu.jsentinel.jcustos.policy.api.PolicyContext;
import eu.jsentinel.jcustos.policy.api.PolicyDecision;

import java.util.Optional;

/**
 * Lookup + evaluation SPI for named policies.
 * <p>
 * Discovered via {@code java.util.ServiceLoader}; consuming applications
 * register a default implementation in
 * {@code META-INF/services/eu.jsentinel.jcustos.policy.spi.PolicyRegistry}.
 * If no implementation is registered, the {@code JCustosServiceResolver}
 * supplies an in-memory default.
 *
 * <p>Implementations should be thread-safe: registration typically
 * happens at startup, evaluation runs on every protected access.
 */
@ExperimentalJCustosApi
public interface PolicyRegistry {

  /**
   * Registers a policy. Implementations decide whether duplicate names
   * replace or reject the existing entry — see the implementation's
   * Javadoc.
   *
   * @param policy policy; must not be {@code null}
   */
  void register(Policy policy);

  /**
   * Looks up a previously registered policy by name.
   *
   * @param name policy name
   * @return policy, if present
   */
  Optional<Policy> find(String name);

  /**
   * Evaluates the policy with the given name against the context.
   *
   * <p>If no policy is registered for {@code name}, implementations
   * return {@code Denied("unknown policy: <name>")} rather than
   * throwing — this matches the fail-closed default of the rest of the
   * framework and lets adapters fall through to a standard
   * {@code Forbidden} response without special-casing missing policies.
   *
   * @param name    policy name
   * @param context policy context
   * @return decision
   */
  PolicyDecision evaluate(String name, PolicyContext context);

  /**
   * Whether the named policy may decide a request without an authenticated
   * subject (JS-SEC-157, CWE-306). The enforcement paths ask this before they
   * evaluate a policy for an anonymous request; {@code false} makes them answer
   * <em>unauthenticated</em>.
   *
   * <p>The default looks the policy up through {@link #find(String)} and reads
   * {@link Policy#allowsAnonymous()}; an unknown policy does not allow
   * anonymous evaluation. Registries that keep policies elsewhere override it.
   *
   * @param name policy name
   * @return {@code true} only when the policy is known and opted in
   * @since 00.84.00
   */
  default boolean allowsAnonymous(String name) {
    Optional<Policy> policy = find(name);
    return policy != null && policy.map(Policy::allowsAnonymous).orElse(false);
  }
}
