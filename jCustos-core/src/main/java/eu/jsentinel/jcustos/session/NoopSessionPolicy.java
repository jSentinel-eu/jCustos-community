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
 * Inert {@link SessionPolicy} — every navigation continues, login and
 * logout do nothing.
 *
 * <p>Until 00.83.00 this was the resolver fallback; since 00.84.00 the
 * fallback is the enforcing {@link TimeoutSessionPolicy#secureDefault(String)}
 * (JS-SEC-065, CWE-1188). Register this policy explicitly to opt out of
 * session-lifetime enforcement — the Vaadin {@code SessionLifetimeListener}
 * reports that choice once at WARN.
 *
 * @param <U> subject type
 */
public final class NoopSessionPolicy<U> implements SessionPolicy<U> {

  @SuppressWarnings("rawtypes")
  private static final NoopSessionPolicy INSTANCE = new NoopSessionPolicy<>();

  /**
   * Returns the singleton, narrowed to the caller's subject type.
   *
   * @param <U> the caller's subject type
   * @return the shared {@link NoopSessionPolicy} instance
   */
  @SuppressWarnings("unchecked")
  public static <U> NoopSessionPolicy<U> instance() {
    return (NoopSessionPolicy<U>) INSTANCE;
  }

  /** Public for {@link java.util.ServiceLoader} discovery. Prefer {@link #instance()}. */
  public NoopSessionPolicy() {
  }

  @Override
  public SessionDecision beforeNavigation(SessionContext<U> context) {
    return SessionDecision.Continue.INSTANCE;
  }
}
