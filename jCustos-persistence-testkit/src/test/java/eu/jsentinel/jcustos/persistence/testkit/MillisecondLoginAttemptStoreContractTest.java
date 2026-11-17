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
package eu.jsentinel.jcustos.persistence.testkit;

import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptStore;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptKey;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Runs {@link AtomicLoginAttemptStoreContract} against a store that keeps instants in
 * milliseconds, as a JDBC {@code TIMESTAMP(3)} column does: an atomic store that cuts every
 * instant before it reaches the in-memory store underneath. Proves that the contract accepts
 * such a store - and, through its {@code CWE-778} tests, that the store-backed policy audits
 * the lockouts it reports.
 */
class MillisecondLoginAttemptStoreContractTest implements AtomicLoginAttemptStoreContract {

  @Override
  public LoginAttemptStore newStore() {
    return new MillisecondStore(new InMemoryLoginAttemptStore());
  }

  private static final class MillisecondStore implements LoginAttemptStore {
    private final LoginAttemptStore inner;

    private MillisecondStore(LoginAttemptStore inner) {
      this.inner = inner;
    }

    private static Instant cut(Instant instant) {
      return requireNonNull(instant, "instant must not be null").truncatedTo(ChronoUnit.MILLIS);
    }

    @Override
    public void recordFailure(LoginAttemptKey key, Instant at) {
      inner.recordFailure(key, cut(at));
    }

    @Override
    public int failureCount(LoginAttemptKey key) {
      return inner.failureCount(key);
    }

    @Override
    public Optional<Instant> lastFailureAt(LoginAttemptKey key) {
      return inner.lastFailureAt(key);
    }

    @Override
    public void reset(LoginAttemptKey key) {
      inner.reset(key);
    }

    @Override
    public AttemptStatus tryBeginAttempt(LoginAttemptKey key, Instant now, AttemptLimits limits) {
      return inner.tryBeginAttempt(key, cut(now), limits);
    }

    @Override
    public AttemptStatus completeFailure(LoginAttemptKey key, Instant now, AttemptLimits limits) {
      return inner.completeFailure(key, cut(now), limits);
    }

    @Override
    public AttemptStatus completeSuccess(LoginAttemptKey key, Instant now, AttemptLimits limits) {
      return inner.completeSuccess(key, cut(now), limits);
    }

    @Override
    public void abandonAttempt(LoginAttemptKey key, Instant now) {
      inner.abandonAttempt(key, cut(now));
    }
  }
}
