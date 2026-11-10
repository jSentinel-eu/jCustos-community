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

import eu.jsentinel.jcustos.bruteforce.LoginAttemptKey;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptStore;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Objects.requireNonNull;

/**
 * Runs {@link LoginAttemptStoreContract} against a store that implements
 * only the four counter methods and inherits the attempt operations from
 * the SPI defaults - the shape of a third-party store written before
 * 00.84.00. Proves that the base contract does not demand more than the
 * defaults deliver; the atomic guarantees are a separate contract.
 */
class CounterOnlyLoginAttemptStoreContractTest implements LoginAttemptStoreContract {

  @Override
  public LoginAttemptStore newStore() {
    return new CounterOnlyStore();
  }

  private static final class CounterOnlyStore implements LoginAttemptStore {

    private record Entry(int count, Instant last) {
    }

    private final ConcurrentHashMap<LoginAttemptKey, Entry> entries = new ConcurrentHashMap<>();

    @Override
    public void recordFailure(LoginAttemptKey key, Instant at) {
      requireNonNull(key, "key must not be null");
      requireNonNull(at, "at must not be null");
      entries.merge(key, new Entry(1, at), (old, fresh) -> new Entry(old.count() + 1, at));
    }

    @Override
    public int failureCount(LoginAttemptKey key) {
      requireNonNull(key, "key must not be null");
      Entry entry = entries.get(key);
      return entry == null ? 0 : entry.count();
    }

    @Override
    public Optional<Instant> lastFailureAt(LoginAttemptKey key) {
      requireNonNull(key, "key must not be null");
      return Optional.ofNullable(entries.get(key)).map(Entry::last);
    }

    @Override
    public void reset(LoginAttemptKey key) {
      requireNonNull(key, "key must not be null");
      entries.remove(key);
    }
  }
}
