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
package eu.jsentinel.jcustos.persistence.eclipsestore;

import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.JCustosVersionStore;

import static java.util.Objects.requireNonNull;

/**
 * Eclipse-Store-backed {@link JCustosVersionStore}; one entry per subject whose
 * version was ever raised, not bounded — a version that is dropped would make
 * stale sessions valid again.
 */
final class EclipseStoreJCustosVersionStore implements JCustosVersionStore {

  private final EclipseStoreJCustosStorage storage;

  EclipseStoreJCustosVersionStore(EclipseStoreJCustosStorage storage) {
    this.storage = storage;
  }

  @Override
  public JCustosVersion current(JCustosVersionKey key) {
    requireNonNull(key, "key must not be null");
    return storage.read(() -> {
      JCustosVersion v = storage.tables().securityVersions.get(key);
      return v == null ? JCustosVersion.INITIAL : v;
    });
  }

  @Override
  public JCustosVersion increment(JCustosVersionKey key) {
    requireNonNull(key, "key must not be null");
    return storage.write(() -> {
      JCustosVersion prev = storage.tables().securityVersions.get(key);
      JCustosVersion next = prev == null
          ? JCustosVersion.INITIAL.next()
          : prev.next();
      storage.tables().securityVersions.put(key, next);
      return next;
    });
  }

  @Override
  public void reset(JCustosVersionKey key) {
    requireNonNull(key, "key must not be null");
    storage.update(() -> storage.tables().securityVersions.remove(key));
  }
}
