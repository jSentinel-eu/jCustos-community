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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bootstrap.BootstrapState;
import eu.jsentinel.jcustos.bootstrap.BootstrapStateStore;

import java.util.Optional;

import static java.util.Objects.requireNonNull;

/** Eclipse-Store-backed {@link BootstrapStateStore}; one entry per tenant, not bounded. */
final class EclipseStoreBootstrapStateStore implements BootstrapStateStore {

  private final EclipseStoreJCustosStorage storage;

  EclipseStoreBootstrapStateStore(EclipseStoreJCustosStorage storage) {
    this.storage = storage;
  }

  @Override
  public Optional<BootstrapState> find(TenantId tenant) {
    requireNonNull(tenant, "tenant must not be null");
    return storage.read(() -> Optional.ofNullable(storage.tables().bootstrapStates.get(tenant)));
  }

  @Override
  public void save(BootstrapState state) {
    requireNonNull(state, "state must not be null");
    storage.update(() -> storage.tables().bootstrapStates.put(state.tenant(), state));
  }

  @Override
  public boolean delete(TenantId tenant) {
    requireNonNull(tenant, "tenant must not be null");
    return storage.write(() -> storage.tables().bootstrapStates.remove(tenant) != null);
  }
}
