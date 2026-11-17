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

import eu.jsentinel.jcustos.session.InMemoryJCustosVersionStore;
import eu.jsentinel.jcustos.session.JCustosVersionStore;
import eu.jsentinel.jcustos.session.ObservableJCustosVersionStore;
import org.junit.jupiter.api.DisplayName;

/**
 * R8 (JS-SEC-167): a listener that throws on every change does not change what the observable
 * decorator stores or returns - the whole {@link JCustosVersionStoreContract} still holds.
 */
@DisplayName("ObservableJCustosVersionStore with a failing listener - JCustosVersionStore contract")
class ObservableJCustosVersionStoreWithFailingListenerContractTest implements JCustosVersionStoreContract {

  @Override
  public JCustosVersionStore newStore() {
    ObservableJCustosVersionStore store =
        new ObservableJCustosVersionStore(new InMemoryJCustosVersionStore());
    store.addListener((key, version) -> {
      throw new IllegalStateException("listener failure");
    });
    return store;
  }
}
