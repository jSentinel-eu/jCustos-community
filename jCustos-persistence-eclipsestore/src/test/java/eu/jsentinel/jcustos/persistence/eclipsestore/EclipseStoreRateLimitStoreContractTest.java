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

import eu.jsentinel.jcustos.persistence.testkit.RateLimitStoreContract;
import eu.jsentinel.jcustos.ratelimiting.RateLimitStore;

class EclipseStoreRateLimitStoreContractTest
    extends EclipseStoreContractTestBase
    implements RateLimitStoreContract {

  @Override
  public RateLimitStore newStore() {
    return storage.rateLimitStore();
  }

  /** JS-SEC-166: node B gets an adapter of its own over the same storage. */
  @Override
  public RateLimitStore secondNodeStore(RateLimitStore store) {
    return storage.rateLimitStore();
  }
}
