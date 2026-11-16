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
package eu.jsentinel.jcustos.demo.rest.server;

import eu.jsentinel.jcustos.rest.RestAuthorizationFilter;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * JS-SEC-114 (CWE-862): {@link DemoHttpRouter} authorises every protected route with the
 * handler-class overload of {@link RestAuthorizationFilter}. This test resolves each routed
 * handler method the same way - method plus handler class - and proves that none of them
 * would be served by omission. All routed methods are declared by {@link DemoHandlers}
 * itself, so the method-only overload would decide the same today; the test keeps the
 * class-aware view the router uses honest when a handler moves into a base class.
 */
@DisplayName("Demo REST handlers — every routed handler is restricted as seen from its handler class")
class DemoHandlerRestrictionTest {

  @ParameterizedTest(name = "{0}")
  @ValueSource(strings = {
      "listDocuments", "createDocument", "deleteDocument", "inspectDocuments",
      "createApiKey", "revokeApiKey", "inspectOwnedDocument", "adminStatus",
      "auditEvents", "listUsers", "setUserRole", "createUser", "deleteUser"})
  void routedHandlerIsNotOpenByOmission(String name) throws NoSuchMethodException {
    Method method = DemoHandlers.class.getMethod(name, RestRequest.class, RestResponse.class);
    assertFalse(RestAuthorizationFilter.isOpenByOmission(method, DemoHandlers.class),
        name + " must carry a restriction the class-aware scan sees");
  }
}
