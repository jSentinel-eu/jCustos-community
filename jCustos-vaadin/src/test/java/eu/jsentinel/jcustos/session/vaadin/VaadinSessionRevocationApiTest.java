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
package eu.jsentinel.jcustos.session.vaadin;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;

import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Exit review XR09-5: {@link VaadinSessionRevocation#reset()} forgets the registered store and
 * every tracked session, which switches the revocation check off for the whole process. It is
 * a helper for the tests of this package and must not be callable by application code.
 */
@DisplayName("XR09-5 - the process-wide reset of the revocation check is not public")
class VaadinSessionRevocationApiTest {

  @Test
  @DisplayName("reset() is not part of the public API")
  void resetIsNotPublic() throws NoSuchMethodException {
    int modifiers = VaadinSessionRevocation.class.getDeclaredMethod("reset").getModifiers();

    assertFalse(Modifier.isPublic(modifiers), "reset() would let any code switch the check off");
    assertFalse(Modifier.isProtected(modifiers));
  }
}
