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
package eu.jsentinel.jcustos.jwt.api;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** JS-SEC-098 (CWE-1041): the single segment counter of the JOSE parsers. */
@DisplayName("JS-SEC-098 — JoseLimits.countSegments")
class JoseLimitsCountSegmentsTest {

  @Test
  @DisplayName("counts the dot-separated segments of a compact serialisation")
  void counts() {
    assertEquals(3, JoseLimits.countSegments("aGVhZA.Y2xhaW1z.c2ln"));
    assertEquals(5, JoseLimits.countSegments("aGVhZA.a2V5.aXY.Y2lwaGVy.dGFn"));
    assertEquals(3, JoseLimits.countSegments("aGVhZA.Y2xhaW1z."), "an empty last segment still counts");
    assertEquals(1, JoseLimits.countSegments("no-dots"));
    assertEquals(1, JoseLimits.countSegments(""));
    assertEquals(4, JoseLimits.countSegments("..."));
  }

  @Test
  @DisplayName("null is a NullPointerException, as in the three copies it replaces")
  void nullInput() {
    assertThrows(NullPointerException.class, () -> JoseLimits.countSegments(null));
  }
}
