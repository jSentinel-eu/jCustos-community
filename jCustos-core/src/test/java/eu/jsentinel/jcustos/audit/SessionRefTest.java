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
package eu.jsentinel.jcustos.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SessionRef (JS-SEC-117)")
class SessionRefTest {

  private static final String TOKEN = "eyJhbGciOiJub25lIn0.synthetic-bearer-token.0123456789";

  @Test
  @DisplayName("a reference is the marker plus 16 hex characters and never contains the identifier")
  void shape() {
    String reference = SessionRef.of(TOKEN);

    assertTrue(reference.matches("sref-[0-9a-f]{16}"), reference);
    assertEquals(SessionRef.PREFIX.length() + SessionRef.HEX_LENGTH, reference.length());
    assertFalse(reference.contains(TOKEN));
    assertTrue(SessionRef.isReference(reference));
  }

  @Test
  @DisplayName("the reference is the truncated SHA-256 of the identifier")
  void knownValue() {
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    assertEquals("sref-ba7816bf8f01cfea", SessionRef.of("abc"));
  }

  @Test
  @DisplayName("stable per identifier, distinct between identifiers")
  void stableAndDistinct() {
    assertEquals(SessionRef.of(TOKEN), SessionRef.of(TOKEN));
    assertNotEquals(SessionRef.of(TOKEN), SessionRef.of(TOKEN + "x"));
  }

  @Test
  @DisplayName("of() is idempotent: a reference is returned unchanged, however often it is applied")
  void idempotent() {
    String once = SessionRef.of(TOKEN);

    assertEquals(once, SessionRef.of(once));
    assertEquals(once, SessionRef.of(SessionRef.of(once)));
  }

  @Test
  @DisplayName("only the exact shape is a reference; everything else is hashed")
  void recognitionIsStrict() {
    assertFalse(SessionRef.isReference(null));
    assertFalse(SessionRef.isReference(""));
    assertFalse(SessionRef.isReference("0123456789abcdef"), "bare hex without the marker");
    assertFalse(SessionRef.isReference("sref-0123456789abcde"), "one character short");
    assertFalse(SessionRef.isReference("sref-0123456789abcdef0"), "one character long");
    assertFalse(SessionRef.isReference("sref-0123456789ABCDEF"), "upper-case hex");
    assertFalse(SessionRef.isReference("sref-0123456789abcdeg"), "not hex");
    assertFalse(SessionRef.isReference("SREF-0123456789abcdef"), "marker is case-sensitive");
    assertFalse(SessionRef.isReference(" sref-0123456789abcdef"), "leading blank");

    for (String notAReference : new String[] {
        "0123456789abcdef", "sref-0123456789ABCDEF", "sref-0123456789abcdef0", "sref-"}) {
      String reduced = SessionRef.of(notAReference);
      assertNotEquals(notAReference, reduced, "must be hashed: " + notAReference);
      assertTrue(SessionRef.isReference(reduced));
    }
  }

  @Test
  @DisplayName("null: of() refuses, ofNullable() passes it through")
  void nullHandling() {
    assertThrows(NullPointerException.class, () -> SessionRef.of(null));
    assertNull(SessionRef.ofNullable(null));
    assertEquals(SessionRef.of(TOKEN), SessionRef.ofNullable(TOKEN));
  }
}
