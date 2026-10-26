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
package eu.jsentinel.jcustos.authentication;

import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2Defaults;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Pbkdf2PasswordHasherTest {

  private static final int FAST_ITERATIONS = 1_000;

  private static Pbkdf2PasswordHasher hasher() {
    return new Pbkdf2PasswordHasher(FAST_ITERATIONS, new SecureRandom());
  }

  // ── JS-SEC-072: defaults and parameter validation ────────────────

  @Test
  @DisplayName("JS-SEC-072: the default hasher writes Pbkdf2Defaults.DEFAULT_ITERATIONS (600 000)")
  void defaultIterationsFollowPbkdf2Defaults() {
    Pbkdf2PasswordHasher hasher = new Pbkdf2PasswordHasher();
    String stored = hasher.hash("x".toCharArray());
    int iterations = hasher.parse(stored).intParameter(Pbkdf2PasswordHasher.PARAM_ITERATIONS, -1);
    assertEquals(Pbkdf2Defaults.DEFAULT_ITERATIONS, iterations);
    assertTrue(iterations >= 600_000);
    assertTrue(hasher.verify("x".toCharArray(), stored));
  }

  @Test
  @DisplayName("JS-SEC-072: a hash written with the historical 120 000 iterations needs a rehash")
  void legacyDefaultNeedsRehash() {
    Pbkdf2PasswordHasher legacy = new Pbkdf2PasswordHasher(120_000, new SecureRandom());
    Pbkdf2PasswordHasher current = new Pbkdf2PasswordHasher();
    String stored = legacy.hash("pw".toCharArray());
    assertTrue(current.verify("pw".toCharArray(), stored), "old hashes must still verify");
    assertTrue(current.needsRehash(current.parse(stored)), "old hashes must be upgraded on next login");
  }

  @Test
  @DisplayName("JS-SEC-072: zero iterations in a stored hash yield false, not an exception (CWE-248)")
  void verifyRejectsZeroIterationsWithoutException() {
    String salt = Base64.getEncoder().withoutPadding().encodeToString(new byte[16]);
    assertFalse(hasher().verify("x".toCharArray(), "pbkdf2$0$" + salt + "$AAAA"));
    assertFalse(hasher().verify("x".toCharArray(), "pbkdf2$-5$" + salt + "$AAAA"));
  }

  @Test
  @DisplayName("JS-SEC-072: an empty or too short salt yields false, not an exception (CWE-248)")
  void verifyRejectsEmptyOrShortSaltWithoutException() {
    assertFalse(hasher().verify("x".toCharArray(), "pbkdf2$1000$$AAAA"));
    String shortSalt = Base64.getEncoder().withoutPadding().encodeToString(new byte[4]);
    assertFalse(hasher().verify("x".toCharArray(), "pbkdf2$1000$" + shortSalt + "$AAAA"));
    String longSalt = Base64.getEncoder().withoutPadding().encodeToString(new byte[65]);
    assertFalse(hasher().verify("x".toCharArray(), "pbkdf2$1000$" + longSalt + "$AAAA"));
  }

  @Test
  @DisplayName("JS-SEC-072: an iteration count above MAX_ITERATIONS is refused before deriving (CWE-400)")
  void verifyRejectsExcessiveIterationsFast() {
    String salt = Base64.getEncoder().withoutPadding().encodeToString(new byte[16]);
    String hostile = "pbkdf2$" + (Pbkdf2Defaults.MAX_ITERATIONS + 1) + "$" + salt + "$AAAA";
    long start = System.nanoTime();
    assertFalse(hasher().verify("x".toCharArray(), hostile));
    long elapsedMillis = (System.nanoTime() - start) / 1_000_000;
    assertTrue(elapsedMillis < 50, "refusal must not derive; took " + elapsedMillis + " ms");
    assertFalse(hasher().verify("x".toCharArray(), "pbkdf2$2000000000$" + salt + "$AAAA"));
  }

  @Test
  @DisplayName("JS-SEC-072: an empty hash segment yields false")
  void verifyRejectsEmptyHashSegment() {
    String salt = Base64.getEncoder().withoutPadding().encodeToString(new byte[16]);
    assertFalse(hasher().verify("x".toCharArray(), "pbkdf2$1000$" + salt + "$"));
  }

  @Test
  @DisplayName("JS-SEC-072: the constructor validates its parameters")
  void constructorValidation() {
    assertThrows(IllegalArgumentException.class, () -> new Pbkdf2PasswordHasher(0, new SecureRandom()));
    assertThrows(IllegalArgumentException.class, () -> new Pbkdf2PasswordHasher(-1, new SecureRandom()));
    assertThrows(IllegalArgumentException.class,
        () -> new Pbkdf2PasswordHasher(Pbkdf2Defaults.MAX_ITERATIONS + 1, new SecureRandom()));
    assertThrows(NullPointerException.class, () -> new Pbkdf2PasswordHasher(1_000, null));
    assertEquals(Pbkdf2Defaults.MAX_ITERATIONS, new Pbkdf2PasswordHasher(Pbkdf2Defaults.MAX_ITERATIONS,
        new SecureRandom()).parse("pbkdf2$" + Pbkdf2Defaults.MAX_ITERATIONS + "$AAAA$BBBB")
        .intParameter(Pbkdf2PasswordHasher.PARAM_ITERATIONS, -1));
  }

  @Test
  @DisplayName("hash + verify roundtrip with the same password returns true")
  void verifyAcceptsCorrectPassword() {
    Pbkdf2PasswordHasher hasher = hasher();
    String stored = hasher.hash("correct horse battery staple".toCharArray());
    assertTrue(hasher.verify("correct horse battery staple".toCharArray(), stored));
  }

  @Test
  @DisplayName("verify returns false for a wrong password against a real hash")
  void verifyRejectsWrongPassword() {
    Pbkdf2PasswordHasher hasher = hasher();
    String stored = hasher.hash("right".toCharArray());
    assertFalse(hasher.verify("wrong".toCharArray(), stored));
  }

  @Test
  @DisplayName("verify returns false for a null stored hash")
  void verifyRejectsNullStoredHash() {
    assertFalse(hasher().verify("anything".toCharArray(), (String) null));
  }

  @Test
  @DisplayName("verify returns false when the stored hash has too few segments")
  void verifyRejectsTooFewSegments() {
    assertFalse(hasher().verify("x".toCharArray(), "pbkdf2$1000$saltOnly"));
  }

  @Test
  @DisplayName("verify returns false when the stored hash has too many segments")
  void verifyRejectsTooManySegments() {
    String s = "pbkdf2$1000$AAAA$BBBB$CCCC";
    assertFalse(hasher().verify("x".toCharArray(), s));
  }

  @Test
  @DisplayName("verify returns false when the algorithm prefix is wrong")
  void verifyRejectsWrongAlgorithmPrefix() {
    assertFalse(hasher().verify("x".toCharArray(), "scrypt$1000$AAAA$BBBB"));
  }

  @Test
  @DisplayName("verify returns false when the iteration count is not numeric")
  void verifyRejectsNonNumericIterations() {
    assertFalse(hasher().verify("x".toCharArray(), "pbkdf2$NOTANUMBER$AAAA$BBBB"));
  }

  @Test
  @DisplayName("verify returns false when the salt segment is not valid base64")
  void verifyRejectsCorruptSalt() {
    assertFalse(hasher().verify("x".toCharArray(), "pbkdf2$1000$@@@@$BBBB"));
  }

  @Test
  @DisplayName("verify returns false when the hash segment is not valid base64")
  void verifyRejectsCorruptHash() {
    String validSalt = Base64.getEncoder().withoutPadding().encodeToString(new byte[16]);
    assertFalse(hasher().verify("x".toCharArray(), "pbkdf2$1000$" + validSalt + "$@@@@"));
  }

  @Test
  @DisplayName("hash format is exactly four $-separated segments starting with pbkdf2")
  void hashEncodingShape() {
    String stored = hasher().hash("p".toCharArray());
    String[] parts = stored.split("\\$");
    assertEquals(4, parts.length);
    assertEquals("pbkdf2", parts[0]);
    assertEquals(String.valueOf(FAST_ITERATIONS), parts[1]);
  }

  @Test
  @DisplayName("two hashes of the same password use a fresh salt and therefore differ")
  void hashUsesFreshSaltEachCall() {
    Pbkdf2PasswordHasher hasher = hasher();
    String h1 = hasher.hash("same".toCharArray());
    String h2 = hasher.hash("same".toCharArray());
    assertNotEquals(h1, h2);
    assertNotEquals(h1.split("\\$")[2], h2.split("\\$")[2]);
  }

  @Test
  @DisplayName("hash + verify works with empty password")
  void verifyAcceptsEmptyPassword() {
    Pbkdf2PasswordHasher hasher = hasher();
    String stored = hasher.hash(new char[0]);
    assertTrue(hasher.verify(new char[0], stored));
    assertFalse(hasher.verify(new char[]{'x'}, stored));
  }

  // ── Typed PasswordHash API ───────────────────────────────────

  @Test
  @DisplayName("parse() roundtrips a hashed string into algorithm + iterations + salt + encoded")
  void parseRoundTrip() {
    Pbkdf2PasswordHasher hasher = hasher();
    String stored = hasher.hash("p".toCharArray());

    PasswordHash typed = hasher.parse(stored);

    assertEquals(Pbkdf2PasswordHasher.ALGORITHM_ID, typed.algorithm());
    assertEquals(String.valueOf(FAST_ITERATIONS),
        typed.parameters().get(Pbkdf2PasswordHasher.PARAM_ITERATIONS));
    assertEquals(stored.split("\\$")[2],
        typed.parameters().get(Pbkdf2PasswordHasher.PARAM_SALT));
    assertEquals(stored.split("\\$")[3], typed.encoded());
  }

  @Test
  @DisplayName("serialize() reproduces the wire format byte-for-byte")
  void serializeRoundTrip() {
    Pbkdf2PasswordHasher hasher = hasher();
    String stored = hasher.hash("p".toCharArray());

    String round = hasher.serialize(hasher.parse(stored));

    assertEquals(stored, round);
  }

  @Test
  @DisplayName("hashTo() returns a typed PasswordHash that verifies the same password")
  void hashToVerify() {
    Pbkdf2PasswordHasher hasher = hasher();
    PasswordHash typed = hasher.hashTo("hello".toCharArray());

    assertTrue(hasher.verify("hello".toCharArray(), typed));
    assertFalse(hasher.verify("wrong".toCharArray(), typed));
  }

  @Test
  @DisplayName("parse() rejects non-pbkdf2 hashes")
  void parseRejectsForeignAlgorithm() {
    assertThrows(IllegalArgumentException.class,
        () -> hasher().parse("scrypt$1000$AAAA$BBBB"));
    assertThrows(IllegalArgumentException.class,
        () -> hasher().parse("pbkdf2$NOTANUMBER$AAAA$BBBB"));
    assertThrows(IllegalArgumentException.class,
        () -> hasher().parse(null));
  }

  @Test
  @DisplayName("serialize() rejects malformed PasswordHash records")
  void serializeRejectsMalformed() {
    assertThrows(IllegalArgumentException.class,
        () -> hasher().serialize(null));
    assertThrows(IllegalArgumentException.class,
        () -> hasher().serialize(new PasswordHash("scrypt", "AAAA", Map.of())));
    assertThrows(IllegalArgumentException.class,
        () -> hasher().serialize(new PasswordHash("pbkdf2", "AAAA", Map.of())));
    assertThrows(IllegalArgumentException.class,
        () -> hasher().serialize(new PasswordHash("pbkdf2", "AAAA",
            Map.of("iterations", "100"))));
  }

  @Test
  @DisplayName("needsRehash false when stored iteration count matches current")
  void needsRehash_sameIterations() {
    Pbkdf2PasswordHasher hasher = new Pbkdf2PasswordHasher(FAST_ITERATIONS, new SecureRandom());
    PasswordHash stored = hasher.hashTo("p".toCharArray());

    assertFalse(hasher.needsRehash(stored));
  }

  @Test
  @DisplayName("needsRehash true when current iteration count is higher than stored")
  void needsRehash_iterationsDriftedUp() {
    Pbkdf2PasswordHasher older = new Pbkdf2PasswordHasher(1_000, new SecureRandom());
    Pbkdf2PasswordHasher newer = new Pbkdf2PasswordHasher(2_000, new SecureRandom());
    PasswordHash stored = older.hashTo("p".toCharArray());

    assertTrue(newer.needsRehash(stored));
  }

  @Test
  @DisplayName("needsRehash true when stored algorithm is not pbkdf2")
  void needsRehash_foreignAlgorithm() {
    PasswordHash legacy = new PasswordHash("bcrypt", "AAAA", Map.of("rounds", "10"));
    assertTrue(hasher().needsRehash(legacy));
  }

  @Test
  @DisplayName("needsRehash(PasswordHash) false for a null stored hash (nothing to migrate)")
  void needsRehash_nullIsFalse() {
    assertFalse(hasher().needsRehash((PasswordHash) null));
  }

  @Test
  @DisplayName("needsRehash(String) false for a null stored hash")
  void needsRehashString_nullIsFalse() {
    assertFalse(hasher().needsRehash((String) null));
  }

  @Test
  @DisplayName("needsRehash(String) parses the wire format and returns true on iteration drift")
  void needsRehashString_parsesAndDetectsDrift() {
    Pbkdf2PasswordHasher older = new Pbkdf2PasswordHasher(1_000, new SecureRandom());
    Pbkdf2PasswordHasher newer = new Pbkdf2PasswordHasher(2_000, new SecureRandom());
    String stored = older.hash("p".toCharArray());

    assertFalse(older.needsRehash(stored), "older sees its own iteration count as fresh");
    assertTrue(newer.needsRehash(stored), "newer sees iteration drift in the older's output");
  }

  @Test
  @DisplayName("needsRehash(String) returns false for malformed input")
  void needsRehashString_falseOnMalformed() {
    assertFalse(hasher().needsRehash("not-a-pbkdf2-hash"));
  }
}
