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
package eu.jsentinel.jcustos.util;

import eu.jsentinel.jcustos.credential.store.CredentialRecord;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.store.InMemoryCredentialStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** JS-SEC-123 (CWE-178): one key per account, whatever the spelling. */
@DisplayName("SubjectKeyCanonicalizer")
class SubjectKeyCanonicalizerTest {

  private final SubjectKeyCanonicalizer defaults = SubjectKeyCanonicalizer.defaults();

  @Test
  @DisplayName("defaults fold case, surrounding whitespace and compatibility forms")
  void defaultsFold() {
    assertEquals("alice", defaults.canonicalize("alice"));
    assertEquals("alice", defaults.canonicalize("ALICE"));
    assertEquals("alice", defaults.canonicalize("  Alice\t"));
    assertEquals("alice", defaults.canonicalize("\u00A0Alice\u2003"), "no-break and em space");
    assertEquals("alice", defaults.canonicalize("\uFF21\uFF4C\uFF49\uFF43\uFF45"), "full-width letters");
    assertEquals("file", defaults.canonicalize("\uFB01le"), "the fi ligature");
    assertEquals("alice smith", defaults.canonicalize("Alice Smith"), "inner whitespace stays");
    assertEquals("", defaults.canonicalize("   "));
  }

  @Test
  @DisplayName("defaults do not depend on the default locale: I stays i, also under tr-TR")
  void defaultsAreLocaleIndependent() {
    java.util.Locale before = java.util.Locale.getDefault();
    try {
      java.util.Locale.setDefault(java.util.Locale.forLanguageTag("tr-TR"));
      assertEquals("istanbul", defaults.canonicalize("ISTANBUL"));
    } finally {
      java.util.Locale.setDefault(before);
    }
  }

  @Test
  @DisplayName("defaults are idempotent, also where lower-casing decomposes a character")
  void defaultsAreIdempotent() {
    String[] samples = {"Alice", " \u0130stanbul ", "\u00C5ngstr\u00F6m", "\u2126hm", "\u0001\u2028x\u2028\u0001",
        "\uFF21\u0301", "stra\u00DFe"};
    for (String sample : samples) {
      String once = defaults.canonicalize(sample);
      assertEquals(once, defaults.canonicalize(once), "not stable for " + sample);
    }
  }

  @Test
  @DisplayName("different names stay different")
  void differentNamesStayDifferent() {
    assertNotEquals(defaults.canonicalize("alice"), defaults.canonicalize("alice2"));
    assertNotEquals(defaults.canonicalize("al ice"), defaults.canonicalize("alice"));
  }

  @Test
  @DisplayName("exact() changes nothing")
  void exactChangesNothing() {
    assertEquals(" ALICE ", SubjectKeyCanonicalizer.exact().canonicalize(" ALICE "));
  }

  @Test
  @DisplayName("JS-SEC-123: a name over the cap is not normalised; it gets a bounded, stable, idempotent key")
  void overlongNameGetsABoundedKey() {
    // U+FDFA expands to eighteen characters under NFKC
    String expanding = "\uFDFA".repeat(SubjectKeyCanonicalizer.MAX_RAW_LENGTH + 1);
    String key = defaults.canonicalize(expanding);

    assertTrue(key.startsWith(SubjectKeyCanonicalizer.OVERLONG_KEY_PREFIX), key);
    assertEquals(SubjectKeyCanonicalizer.OVERLONG_KEY_PREFIX.length() + 64, key.length());
    assertEquals(key, defaults.canonicalize(expanding), "stable");
    assertEquals(key, defaults.canonicalize(key), "idempotent");
    assertNotEquals(key, defaults.canonicalize(expanding + "x"), "different names, different keys");

    String atTheCap = "\uFDFA".repeat(SubjectKeyCanonicalizer.MAX_RAW_LENGTH);
    assertEquals(18 * SubjectKeyCanonicalizer.MAX_RAW_LENGTH,
        defaults.canonicalize(atTheCap).length(), "up to the cap the name is normalised");
  }

  @Test
  @DisplayName("JS-SEC-123: an over-long name is an unknown user in the credential store, not an error")
  void overlongNameIsAnUnknownUser() {
    InMemoryCredentialStore store = new InMemoryCredentialStore();
    store.register(CredentialRecord.initial("alice", "encoded-alice", CredentialStatus.ACTIVE,
        Instant.parse("2026-11-16T10:00:00Z")));
    String overlong = "alice" + " ".repeat(SubjectKeyCanonicalizer.MAX_RAW_LENGTH);

    assertTrue(store.findByUsername(overlong).isEmpty(), "padding beyond the cap is not trimmed");
    assertTrue(store.findByUsername("\uFDFA".repeat(100_000)).isEmpty());
    assertTrue(store.findByUsername("alice").isPresent());
  }
}
