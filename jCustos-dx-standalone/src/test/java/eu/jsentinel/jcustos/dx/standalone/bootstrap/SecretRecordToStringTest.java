/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.dx.standalone.bootstrap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** SA27 follow-up (JS-SEC-127, CWE-532): the string form of the prompted credentials has no secret. */
@DisplayName("JS-SEC-127 — InteractiveLoginPrompt.Credentials masks the secret")
class SecretRecordToStringTest {

  @Test
  @DisplayName("the secret is masked, the user name stays readable")
  void credentials() {
    String text = new InteractiveLoginPrompt.Credentials("alice", "s3cr3t-Horse".toCharArray()).toString();
    assertFalse(text.contains("s3cr3t-Horse"), text);
    assertTrue(text.contains("username=alice"), text);
  }
}
