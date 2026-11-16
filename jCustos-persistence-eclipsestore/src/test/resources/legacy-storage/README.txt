Storage directories in the layout of the releases before JS-SEC-125 (00.84.00)
==============================================================================

LegacyStorageCompatibilityTest copies these directories to a temporary directory and opens them
with the current code. They prove that a security store written by an earlier release still opens,
keeps every record and works afterwards.

  written-by-00.83.00/
      written with the released artefacts eu.jsentinel:jCustos-core:00.83.00 and
      eu.jsentinel:jCustos-persistence-eclipsestore:00.83.00 (Eclipse Store 4.1.0)

  written-by-00.84.00-before-js-sec-125/
      written with the classes of commit f3af8000 - 00.84.00-SNAPSHOT after JS-SEC-122 and
      JS-SEC-129 (root field refreshTokenInvalidBefore), before the stored layout changed;
      run with the argument "with-revoke-all", so it also carries an "invalid before" mark

  written-by-00.84.00-before-remember-me-marks/
      written with the classes of commit 4ad59859 - 00.84.00-SNAPSHOT in the layout of JS-SEC-125,
      before the table of remember-me "invalid before" marks (JS-SEC-129, exit review XR07) was
      added to EclipseStoreJCustosRoot.Tables; run with the argument "with-revoke-all".
      Opened by RememberMeMarkLayoutCompatibilityTest.

These were produced by LegacyStorageFixtureWriter (source next to this file, kept as .txt so that it
is not compiled with the tests; it uses the public API only). Synthetic data only.

  javac -cp <core>:<persistence-eclipsestore>:<eclipse-store 4.1.0 jars>:<slf4j> \
        -d out LegacyStorageFixtureWriter.java
  java --add-exports java.base/jdk.internal.misc=ALL-UNNAMED -cp out:<same class path> \
        LegacyStorageFixtureWriter <empty directory> [with-revoke-all]

Do not regenerate these directories with current code: their value is that older code wrote them.
The files are binary; a patch that carries them has to be made with "git diff --binary".

  written-by-00.83.00-credential-records/
      not a security store: an application root - a java.util.ArrayList - holding three
      CredentialRecord rows in the six-component shape before JS-SEC-161, written with
      eu.jsentinel:jCustos-core:00.83.00 by LegacyCredentialRecordFixtureWriter (source next to
      this file, as .txt). It stands for an application that keeps credential rows in its own
      Eclipse-Store root. Opened by LegacyCredentialRecordCompatibilityTest.
