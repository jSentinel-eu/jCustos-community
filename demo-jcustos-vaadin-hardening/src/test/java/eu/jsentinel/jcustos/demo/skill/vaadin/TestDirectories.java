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
package eu.jsentinel.jcustos.demo.skill.vaadin;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bootstrap.BootstrapConfigurationLoader;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap.JCustosStorageProvider;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.ConfiguredHashingService;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.InMemoryUserDirectoryPersistence;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.PersistentUserDirectory;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.UserDirectory;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;

/**
 * Fixtures of the hardening-layer demo. The demo opens its stores under
 * {@code ./data}; the tests point every store, the user directory and the bootstrap
 * token file at a temporary directory before the demo's bootstrap runs.
 */
final class TestDirectories {

  /** A token in the generator's format (JS-SEC-130): five groups of four, no O, I, 0, 1. */
  static final String KNOWN_TOKEN = "TEST-TKNS-2222-3333-AAAA";

  private static Path tokenFile;

  private TestDirectories() {
  }

  /**
   * Once per JVM: storage in a temporary directory, an in-memory user directory, and a
   * bootstrap token file holding {@link #KNOWN_TOKEN} (owner-only, as the store requires).
   */
  static synchronized void isolateStorage() {
    if (tokenFile != null) {
      return;
    }
    try {
      Path storage = Files.createTempDirectory("jcustos-demo-storage");
      installStorage(storage);
      UserDirectoryProvider.setDirectory(fresh());
      tokenFile = Files.createTempFile("jcustos-demo-bootstrap", ".token");
      writeKnownToken();
      System.setProperty(BootstrapConfigurationLoader.TOKEN_FILE_PROPERTY, tokenFile.toString());
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /**
   * Rewrites the token file with {@link #KNOWN_TOKEN}, freshly created and owner-only: a
   * completed setup consumes the file, and a file recreated with the default umask would be
   * refused as planted (JS-SEC-130).
   */
  static void writeKnownToken() {
    try {
      Files.writeString(tokenFile,
          "token=" + KNOWN_TOKEN + System.lineSeparator()
              + "createdAt=" + Instant.now() + System.lineSeparator());
      if (Files.getFileStore(tokenFile).supportsFileAttributeView(PosixFileAttributeView.class)) {
        Files.setPosixFilePermissions(tokenFile, PosixFilePermissions.fromString("rw-------"));
      }
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private static void installStorage(Path storage) {
    JCustosStorageProvider.setStorage(
        eu.jsentinel.jcustos.persistence.eclipsestore.EclipseStoreJCustosStorage.openAt(storage));
  }

  /** Forgets the first-administrator wiring, so the next use captures the current directory. */
  static void resetBootstrapWiring() {
    try {
      var field = BootstrapWiring.class.getDeclaredField("current");
      field.setAccessible(true);
      field.set(null, null);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError("cannot reset BootstrapWiring: " + e);
    }
  }

  /** An empty directory on the demo's configured hashing service. */
  static UserDirectory fresh() {
    return new PersistentUserDirectory(new InMemoryUserDirectoryPersistence(),
        ConfiguredHashingService.INSTANCE);
  }

  static SessionRecord record(String sessionId, String subjectId) {
    Instant now = Instant.now();
    return new SessionRecord(SessionId.of(sessionId), SubjectId.of(subjectId), TenantId.DEFAULT,
        now, now, JCustosVersion.INITIAL, SessionStatus.ACTIVE);
  }
}
