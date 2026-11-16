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

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;

/**
 * The storage directories under {@code src/test/resources/legacy-storage}: security stores
 * written by earlier code, in the layout before JS-SEC-125. See the README next to them for
 * how they were produced and what they contain; the data is the one
 * {@code LegacyStorageFixtureWriter} wrote.
 */
final class LegacyStorageFixtures {

  /** Written with the released 00.83.00 artefacts. */
  static final String WRITTEN_BY_00_83_00 = "written-by-00.83.00";

  /** Written with 00.84.00-SNAPSHOT of commit f3af8000, before the layout changed. */
  static final String WRITTEN_BY_00_84_00_BEFORE_JS_SEC_125 = "written-by-00.84.00-before-js-sec-125";

  /** The instant all fixture data is relative to. */
  static final Instant T0 = Instant.parse("2026-03-01T08:00:00Z");

  private LegacyStorageFixtures() {
  }

  /**
   * Copies a fixture into {@code target}, which must be an empty directory. Opening a storage
   * writes to it, so no test may open the resources themselves.
   */
  static void copyTo(String fixture, Path target) throws IOException, URISyntaxException {
    URL resource = LegacyStorageFixtures.class.getResource("/legacy-storage/" + fixture);
    if (resource == null) {
      throw new IllegalStateException("fixture not on the test class path: " + fixture);
    }
    Path source = Path.of(resource.toURI());
    List<Path> entries;
    try (Stream<Path> walk = Files.walk(source)) {
      entries = walk.toList();
    }
    for (Path entry : entries) {
      Path destination = target.resolve(source.relativize(entry).toString());
      if (Files.isDirectory(entry)) {
        Files.createDirectories(destination);
      } else {
        Files.copy(entry, destination, StandardCopyOption.REPLACE_EXISTING);
      }
    }
  }
}
