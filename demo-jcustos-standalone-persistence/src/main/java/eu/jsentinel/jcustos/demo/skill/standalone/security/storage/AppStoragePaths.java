/*
 * Copyright © 2013 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 (the "Licence");
 * you may not use this file except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 *     https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package eu.jsentinel.jcustos.demo.skill.standalone.security.storage;

import eu.jsentinel.jcustos.persistence.eclipsestore.StorageLayout;

import java.nio.file.Path;

/**
 * Single source of truth for the application's on-disk storage base.
 *
 * <p>Production runs use {@code ./data/jcustos-standalone-persistence} as the base. Tests,
 * CI and any deployment that wants to redirect persistence elsewhere
 * override the base via the JVM system property
 * {@code -Dapp.storage.dir=/some/path}.
 *
 * <p>Since V00.74.20 the entire layout (framework + app) is owned by
 * a single {@link eu.jsentinel.jcustos.persistence.eclipsestore.JCustosStoragePair}
 * opened under {@link #baseDir()}; sub-directories are no longer this
 * class's concern — {@link StorageLayout#DEFAULT} resolves them to
 * {@code jcustos-store/} (framework) and {@code app-store/} (app)
 * underneath {@link #baseDir()}.
 *
 * <p>Wire Surefire so tests fork with
 * {@code app.storage.dir = ${project.build.directory}/test-data}:
 *
 * <pre>
 * &lt;plugin&gt;
 *   &lt;artifactId&gt;maven-surefire-plugin&lt;/artifactId&gt;
 *   &lt;configuration&gt;
 *     &lt;systemPropertyVariables&gt;
 *       &lt;app.storage.dir&gt;${project.build.directory}/test-data&lt;/app.storage.dir&gt;
 *     &lt;/systemPropertyVariables&gt;
 *   &lt;/configuration&gt;
 * &lt;/plugin&gt;
 * </pre>
 *
 * <p>That way no test run ever creates the repo-rooted
 * {@code ./data/jcustos-standalone-persistence} directory, and PIT workers cannot corrupt
 * each other's storage state.
 */
public final class AppStoragePaths {

  /** System-property name for the storage base directory. */
  public static final String PROPERTY = "app.storage.dir";

  /** Built-in default when nothing was configured. */
  public static final String DEFAULT = "./data/jcustos-standalone-persistence";

  private AppStoragePaths() {
  }

  /**
   * Base directory the storage pair is opened under. The
   * pair's {@link StorageLayout#DEFAULT} fans this out into a
   * framework and an app sub-directory.
   */
  public static Path baseDir() {
    return Path.of(System.getProperty(PROPERTY, DEFAULT));
  }

  /**
   * Bootstrap-token file. Sits inside the framework sub-directory
   * so it shares the same lifecycle as the framework storage.
   */
  public static Path bootstrapTokenFile() {
    return baseDir()
        .resolve(StorageLayout.DEFAULT.frameworkSubdir())
        .resolve("bootstrap.token");
  }
}
