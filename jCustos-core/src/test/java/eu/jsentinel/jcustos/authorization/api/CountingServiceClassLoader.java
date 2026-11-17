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
package eu.jsentinel.jcustos.authorization.api;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

/**
 * Test support for exit review RF17 / RF22: a real {@link URLClassLoader} over a directory that
 * holds a {@code META-INF/services} file, counting how often {@link java.util.ServiceLoader}
 * asks it for that file - one request per scan of the class path. Used as the thread's context
 * class loader, which is where {@code ServiceLoader.load(Class)} looks. No mocking framework.
 */
public final class CountingServiceClassLoader extends URLClassLoader {

  private final String servicesFile;
  private final AtomicInteger lookups = new AtomicInteger();

  private CountingServiceClassLoader(Path root, Class<?> service) {
    super(new URL[] {urlOf(root)}, CountingServiceClassLoader.class.getClassLoader());
    this.servicesFile = "META-INF/services/" + service.getName();
  }

  /**
   * Writes the {@code META-INF/services} file of {@code service} below {@code root}, listing
   * {@code providers} - none for "nothing registered" - and returns a loader over {@code root}.
   *
   * @param root      an empty directory
   * @param service   the service interface
   * @param providers the registered implementations
   * @return the counting loader
   */
  public static CountingServiceClassLoader registering(Path root, Class<?> service,
                                                       Class<?>... providers) {
    try {
      Path dir = Files.createDirectories(root.resolve("META-INF/services"));
      StringBuilder lines = new StringBuilder();
      for (Class<?> provider : providers) {
        lines.append(provider.getName()).append('\n');
      }
      Files.writeString(dir.resolve(service.getName()), lines);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    return new CountingServiceClassLoader(root, service);
  }

  /** @return how often the services file was asked for */
  public int lookups() {
    return lookups.get();
  }

  /**
   * Runs {@code action} with this loader as the calling thread's context class loader.
   *
   * @param action what to run
   * @param <T>    the result type
   * @return what {@code action} returned
   */
  public <T> T run(Supplier<T> action) {
    Thread thread = Thread.currentThread();
    ClassLoader previous = thread.getContextClassLoader();
    thread.setContextClassLoader(this);
    try {
      return action.get();
    } finally {
      thread.setContextClassLoader(previous);
    }
  }

  @Override
  public Enumeration<URL> getResources(String name) throws IOException {
    if (servicesFile.equals(name)) {
      lookups.incrementAndGet();
    }
    return super.getResources(name);
  }

  private static URL urlOf(Path root) {
    try {
      return root.toUri().toURL();
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException(e);
    }
  }
}
