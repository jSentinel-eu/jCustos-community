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
package eu.jsentinel.jcustos.processor;

import com.google.testing.compile.Compilation;
import com.google.testing.compile.Compiler;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.permissions.HasPermissions;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.HasRoles;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;

import javax.tools.JavaFileObject;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static com.google.testing.compile.CompilationSubject.assertThat;

/**
 * Test support for JS-SEC-156: compiles fixture sources with the real
 * {@link SecuredAnnotationProcessor}, loads the fixture and its generated
 * {@code ...Secured} wrapper from the in-memory class files and runs them
 * against a real {@code JCustosEnforcer} with hand-written services - no
 * mocking framework involved.
 */
final class GeneratedWrapperHarness {

  private final ClassLoader loader;

  private GeneratedWrapperHarness(ClassLoader loader) {
    this.loader = loader;
  }

  /** Compiles {@code sources} with the processor and makes the result loadable. */
  static GeneratedWrapperHarness compile(JavaFileObject... sources) {
    return new GeneratedWrapperHarness(
        new InMemoryClassLoader(classFiles(compileOrFail(sources))));
  }

  /**
   * A harness over explicitly chosen class files - used to pair a wrapper with a
   * source class it was not generated from.
   */
  static GeneratedWrapperHarness of(Map<String, byte[]> classFiles) {
    return new GeneratedWrapperHarness(new InMemoryClassLoader(classFiles));
  }

  static Compilation compileOrFail(JavaFileObject... sources) {
    Compilation compilation = Compiler.javac()
        .withProcessors(new SecuredAnnotationProcessor())
        .compile(sources);
    assertThat(compilation).succeeded();
    return compilation;
  }

  /** Binary class name to class file bytes, for everything the compilation produced. */
  static Map<String, byte[]> classFiles(Compilation compilation) {
    Map<String, byte[]> classes = new HashMap<>();
    for (JavaFileObject file : compilation.generatedFiles()) {
      if (file.getKind() != JavaFileObject.Kind.CLASS) {
        continue;
      }
      String path = file.toUri().getPath();
      String marker = "CLASS_OUTPUT/";
      String binaryName = path
          .substring(path.indexOf(marker) + marker.length(), path.length() - ".class".length())
          .replace('/', '.');
      try (InputStream in = file.openInputStream()) {
        classes.put(binaryName, in.readAllBytes());
      } catch (IOException e) {
        throw new AssertionError("could not read " + path, e);
      }
    }
    return classes;
  }

  Class<?> load(String binaryName) {
    try {
      return Class.forName(binaryName, true, loader);
    } catch (ClassNotFoundException e) {
      throw new AssertionError("class not produced by the compilation: " + binaryName, e);
    }
  }

  /** A new instance of the wrapper generated for {@code sourceBinaryName}. */
  Object newWrapper(String sourceBinaryName) {
    try {
      return load(sourceBinaryName + "Secured").getDeclaredConstructor().newInstance();
    } catch (InvocationTargetException e) {
      throw new AssertionError("wrapper constructor failed", e.getCause());
    } catch (ReflectiveOperationException e) {
      throw new AssertionError("wrapper not instantiable for " + sourceBinaryName, e);
    }
  }

  /**
   * Invokes the public method {@code name} on {@code target} and rethrows what
   * the method itself threw, without the reflection wrapper.
   */
  static Object call(Object target, String name, Object... args) throws Throwable {
    Method method = Arrays.stream(target.getClass().getMethods())
        .filter(candidate -> candidate.getName().equals(name))
        .filter(candidate -> candidate.getParameterCount() == args.length)
        .findFirst()
        .orElseThrow(() -> new AssertionError("no method " + name + " on " + target.getClass()));
    try {
      return method.invoke(target, args);
    } catch (InvocationTargetException e) {
      throw e.getCause();
    }
  }

  // ── a real, minimal security context ─────────────────────────────

  /** Installs the services {@code JCustosEnforcer} resolves; call from {@code @BeforeEach}. */
  static void installServices() {
    resetServices();
    JCustosServiceResolver.setAuthenticationService(new StubAuthentication());
    JCustosServiceResolver.setAuthorizationService(new StubAuthorization());
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
  }

  /** Restores the global state; call from {@code @AfterEach}. */
  static void resetServices() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
    InMemorySubjectStore.STORE.clear();
    StubAuthorization.ROLES.clear();
    StubAuthorization.PERMISSIONS.clear();
  }

  /** Binds {@code id} as the current subject with the given roles and permissions. */
  static void bindSubject(String id, Set<String> roles, Set<String> permissions) {
    InMemorySubjectStore.STORE.put(String.class, id);
    StubAuthorization.ROLES.put(id,
        roles.stream().map(RoleName::new).collect(Collectors.toSet()));
    StubAuthorization.PERMISSIONS.put(id,
        permissions.stream().map(PermissionName::new).collect(Collectors.toSet()));
  }

  /** Removes the current subject: the caller is anonymous. */
  static void unbindSubject() {
    InMemorySubjectStore.STORE.clear();
  }

  private static final class StubAuthentication implements AuthenticationService<String, String> {
    @Override
    public boolean checkCredentials(String credentials) {
      return true;
    }

    @Override
    public String loadSubject(String credentials) {
      return credentials;
    }

    @Override
    public Class<String> subjectType() {
      return String.class;
    }
  }

  private static final class StubAuthorization implements AuthorizationService<String> {
    static final Map<String, Set<RoleName>> ROLES = new HashMap<>();
    static final Map<String, Set<PermissionName>> PERMISSIONS = new HashMap<>();

    @Override
    public HasRoles rolesFor(String subject) {
      return () -> List.copyOf(ROLES.getOrDefault(subject, Set.of()));
    }

    @Override
    public HasPermissions permissionsFor(String subject) {
      return () -> List.copyOf(PERMISSIONS.getOrDefault(subject, Set.of()));
    }
  }

  private static final class InMemorySubjectStore implements SubjectStore {
    static final Map<Class<?>, Object> STORE = new HashMap<>();

    @Override
    public <T> Optional<T> currentSubject(Class<T> subjectType) {
      return Optional.ofNullable(subjectType.cast(STORE.get(subjectType)));
    }

    @Override
    public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
      STORE.put(subjectType, subject);
    }

    @Override
    public <T> void deleteCurrentSubject(Class<T> subjectType) {
      STORE.remove(subjectType);
    }
  }

  /** Defines the compiled classes; everything else comes from the test class path. */
  private static final class InMemoryClassLoader extends ClassLoader {
    private final Map<String, byte[]> classFiles;

    InMemoryClassLoader(Map<String, byte[]> classFiles) {
      super(GeneratedWrapperHarness.class.getClassLoader());
      this.classFiles = Map.copyOf(classFiles);
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
      byte[] bytes = classFiles.get(name);
      if (bytes == null) {
        throw new ClassNotFoundException(name);
      }
      return defineClass(name, bytes, 0, bytes.length);
    }
  }
}
