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

import eu.jsentinel.jcustos.authorization.api.CurrentSubjectTest.PiiAuthentication;
import eu.jsentinel.jcustos.authorization.api.CurrentSubjectTest.PiiAuthorization;
import eu.jsentinel.jcustos.authorization.api.CurrentSubjectTest.PiiUser;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exit review RF17 (CWE-400, CWE-779): {@link CurrentSubject#subjectIdOf(Object)} runs for
 * every secured component of a page. Without a registered {@link SubjectIdResolver} it scanned
 * the class path on every call, and with a failing or an ambiguous one it wrote a WARN line on
 * every call - 50 secured components, 50 scans and 50 lines per request. Now the lookup is
 * cached until {@code setSubjectIdResolver(...)} or {@code resetAll()}, the WARN is throttled
 * per resolver class, and a visibility decision does not resolve the id at all. The class path
 * is a real {@link java.net.URLClassLoader} that counts the service lookups.
 */
@DisplayName("RF17 - the SubjectIdResolver is looked up once, a failing one is reported at most once a minute")
class SubjectIdResolverLookupTest {

  private static final int CALLS = 100;
  private static final Pattern FAILING_RESOLVER_WARNING =
      Pattern.compile("The SubjectIdResolver \\S+ failed");
  private static final Pattern LOOKUP_WARNING = Pattern.compile("No SubjectIdResolver can be resolved");

  @TempDir
  Path classPath;

  private final InMemorySubjectStore store = new InMemorySubjectStore();
  private final PiiUser alice = new PiiUser("alice@example.test", "pw-SECRET-4711");

  @BeforeEach
  void wire() {
    JCustosServiceResolver.resetAll();
    SubjectStores.setSubjectStore(store);
    JCustosServiceResolver.setAuthenticationService(new PiiAuthentication());
    JCustosServiceResolver.setAuthorizationService(new PiiAuthorization());
    store.setCurrentSubject(alice, PiiUser.class);
  }

  @AfterEach
  void reset() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("no resolver registered: one class-path scan for 100 subjects, again only after a set or a reset")
  void absentResolver_scannedOnce() throws IOException {
    try (CountingServiceClassLoader loader =
             CountingServiceClassLoader.registering(classPath, SubjectIdResolver.class)) {
      loader.run(() -> {
        for (int i = 0; i < CALLS; i++) {
          assertTrue(CurrentSubject.currentJCustosSubject().isPresent());
        }
        return null;
      });
      assertEquals(1, loader.lookups(), "the absence of a resolver is remembered");

      JCustosServiceResolver.<PiiUser>setSubjectIdResolver(user -> SubjectId.of("user-7"));
      assertEquals("user-7", loader.run(() -> CurrentSubject.subjectIdOf(alice)),
          "a resolver set later is used at once");
      JCustosServiceResolver.setSubjectIdResolver(null);
      loader.run(() -> CurrentSubject.subjectIdOf(alice));
      assertEquals(2, loader.lookups(), "clearing the resolver makes the next lookup scan again");

      JCustosServiceResolver.resetAll();
      wire();
      loader.run(() -> CurrentSubject.subjectIdOf(alice));
      assertEquals(3, loader.lookups(), "resetAll() forgets the remembered absence");
    }
  }

  @Test
  @DisplayName("currentRolesAndPermissions(): what a visibility decision needs, without resolving the id")
  void rolesAndPermissions_withoutTheId() {
    AtomicInteger resolved = new AtomicInteger();
    JCustosServiceResolver.<PiiUser>setSubjectIdResolver(user -> {
      resolved.incrementAndGet();
      return SubjectId.of("user-7");
    });

    for (int i = 0; i < CALLS; i++) {
      CurrentSubject.RolesAndPermissions granted = CurrentSubject.currentRolesAndPermissions()
          .orElseThrow();
      assertEquals(Set.of(new RoleName("ADMIN")), granted.roleNames());
    }
    assertEquals(0, resolved.get(), "no subject id is resolved for a visibility decision");

    assertEquals("user-7", CurrentSubject.currentJCustosSubject().orElseThrow().subjectId());
    assertEquals(1, resolved.get(), "currentJCustosSubject() still carries the resolver's id");

    store.deleteCurrentSubject(PiiUser.class);
    assertTrue(CurrentSubject.currentRolesAndPermissions().isEmpty(), "no subject, no roles");
  }

  @Test
  @DisplayName("a failing resolver: 100 subject ids, one WARN line; resetAll() re-arms the throttle")
  void failingResolver_warnsOncePerInterval() {
    String handle = "PiiUser@" + Integer.toHexString(System.identityHashCode(alice));
    JCustosServiceResolver.<PiiUser>setSubjectIdResolver(user -> {
      throw new IllegalStateException("directory unreachable for " + user);
    });

    String log = capturingStdErr(() -> {
      for (int i = 0; i < CALLS; i++) {
        assertEquals(handle, CurrentSubject.subjectIdOf(alice));
      }
    });

    assertEquals(1, count(FAILING_RESOLVER_WARNING, log), log);
    assertTrue(log.contains(IllegalStateException.class.getName()), log);
    assertTrue(!log.contains("pw-SECRET-4711") && !log.contains("directory unreachable"),
        "the exception message is not logged: " + log);

    JCustosServiceResolver.resetAll();
    wire();
    JCustosServiceResolver.<PiiUser>setSubjectIdResolver(user -> {
      throw new IllegalStateException("still unreachable");
    });
    String again = capturingStdErr(() -> CurrentSubject.subjectIdOf(alice));
    assertEquals(1, count(FAILING_RESOLVER_WARNING, again), "re-armed by resetAll(): " + again);
  }

  @Test
  @DisplayName("two registrations: one scan and one WARN for 100 subject ids; the lookup still reports the ambiguity")
  void ambiguousRegistration_scannedOnceWarnedOnce() throws IOException {
    String handle = "PiiUser@" + Integer.toHexString(System.identityHashCode(alice));
    try (CountingServiceClassLoader loader = CountingServiceClassLoader.registering(classPath,
        SubjectIdResolver.class, FirstResolver.class, SecondResolver.class)) {

      String log = capturingStdErr(() -> loader.run(() -> {
        for (int i = 0; i < CALLS; i++) {
          assertEquals(handle, CurrentSubject.subjectIdOf(alice));
        }
        return null;
      }));

      assertEquals(1, loader.lookups(), "the ambiguity is remembered, not scanned again");
      assertEquals(1, count(LOOKUP_WARNING, log), log);
      IllegalStateException ambiguity = assertThrows(IllegalStateException.class,
          () -> loader.run(JCustosServiceResolver::findSubjectIdResolver),
          "the diagnostics rely on the lookup reporting the ambiguity");
      assertTrue(ambiguity.getMessage().contains(FirstResolver.class.getName())
          && ambiguity.getMessage().contains(SecondResolver.class.getName()), ambiguity.getMessage());
      assertEquals(1, loader.lookups());
    }
  }

  private static int count(Pattern pattern, String text) {
    Matcher matcher = pattern.matcher(text);
    int found = 0;
    while (matcher.find()) {
      found++;
    }
    return found;
  }

  /** Runs {@code action} and returns what slf4j-simple wrote to {@code System.err} meanwhile. */
  private static String capturingStdErr(Runnable action) {
    PrintStream original = System.err;
    ByteArrayOutputStream captured = new ByteArrayOutputStream();
    System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
    try {
      action.run();
    } finally {
      System.setErr(original);
    }
    return captured.toString(StandardCharsets.UTF_8);
  }

  // ── providers, loaded by ServiceLoader through their public no-argument constructor ──

  /** A subject id resolver registered through {@code META-INF/services}. */
  public static class FirstResolver implements SubjectIdResolver<PiiUser> {
    @Override
    public SubjectId resolve(PiiUser subject) {
      return SubjectId.of("first");
    }
  }

  /** A second registration of the same SPI. */
  public static final class SecondResolver extends FirstResolver {
  }
}
