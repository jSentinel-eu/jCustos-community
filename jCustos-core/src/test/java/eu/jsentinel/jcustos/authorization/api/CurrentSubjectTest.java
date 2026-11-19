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

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.permissions.HasPermissions;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.HasRoles;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-097 (CWE-1041, CWE-532): {@link CurrentSubject} is the one subject lookup and the one
 * subject id rule of the adapters - the registered {@link SubjectIdResolver}, otherwise the
 * identity handle; never {@code toString()}, never empty (decision F06).
 */
@DisplayName("JS-SEC-097 - CurrentSubject: one lookup, one subject id rule")
class CurrentSubjectTest {

  private static final String SECRET = "pw-SECRET-4711";

  /** An application user whose toString() carries a credential - the leak shape. */
  record PiiUser(String email, String password) {
    @Override
    public String toString() {
      return "PiiUser[email=" + email + ", password=" + password + "]";
    }
  }

  private final InMemorySubjectStore store = new InMemorySubjectStore();
  private final PiiUser alice = new PiiUser("alice@example.test", SECRET);

  @BeforeEach
  @AfterEach
  void reset() {
    JCustosServiceResolver.resetAll();
  }

  private void wire() {
    SubjectStores.setSubjectStore(store);
    JCustosServiceResolver.setAuthenticationService(new PiiAuthentication());
    JCustosServiceResolver.setAuthorizationService(new PiiAuthorization());
  }

  // ── subjectIdOf ────────────────────────────────────────────────

  @Test
  @DisplayName("with a resolver: the resolver value, never toString()")
  void subjectIdOf_resolverValue() {
    JCustosServiceResolver.<PiiUser>setSubjectIdResolver(u -> SubjectId.of("user-7"));

    String id = CurrentSubject.subjectIdOf(alice);

    assertEquals("user-7", id);
    assertFalse(id.contains(SECRET));
  }

  @Test
  @DisplayName("without a resolver: the identity handle SimpleClassName@identityHash - not toString(), not empty")
  void subjectIdOf_noResolver_identityHandle() {
    String id = CurrentSubject.subjectIdOf(alice);

    assertEquals("PiiUser@" + Integer.toHexString(System.identityHashCode(alice)), id);
    assertFalse(id.contains(SECRET), "toString() must never reach the subject id");
    assertFalse(id.contains("alice@example.test"));
    assertEquals(id, CurrentSubject.subjectIdOf(alice), "stable for the same subject object");
  }

  @Test
  @DisplayName("resolvedSubjectIdOf: the resolver value, without the identity-handle fallback (F21)")
  void resolvedSubjectIdOf_resolverOnly() {
    assertEquals(Optional.empty(), CurrentSubject.resolvedSubjectIdOf(alice), "no resolver: empty, no handle");

    JCustosServiceResolver.<PiiUser>setSubjectIdResolver(u -> SubjectId.of("user-7"));
    assertEquals(Optional.of("user-7"), CurrentSubject.resolvedSubjectIdOf(alice));

    JCustosServiceResolver.<PiiUser>setSubjectIdResolver(u -> {
      throw new IllegalStateException("directory unreachable for " + u);
    });
    assertEquals(Optional.empty(), CurrentSubject.resolvedSubjectIdOf(alice), "a failing resolver: empty");

    JCustosServiceResolver.<PiiUser>setSubjectIdResolver(u -> null);
    assertEquals(Optional.empty(), CurrentSubject.resolvedSubjectIdOf(alice), "no id: empty");
  }

  @Test
  @DisplayName("without a resolver: two equal subject objects get different handles (identity, not equality)")
  void subjectIdOf_noResolver_identityNotEquality() {
    PiiUser twin = new PiiUser("alice@example.test", SECRET);

    assertEquals(alice, twin);
    assertNotEquals(CurrentSubject.subjectIdOf(alice), CurrentSubject.subjectIdOf(twin));
  }

  @Test
  @DisplayName("a resolver that throws or returns null falls back to the identity handle")
  void subjectIdOf_failingResolver_identityHandle() {
    String handle = "PiiUser@" + Integer.toHexString(System.identityHashCode(alice));

    JCustosServiceResolver.<PiiUser>setSubjectIdResolver(u -> {
      throw new IllegalStateException("directory unreachable for " + u);
    });
    assertEquals(handle, CurrentSubject.subjectIdOf(alice));

    JCustosServiceResolver.<PiiUser>setSubjectIdResolver(u -> null);
    assertEquals(handle, CurrentSubject.subjectIdOf(alice));
  }

  @Test
  @DisplayName("a null subject is rejected - an absent subject has no id")
  void subjectIdOf_null_rejected() {
    assertThrows(NullPointerException.class, () -> CurrentSubject.subjectIdOf(null));
  }

  // ── subjectType / current ──────────────────────────────────────

  @Test
  @DisplayName("subjectType: the authentication service's type, empty without one")
  void subjectType() {
    assertTrue(CurrentSubject.subjectType().isEmpty());

    JCustosServiceResolver.setAuthenticationService(new PiiAuthentication());

    assertEquals(Optional.of(PiiUser.class), CurrentSubject.subjectType());
  }

  @Test
  @DisplayName("current: the bound subject; empty without a subject, store or authentication service")
  void current() {
    assertTrue(CurrentSubject.current().isEmpty(), "nothing wired");

    wire();
    assertTrue(CurrentSubject.current().isEmpty(), "nothing bound");

    store.setCurrentSubject(alice, PiiUser.class);
    assertEquals(Optional.of(alice), CurrentSubject.current());

    JCustosServiceResolver.setAuthenticationService(null);
    assertTrue(CurrentSubject.current().isEmpty(), "no authentication service, no subject type");
  }

  @Test
  @DisplayName("current reads a failing store as 'no subject'; currentPropagatingFailures throws it")
  void failingStore() {
    wire();
    SubjectStores.setSubjectStore(new FailingSubjectStore());

    assertTrue(CurrentSubject.current().isEmpty(), "an authorisation decision denies");
    assertTrue(CurrentSubject.currentJCustosSubject().isEmpty());
    IllegalStateException thrown = assertThrows(IllegalStateException.class,
        CurrentSubject::currentPropagatingFailures,
        "a check that ends a session must not read a broken store as 'nothing to end'");
    assertEquals("subject store unreachable", thrown.getMessage());
  }

  // ── currentJCustosSubject ──────────────────────────────────────

  @Test
  @DisplayName("currentJCustosSubject: roles and permissions from the AuthorizationService, id and display name by the one rule")
  void currentJCustosSubject() {
    wire();
    store.setCurrentSubject(alice, PiiUser.class);

    JCustosSubject subject = CurrentSubject.currentJCustosSubject().orElseThrow();

    assertEquals(Set.of(new RoleName("ADMIN")), subject.roles());
    assertEquals(Set.of(new PermissionName("doc:read")), subject.permissions());
    assertEquals(CurrentSubject.subjectIdOf(alice), subject.subjectId());
    assertEquals(subject.subjectId(), subject.displayName(), "never toString() as display name");
    assertFalse(subject.toString().contains(SECRET));
  }

  @Test
  @DisplayName("currentJCustosSubject: empty without an AuthorizationService or when it fails")
  void currentJCustosSubject_noOrFailingAuthorization() {
    wire();
    store.setCurrentSubject(alice, PiiUser.class);

    JCustosServiceResolver.setAuthorizationService(null);
    assertTrue(CurrentSubject.currentJCustosSubject().isEmpty());

    JCustosServiceResolver.setAuthorizationService(new FailingAuthorization());
    assertTrue(CurrentSubject.currentJCustosSubject().isEmpty(), "a failure denies, it does not escape");
  }

  // ── clear ──────────────────────────────────────────────────────

  @Test
  @DisplayName("clear: removes the bound subject; never throws")
  void clear() {
    CurrentSubject.clear(); // nothing wired - nothing to do, no exception

    wire();
    store.setCurrentSubject(alice, PiiUser.class);
    CurrentSubject.clear();
    assertTrue(store.currentSubject(PiiUser.class).isEmpty());

    SubjectStores.setSubjectStore(new FailingSubjectStore());
    CurrentSubject.clear(); // logged, not thrown
  }

  // ── fixtures ───────────────────────────────────────────────────

  static final class PiiAuthentication implements AuthenticationService<String, PiiUser> {
    @Override public boolean checkCredentials(String credentials) {
      return false;
    }

    @Override public PiiUser loadSubject(String credentials) {
      return null;
    }

    @Override public Class<PiiUser> subjectType() {
      return PiiUser.class;
    }
  }

  static final class PiiAuthorization implements AuthorizationService<PiiUser> {
    @Override public HasRoles rolesFor(PiiUser subject) {
      return () -> List.of(new RoleName("ADMIN"));
    }

    @Override public HasPermissions permissionsFor(PiiUser subject) {
      return () -> List.of(new PermissionName("doc:read"));
    }
  }

  static final class FailingAuthorization implements AuthorizationService<PiiUser> {
    @Override public HasRoles rolesFor(PiiUser subject) {
      throw new IllegalStateException("role backend unreachable");
    }

    @Override public HasPermissions permissionsFor(PiiUser subject) {
      throw new IllegalStateException("permission backend unreachable");
    }
  }

  static final class FailingSubjectStore implements SubjectStore {
    @Override public <T> Optional<T> currentSubject(Class<T> subjectType) {
      throw new IllegalStateException("subject store unreachable");
    }

    @Override public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
      throw new IllegalStateException("subject store unreachable");
    }

    @Override public <T> void deleteCurrentSubject(Class<T> subjectType) {
      throw new IllegalStateException("subject store unreachable");
    }
  }
}
