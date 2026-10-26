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
package eu.jsentinel.jcustos.authorization.impl;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.Location;
import com.vaadin.flow.router.NavigationTrigger;
import com.vaadin.flow.router.Router;
import com.vaadin.flow.router.internal.AbstractRouteRegistry;
import com.vaadin.flow.server.VaadinContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("VaadinAccessContextFactory")
class VaadinAccessContextFactoryTest {

  private final VaadinAccessContextFactory factory = new VaadinAccessContextFactory();

  @BeforeEach
  void resetServices() {
    JCustosServiceResolver.resetAll();
    StubAuthorizationService.clear();
  }

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
    StubAuthorizationService.clear();
  }

  // ── No subject ────────────────────────────────────────────────

  @Test
  @DisplayName("create() returns a non-null vaadin-view AccessContext with location/path/target attributes")
  void contextShape() {
    SubjectStores.setSubjectStore(new InMemorySubjectStore());

    AccessContext context = factory.create(event("admin", AdminRoute.class));

    assertNotNull(context);
    assertEquals("vaadin-view", context.resourceType());
    assertEquals(AdminRoute.class.getSimpleName(), context.resourceName());
    assertEquals("navigate", context.operation());
    assertEquals("admin", context.attributes().get("path"));
    assertEquals(AdminRoute.class, context.attributes().get("target"));
    assertNotNull(context.attributes().get("location"));
  }

  @Test
  @DisplayName("currentJCustosSubject yields empty when SubjectStore has no subject")
  void emptySubjectWhenStoreEmpty() {
    SubjectStores.setSubjectStore(new InMemorySubjectStore());

    AccessContext context = factory.create(event("/", AdminRoute.class));

    assertTrue(context.subject().isEmpty(),
        "no subject in the store → AccessContext.subject() must be empty");
  }

  // ── Populated subject path ────────────────────────────────────

  @Test
  @DisplayName("populated subject is exposed with role and permission names")
  void populatedSubjectExposesRolesAndPermissions() {
    InMemorySubjectStore store = new InMemorySubjectStore();
    SubjectStores.setSubjectStore(store);
    String subject = "alice";
    store.setCurrentSubject(subject, String.class);

    RoleName admin = new RoleName("ROLE_ADMIN");
    PermissionName del = new PermissionName("doc:delete");
    StubAuthorizationService.put(subject, Set.of(admin), Set.of(del));

    AccessContext context = factory.create(event("/", AdminRoute.class));

    assertTrue(context.subject().isPresent(),
        "populated SubjectStore must surface as AccessContext.subject()");
    JCustosSubject snapshot = context.subject().get();
    assertEquals(List.of(admin), List.copyOf(snapshot.roles()));
    assertEquals(List.of(del), List.copyOf(snapshot.permissions()));
  }

  @Test
  @DisplayName("subject id contains class simple name and identity hash")
  void subjectIdShape() {
    InMemorySubjectStore store = new InMemorySubjectStore();
    SubjectStores.setSubjectStore(store);
    String subject = "bob";
    store.setCurrentSubject(subject, String.class);
    StubAuthorizationService.put(subject, Set.of(), Set.of());

    AccessContext context = factory.create(event("/", AdminRoute.class));
    JCustosSubject snapshot = context.subject().orElseThrow();

    assertTrue(snapshot.subjectId().startsWith("String@"),
        "subject id must lead with the subject's class simple name + '@'");
    assertEquals(snapshot.subjectId(), snapshot.displayName(),
        "JS-SEC-083: displayName must never be subject.toString(); without a resolver it is the identity handle");
  }

  @Test
  @DisplayName("JS-SEC-083: subjectId and displayName come from the SubjectIdResolver, never from toString()")
  void resolverValueReplacesIdentityHashAndToString() {
    InMemorySubjectStore store = new InMemorySubjectStore();
    SubjectStores.setSubjectStore(store);
    String subject = "carol:secret-password"; // toString() carries a credential
    store.setCurrentSubject(subject, String.class);
    StubAuthorizationService.put(subject, Set.of(), Set.of());
    JCustosServiceResolver.<String>setSubjectIdResolver(s -> SubjectId.of("user-42"));

    JCustosSubject snapshot = factory.create(event("/", AdminRoute.class)).subject().orElseThrow();

    assertEquals("user-42", snapshot.subjectId(), "the resolver value correlates with LoginSucceeded");
    assertEquals("user-42", snapshot.displayName(), "the display name is the resolver value, not toString()");
    assertFalse(snapshot.subjectId().contains("@"), "no identity-hash suffix");
    assertFalse(snapshot.displayName().contains("secret-password"), "no credential leaks into the context");
  }

  @Test
  @DisplayName("without a resolver the displayName is the identity handle (blank toString() included)")
  void blankToStringFallsBackToId() {
    InMemorySubjectStore store = new InMemorySubjectStore();
    SubjectStores.setSubjectStore(store);
    String blank = "   ";
    store.setCurrentSubject(blank, String.class);
    StubAuthorizationService.put(blank, Set.of(), Set.of());

    AccessContext context = factory.create(event("/", AdminRoute.class));
    JCustosSubject snapshot = context.subject().orElseThrow();

    assertEquals(snapshot.subjectId(), snapshot.displayName(),
        "blank subject.toString() must trigger displayName = subjectId fallback");
  }

  @Test
  @DisplayName("AccessContext.attributes is unmodifiable")
  void attributesAreUnmodifiable() {
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    AccessContext context = factory.create(event("/", AdminRoute.class));

    org.junit.jupiter.api.Assertions.assertThrows(UnsupportedOperationException.class,
        () -> context.attributes().put("evil", "v"));
  }

  // ── Helpers ───────────────────────────────────────────────────

  private static BeforeEnterEvent event(String path, Class<? extends Component> target) {
    return new BeforeEnterEvent(
        new Router(new TestRouteRegistry()),
        NavigationTrigger.PROGRAMMATIC,
        new Location(path),
        target,
        new UI(),
        List.of());
  }

  private static final class TestRouteRegistry extends AbstractRouteRegistry {
    @Override
    public VaadinContext getContext() {
      return null;
    }
  }

  static class AdminRoute extends Component {
  }
}
