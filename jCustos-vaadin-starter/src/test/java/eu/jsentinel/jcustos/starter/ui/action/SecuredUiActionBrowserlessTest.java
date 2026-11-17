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
package eu.jsentinel.jcustos.starter.ui.action;

import eu.jsentinel.jcustos.audit.ActionDenied;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.components.SecuredBindingRegistry;
import eu.jsentinel.jcustos.components.SecuredVisibility;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.policy.api.Policy;
import eu.jsentinel.jcustos.policy.impl.InMemoryPolicyRegistry;
import eu.jsentinel.jcustos.starter.ui.SecuredUi;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.browserless.ViewPackages;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.html.Div;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-168 (CWE-1188): {@code SecuredUi.action(...)} enforces the requirement on the click,
 * not only on the control's state. A button rendered while the subject held the permission
 * stays clickable in the browser until something re-renders it; the click must still be
 * refused once the permission is gone. Real components, the real SPI lookup, Vaadin's
 * {@code ButtonTester} for the click.
 */
@DisplayName("JS-SEC-168 - SecuredUi.action refuses a click the subject may no longer make")
@ViewPackages
class SecuredUiActionBrowserlessTest extends BrowserlessTest {

  private static final PermissionName DELETE = new PermissionName("doc:delete");
  private static final RoleName ADMIN = new RoleName("ADMIN");

  private final InMemorySubjectStore subjects = new InMemorySubjectStore();
  private final FakeAuthorizationService<String> authorization = new FakeAuthorizationService<>();
  private final RecordingAuditSink audit = new RecordingAuditSink();
  private final AtomicInteger deletions = new AtomicInteger();

  @BeforeEach
  void wire() {
    JCustosServiceResolver.resetAll();
    SubjectStores.setSubjectStore(subjects);
    JCustosServiceResolver.setAuthenticationService(FakeAuthenticationService.forType(String.class));
    JCustosServiceResolver.setAuthorizationService(authorization);
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.setSubjectIdResolver((SubjectIdResolver<String>) SubjectId::new);
    authorization.putPermissions("alice", Set.of(DELETE));
    authorization.putRoles("alice", Set.of(ADMIN));
    subjects.setCurrentSubject("alice", String.class);
  }

  @AfterEach
  void reset() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
  }

  private Button deleteAction() {
    Button delete = SecuredUi.action(new Button("Delete"), click -> deletions.incrementAndGet())
        .requiresPermission("doc:delete")
        .bind();
    UI.getCurrent().add(delete);
    return delete;
  }

  @Test
  @DisplayName("permitted: the click runs the action")
  void permitted_clickRuns() {
    Button delete = deleteAction();

    test(delete).click();

    assertEquals(1, deletions.get());
    assertTrue(audit.all(ActionDenied.class).isEmpty());
  }

  @Test
  @DisplayName("permission withdrawn after rendering: the click is refused, the button disabled, the refusal audited")
  void withdrawnAfterRendering_clickRefused() {
    Button delete = deleteAction();
    assertTrue(delete.isEnabled(), "rendered while alice held the permission");
    authorization.putPermissions("alice", Set.of());
    assertTrue(delete.isEnabled(), "precondition: nothing re-rendered the button - it is still clickable");

    test(delete).click();

    assertEquals(0, deletions.get(), "the action must not run");
    assertFalse(delete.isEnabled(), "the button is re-evaluated at once");
    ActionDenied denied = audit.single(ActionDenied.class);
    assertEquals("alice", denied.subjectId());
    assertEquals("requiresPermission(doc:delete)", denied.action());
  }

  @Test
  @DisplayName("subject logged out after rendering: the click is refused")
  void loggedOutAfterRendering_clickRefused() {
    Button delete = deleteAction();
    subjects.deleteCurrentSubject(String.class);

    test(delete).click();

    assertEquals(0, deletions.get());
    assertEquals(1, audit.all(ActionDenied.class).size());
  }

  @Test
  @DisplayName("hideWhenDenied(): a refused click hides the control")
  void hideWhenDenied_refusedClickHides() {
    Button export = SecuredUi.action(new Button("Export"), click -> deletions.incrementAndGet())
        .requiresRole("ADMIN")
        .hideWhenDenied()
        .bind();
    UI.getCurrent().add(export);
    authorization.putRoles("alice", Set.of());

    test(export).click();

    assertEquals(0, deletions.get());
    assertFalse(export.isVisible());
    assertEquals("requiresRole(ADMIN)", audit.single(ActionDenied.class).action());
  }

  @Test
  @DisplayName("refreshAll(UI) covers SecuredUi.action and SecuredUi.component bindings")
  void refreshAll_coversStarterBindings() {
    Button delete = deleteAction();
    Div adminPanel = SecuredUi.component(new Div()).requiresRole("ADMIN").bind();
    UI.getCurrent().add(adminPanel);
    assertTrue(adminPanel.isVisible());
    authorization.putPermissions("alice", Set.of());
    authorization.putRoles("alice", Set.of());

    assertEquals(2, SecuredVisibility.refreshAll(UI.getCurrent()));

    assertFalse(delete.isEnabled());
    assertFalse(adminPanel.isVisible());
    assertEquals(2, SecuredBindingRegistry.registeredCount(UI.getCurrent()));
  }

  @Test
  @DisplayName("SecuredUi.component is evaluated again when it is attached")
  void component_reEvaluatedOnAttach() {
    Div adminPanel = SecuredUi.component(new Div()).requiresRole("ADMIN").bind();
    assertTrue(adminPanel.isVisible());
    authorization.putRoles("alice", Set.of());

    UI.getCurrent().add(adminPanel);

    assertFalse(adminPanel.isVisible(), "the role was withdrawn before the panel was shown");
  }

  @Test
  @DisplayName("requiresPolicy: the policy is evaluated again at the click and by refreshAll")
  void policyAction_refusedOnceThePolicyDenies() {
    AtomicBoolean releaseAllowed = new AtomicBoolean(true);
    InMemoryPolicyRegistry policies = new InMemoryPolicyRegistry();
    policies.register(Policy.named("documents.release").allowIf(context -> releaseAllowed.get()).build());
    JCustosServiceResolver.setPolicyRegistry(policies);
    Button release = SecuredUi.action(new Button("Release"), click -> deletions.incrementAndGet())
        .requiresPolicy("documents.release")
        .bind();
    Div panel = SecuredUi.component(new Div()).requiresPolicy("documents.release").bind();
    UI.getCurrent().add(release, panel);
    assertTrue(release.isEnabled());
    assertTrue(panel.isVisible());
    releaseAllowed.set(false);

    test(release).click();

    assertEquals(0, deletions.get());
    assertFalse(release.isEnabled());
    assertEquals("requiresPolicy(documents.release)", audit.single(ActionDenied.class).action());
    assertTrue(panel.isVisible(), "precondition: the panel was not re-evaluated yet");
    SecuredVisibility.refreshAll(UI.getCurrent());
    assertFalse(panel.isVisible(), "the policy binding of SecuredUi.component is refreshed as well");
  }

  @Test
  @DisplayName("builder discipline: a requirement is mandatory, bind() once, the control is returned")
  void builderDiscipline() {
    Button button = new Button("Delete");
    assertThrows(IllegalStateException.class,
        () -> SecuredUi.action(button, click -> deletions.incrementAndGet()).bind());
    assertThrows(NullPointerException.class, () -> SecuredUi.action(button, null));
    SecuredUi.SecuredActionBuilder<Button> builder =
        SecuredUi.action(new Button("Delete"), click -> deletions.incrementAndGet()).requiresRole("ADMIN");
    Button bound = builder.bind();
    assertThrows(IllegalStateException.class, builder::bind);
    assertSame(Button.class, bound.getClass());
  }
}
