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
package eu.jsentinel.jcustos.starter.ui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Builder-validation tests. Construction of the actual Vaadin
 * components (SecuredButton, SecuredRouterLink, SecuredMenuItem) is
 * exercised end-to-end in the demo modules; here we focus on the
 * starter's own discipline so the unit run does not require a Vaadin
 * UI context.
 */
class SecuredUiTest {

  @Test
  void buttonWithoutRequirement_throws() {
    assertThrows(IllegalStateException.class,
        () -> SecuredUi.button("X").build());
  }

  @Test
  void buttonCanNotMixRequiresChecks() {
    assertThrows(IllegalStateException.class,
        () -> SecuredUi.button("X")
            .requiresRole("ADMIN")
            .requiresPermission("doc:delete"));
  }

  @Test
  void buttonCanNotMixVisibilityModes() {
    assertThrows(IllegalStateException.class,
        () -> SecuredUi.button("X")
            .requiresRole("ADMIN")
            .hideWhenDenied()
            .disableWhenDenied());
  }

  @Test
  void requiresPolicyAndRoleMutuallyExclusive() {
    // V00.73 (Prompt 011): requiresPolicy is no longer a build-time
    // UnsupportedOperationException. Builder discipline still enforces
    // "exactly one of requiresRole / requiresPermission / requiresPolicy".
    assertThrows(IllegalStateException.class,
        () -> SecuredUi.button("X")
            .requiresRole("ADMIN")
            .requiresPolicy("doc.policy"));
    assertThrows(IllegalStateException.class,
        () -> SecuredUi.button("X")
            .requiresPolicy("doc.policy")
            .requiresPermission("doc:read"));
  }

  @Test
  void linkWithoutTargetThrows() {
    assertThrows(IllegalStateException.class,
        () -> SecuredUi.link().requiresRole("X").build());
  }

  @Test
  void linkRequiresRequirement() {
    assertThrows(IllegalStateException.class,
        () -> SecuredUi.link().to(com.vaadin.flow.component.html.Div.class).build());
  }

  // ── V00.74 generic component builder ─────────────────────────────

  @Test
  void componentNullRejected() {
    assertThrows(NullPointerException.class,
        () -> SecuredUi.component(null));
  }

  @Test
  void componentRequiresRequirement() {
    // Building a real Vaadin Component without Jackson on the test
    // classpath fails — but the builder discipline-checks fire
    // BEFORE construction. We pass a never-constructed dummy via
    // generics and assert that .bind() rejects "no requirement set".
    com.vaadin.flow.component.html.Div div = new com.vaadin.flow.component.html.Div();
    assertThrows(IllegalStateException.class,
        () -> SecuredUi.component(div).bind());
  }

  @Test
  void componentEnforcesMutualExclusion() {
    com.vaadin.flow.component.html.Div div = new com.vaadin.flow.component.html.Div();
    assertThrows(IllegalStateException.class,
        () -> SecuredUi.component(div)
            .requiresRole("ROLE_USER")
            .requiresPolicy("doc.policy"));
  }

  @Test
  void componentBindReturnsTheSameInstance() {
    com.vaadin.flow.component.html.Div div = new com.vaadin.flow.component.html.Div();
    com.vaadin.flow.component.html.Div bound = SecuredUi.component(div)
        .requiresRole("ROLE_USER")
        .hideWhenDenied()
        .bind();
    org.junit.jupiter.api.Assertions.assertSame(div, bound,
        "bind() must return the same component for chaining");
  }

  // ── JS-SEC-135: an empty role / permission array is rejected ─────

  @Test
  void requiresRoleWithoutRoles_throws() {
    // JS-SEC-135 (CWE-636, CWE-863): used to yield an empty requirement that
    // admitted every visitor, anonymous ones included.
    assertThrows(IllegalArgumentException.class,
        () -> SecuredUi.button("X").requiresRole());
  }

  @Test
  void requiresPermissionWithoutPermissions_throws() {
    assertThrows(IllegalArgumentException.class,
        () -> SecuredUi.button("X").requiresPermission());
  }

  @Test
  void emptyRoleArrayFromConfiguration_throwsOnEveryBuilder() {
    String[] rolesFromConfiguration = new String[0];
    assertThrows(IllegalArgumentException.class,
        () -> SecuredUi.button("Delete").requiresRole(rolesFromConfiguration));
    assertThrows(IllegalArgumentException.class,
        () -> SecuredUi.link().requiresRole(rolesFromConfiguration));
    assertThrows(IllegalArgumentException.class,
        () -> SecuredUi.component(new com.vaadin.flow.component.html.Div())
            .requiresRole(rolesFromConfiguration));
    assertThrows(IllegalArgumentException.class,
        () -> SecuredUi.component(new com.vaadin.flow.component.html.Div())
            .requiresPermission(rolesFromConfiguration));
  }

  @Test
  void rejectedEmptyArrayDoesNotCountAsRequirement() {
    // The rejected call must not leave a requirement behind: build() still fails
    // for "no requirement", and a real requirement can still be set afterwards.
    SecuredUi.SecuredComponentBuilder<com.vaadin.flow.component.html.Div> builder =
        SecuredUi.component(new com.vaadin.flow.component.html.Div());
    assertThrows(IllegalArgumentException.class, builder::requiresRole);
    assertThrows(IllegalStateException.class, builder::bind);

    SecuredUi.SecuredComponentBuilder<com.vaadin.flow.component.html.Div> second =
        SecuredUi.component(new com.vaadin.flow.component.html.Div());
    assertThrows(IllegalArgumentException.class, second::requiresPermission);
    org.junit.jupiter.api.Assertions.assertNotNull(second.requiresRole("ADMIN").bind());
  }
}
