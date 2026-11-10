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

import com.google.testing.compile.JavaFileObjects;

import javax.tools.JavaFileObject;

/**
 * Fixture sources shared by the run-time tests of the generated wrappers
 * (JS-SEC-156): one evaluator behind core's {@code @ProtectedBy} and one
 * consumer-defined restriction annotation. Both decide on the subject, so a
 * test can observe a grant as well as a denial.
 */
final class WrapperFixtures {

  /** Grants when the subject holds the permission {@code order:delete}. */
  static final JavaFileObject OWNER_ONLY = JavaFileObjects.forSourceLines(
      "fixture.OwnerOnly",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.ProtectedBy;",
      "import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;",
      "import eu.jsentinel.jcustos.authorization.api.AuthorizationEvaluator;",
      "import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;",
      "import eu.jsentinel.jcustos.authorization.navigation.AccessContext;",
      "",
      "public final class OwnerOnly implements AuthorizationEvaluator<ProtectedBy> {",
      "    @Override",
      "    public AuthorizationDecision evaluate(AccessContext context, ProtectedBy annotation) {",
      "        if (context.subject().isEmpty()) {",
      "            return AuthorizationDecision.unauthenticated(\"no subject\");",
      "        }",
      "        boolean owner = context.subject().get().permissionNames()",
      "            .contains(new PermissionName(\"order:delete\"));",
      "        return owner ? AuthorizationDecision.granted()",
      "                     : AuthorizationDecision.forbidden(\"not the owner\");",
      "    }",
      "}");

  /** Consumer-defined restriction annotation, bound to {@link #ADMIN_ONLY_EVALUATOR}. */
  static final JavaFileObject ADMIN_ONLY = JavaFileObjects.forSourceLines(
      "fixture.AdminOnly",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.annotations.JCustosAnnotation;",
      "import java.lang.annotation.ElementType;",
      "import java.lang.annotation.Retention;",
      "import java.lang.annotation.RetentionPolicy;",
      "import java.lang.annotation.Target;",
      "",
      "@Retention(RetentionPolicy.RUNTIME)",
      "@Target({ElementType.TYPE, ElementType.METHOD})",
      "@JCustosAnnotation(AdminOnlyEvaluator.class)",
      "public @interface AdminOnly { }");

  /** Grants when the subject holds the role {@code ADMIN}; a legacy {@code AccessEvaluator}. */
  static final JavaFileObject ADMIN_ONLY_EVALUATOR = JavaFileObjects.forSourceLines(
      "fixture.AdminOnlyEvaluator",
      "package fixture;",
      "import eu.jsentinel.jcustos.authorization.api.AccessEvaluator;",
      "import eu.jsentinel.jcustos.authorization.api.roles.RoleName;",
      "import eu.jsentinel.jcustos.authorization.navigation.AccessContext;",
      "import eu.jsentinel.jcustos.authorization.navigation.AccessDecision;",
      "",
      "public final class AdminOnlyEvaluator implements AccessEvaluator<AdminOnly> {",
      "    @Override",
      "    public AccessDecision evaluate(AccessContext context, AdminOnly annotation) {",
      "        boolean admin = context.subject()",
      "            .map(subject -> subject.roleNames().contains(new RoleName(\"ADMIN\")))",
      "            .orElse(false);",
      "        return admin ? AccessDecision.granted()",
      "                     : AccessDecision.rerouteToError(SecurityException.class, \"admins only\");",
      "    }",
      "}");

  private WrapperFixtures() {
  }
}
