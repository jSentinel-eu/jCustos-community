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
package eu.jsentinel.jcustos.demo.app.security.roles;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.AccessEvaluator;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.authorization.navigation.AccessDecision;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.views.MainView;
import eu.jsentinel.jcustos.demo.app.views.MyLoginView;

import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;

/**
 * Role-based access evaluator for the demo application.
 * <ul>
 *   <li>No subject in the SubjectStore: reroute to the login view.</li>
 *   <li>Subject without any of the required roles: forward to {@link MainView}, the home of
 *       every signed-in subject. {@code MainView} must admit every signed-in subject
 *       ({@code @SecureRoute()}): a denial that forwards to the denied view itself ends in
 *       the error view (JS-SEC-158), so a home view that denies would turn every such
 *       forward into an error page.</li>
 *   <li>Subject with at least one required role: granted.</li>
 * </ul>
 */
public class MyRoleAccessEvaluator
    implements AccessEvaluator<VisibleFor>, HasLogger {

  @Override
  public AccessDecision evaluate(AccessContext context, VisibleFor annotation) {

    Set<RoleName> requiredRoles = stream(annotation.value())
        .map(Enum::name)
        .map(RoleName::new)
        .collect(Collectors.toSet());

    if (requiredRoles.isEmpty()) {
      return AccessDecision.granted();
    }

    var currentSubject = SubjectStores.subjectStore().currentSubject(MyUser.class);
    if (currentSubject.isEmpty()) {
      return AccessDecision.denied(MyLoginView.NAV, false);
    }

    AuthorizationService<MyUser> authorizationService =
        JCustosServiceResolver.authorizationService();
    boolean hasRole = authorizationService.rolesFor(currentSubject.get())
        .roleNames()
        .stream()
        .anyMatch(requiredRoles::contains);

    if (hasRole) {
      return AccessDecision.granted();
    }

    return AccessDecision.denied(MainView.NAV, true);
  }
}
