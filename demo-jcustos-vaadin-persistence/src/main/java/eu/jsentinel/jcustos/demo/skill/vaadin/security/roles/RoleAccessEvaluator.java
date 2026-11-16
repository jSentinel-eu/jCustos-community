package eu.jsentinel.jcustos.demo.skill.vaadin.security.roles;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.AccessEvaluator;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.authorization.navigation.AccessDecision;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.User;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.PublicHomeView;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.MyLoginView;

import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;

/**
 * Evaluates {@link VisibleFor @VisibleFor} restrictions on route views.
 *
 * <ul>
 *   <li>No subject in the SubjectStore → reroute to login.</li>
 *   <li>Subject lacks every required role → forward to PublicHomeView,
 *       the landing page every visitor may see. Never to DashboardView:
 *       it carries {@code @VisibleFor} itself, and a denial that points to
 *       the denied view ends in the error view (JS-SEC-158).</li>
 *   <li>Subject has at least one required role → granted.</li>
 * </ul>
 */
public class RoleAccessEvaluator
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

    var currentSubject = SubjectStores.subjectStore().currentSubject(User.class);
    if (currentSubject.isEmpty()) {
      return AccessDecision.denied(MyLoginView.NAV, false);
    }

    AuthorizationService<User> authorizationService =
        JCustosServiceResolver.authorizationService();
    boolean hasRole = authorizationService.rolesFor(currentSubject.get())
        .roleNames()
        .stream()
        .anyMatch(requiredRoles::contains);

    if (hasRole) {
      return AccessDecision.granted();
    }
    return AccessDecision.denied(PublicHomeView.NAV, true);
  }
}
