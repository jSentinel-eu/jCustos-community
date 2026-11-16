package eu.jsentinel.jcustos.demo.skill.rest.security;

import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.rest.BearerTokenExtractor;
import eu.jsentinel.jcustos.rest.RestJCustosVersionContext;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionMetadata;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.User;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.UserDirectoryProvider;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Resolves the current {@link JCustosSubject} from a Bearer token.
 *
 * <p>Used by {@code RestAuthorizationFilter} (via the {@code Router})
 * to know <em>who</em> is making the request. The user is loaded from
 * the {@code UserDirectory} on every request — a token names a user id,
 * not a frozen copy of the user — and roles + permissions come from the
 * {@link AuthorizationService}. A deleted user resolves to nothing.
 *
 * <p>The other three methods feed the library's per-request checks:
 * session lifetime ({@link #resolveSessionMetadata}), security-version
 * drift ({@link #resolveJCustosVersionContext}) and revocation through
 * the {@code SessionStore} ({@link #resolveSessionId}). All of them name
 * the session by its {@code SessionRef}, never by the token.
 */
public final class MyRestSubjectResolver implements RestSubjectResolver {

  private static final BearerTokenExtractor BEARER = new BearerTokenExtractor();

  @Override
  public Optional<JCustosSubject> resolveSubject(RestRequest request) {
    return BEARER.extract(request)
        .flatMap(TokenStore.INSTANCE::resolve)
        .flatMap(session -> UserDirectoryProvider.directory().findById(session.userId()))
        .map(this::toSubject);
  }

  @Override
  public Optional<SessionMetadata> resolveSessionMetadata(RestRequest request) {
    return BEARER.extract(request)
        .filter(token -> TokenStore.INSTANCE.resolve(token).isPresent())
        .flatMap(TokenStore.INSTANCE::touch)
        .map(session -> new SessionMetadata(
            String.valueOf(session.userId()), session.createdAt(), session.lastActivityAt()));
  }

  @Override
  public Optional<RestJCustosVersionContext> resolveJCustosVersionContext(RestRequest request) {
    return BEARER.extract(request)
        .flatMap(TokenStore.INSTANCE::resolve)
        .filter(session -> session.snapshot() != null)
        .map(session -> new RestJCustosVersionContext(
            SubjectId.of(String.valueOf(session.userId())),
            TenantId.DEFAULT,
            session.snapshot(),
            session.reference()));
  }

  @Override
  public Optional<SessionId> resolveSessionId(RestRequest request) {
    return BEARER.extract(request)
        .flatMap(TokenStore.INSTANCE::resolve)
        .map(session -> SessionId.of(session.reference()));
  }

  private JCustosSubject toSubject(User user) {
    AuthorizationService<User> authz =
        JCustosServiceResolver.authorizationService();
    Set<RoleName> roles = authz.rolesFor(user).roleNames().stream()
        .collect(Collectors.toUnmodifiableSet());
    Set<PermissionName> perms = authz.permissionsFor(user).permissionNames().stream()
        .collect(Collectors.toUnmodifiableSet());
    return new JCustosSubject(
        String.valueOf(user.id()),
        user.name(),
        roles,
        perms);
  }
}
