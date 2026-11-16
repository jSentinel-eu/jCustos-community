package eu.jsentinel.jcustos.demo.skill.rest.handlers;

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import com.sun.net.httpserver.HttpExchange;
import eu.jsentinel.jcustos.demo.skill.rest.Json;
import eu.jsentinel.jcustos.demo.skill.rest.Router;
import eu.jsentinel.jcustos.demo.skill.rest.security.TokenStore;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.User;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.UserDirectory;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.demo.skill.rest.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.demo.skill.rest.security.services.PasswordPreflight;
import eu.jsentinel.jcustos.demo.skill.rest.security.services.VersionBumper;

import java.io.IOException;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * {@code GET /api/users}                      — list users
 * {@code POST /api/users}                     — create
 *     body {@code {"username":"...","password":"...","name":"...","role":"USER"}}
 * {@code DELETE /api/users/{id}}              — delete
 * {@code POST /api/users/{id}/roles/{role}}   — assign role
 * {@code DELETE /api/users/{id}/roles/{role}} — revoke role
 *
 * <p>Hardening-skill replacement for the users endpoint. Requires
 * permission {@code admin:roles}. Each route has its own path pattern,
 * so a role revocation can never reach {@code delete} (JS-SEC-132). The
 * last administrator can neither be deleted nor lose the {@code ADMIN}
 * role.
 *
 * <p>Every mutation calls {@link VersionBumper#bump(User)}, so the
 * affected user's open Bearer token is refused with
 * {@code 401 + WWW-Authenticate: SessionStale} on the next request by
 * the drift filter the {@code Router} runs. New passwords pass through
 * {@link PasswordPreflight}.
 */
public final class UsersHandler {

  private UsersHandler() {
  }

  @RequiresPermission("admin:roles")
  public static void list(HttpExchange exchange, JCustosSubject subject) throws IOException {
    UserDirectory dir = UserDirectoryProvider.directory();
    List<Map<String, Object>> body = dir.all()
        .map(UsersHandler::project)
        .toList();
    Router.respondJson(exchange, HttpStatus.OK.code(), Json.encode(body));
  }

  @RequiresPermission("admin:roles")
  public static void create(HttpExchange exchange, JCustosSubject subject) throws IOException {
    Map<String, String> body = Json.parseFlat(Router.readBody(exchange));
    String username = body.get("username");
    String password = body.get("password");
    String name = body.getOrDefault("name", username);
    String roleName = body.getOrDefault("role", "USER");
    if (username == null || password == null) {
      Router.respondJson(exchange, HttpStatus.BAD_REQUEST.code(),
          Json.encode(Map.of("error", "username and password required")));
      return;
    }
    if (!PasswordPreflight.isAcceptable(password)) {
      Router.respondJson(exchange, HttpStatus.UNPROCESSABLE_CONTENT.code(), Json.encode(Map.of(
          "error", PasswordPreflight.REJECTION_REASON)));
      return;
    }
    AuthorizationRole role;
    try {
      role = AuthorizationRole.valueOf(roleName);
    } catch (IllegalArgumentException e) {
      Router.respondJson(exchange, HttpStatus.BAD_REQUEST.code(),
          Json.encode(Map.of("error", "unknown role")));
      return;
    }
    Long id = nextId();
    User user = new User(id, name, EnumSet.of(AuthorizationRole.USER, role));
    UserDirectoryProvider.directory().addUser(username, password, user);
    Router.respondJson(exchange, HttpStatus.CREATED.code(), Json.encode(project(user)));
  }

  @RequiresPermission("admin:roles")
  public static void delete(HttpExchange exchange, JCustosSubject subject) throws IOException {
    Optional<User> existing = userFromPath(exchange);
    if (existing.isEmpty()) {
      Router.respond(exchange, HttpStatus.NOT_FOUND.code(), HttpStatus.NOT_FOUND.reason());
      return;
    }
    if (isLastAdministrator(existing.get())) {
      Router.respondJson(exchange, HttpStatus.CONFLICT.code(),
          Json.encode(Map.of("error", "the last administrator cannot be deleted")));
      return;
    }
    UserDirectoryProvider.directory().deleteUser(existing.get().id());
    VersionBumper.bump(existing.get());
    TokenStore.INSTANCE.revokeAllOf(existing.get().id());
    Router.respondJson(exchange, HttpStatus.OK.code(), "{\"ok\":true}");
  }

  @RequiresPermission("admin:roles")
  public static void assignRole(HttpExchange exchange, JCustosSubject subject) throws IOException {
    Optional<User> existing = userFromPath(exchange);
    Optional<AuthorizationRole> role = roleFromPath(exchange);
    if (existing.isEmpty() || role.isEmpty()) {
      Router.respond(exchange, HttpStatus.NOT_FOUND.code(), HttpStatus.NOT_FOUND.reason());
      return;
    }
    UserDirectoryProvider.directory().assignRole(existing.get().id(), role.get());
    VersionBumper.bump(existing.get());
    Router.respondJson(exchange, HttpStatus.OK.code(), "{\"ok\":true}");
  }

  @RequiresPermission("admin:roles")
  public static void revokeRole(HttpExchange exchange, JCustosSubject subject) throws IOException {
    Optional<User> existing = userFromPath(exchange);
    Optional<AuthorizationRole> role = roleFromPath(exchange);
    if (existing.isEmpty() || role.isEmpty()) {
      Router.respond(exchange, HttpStatus.NOT_FOUND.code(), HttpStatus.NOT_FOUND.reason());
      return;
    }
    if (role.get() == AuthorizationRole.ADMIN && isLastAdministrator(existing.get())) {
      Router.respondJson(exchange, HttpStatus.CONFLICT.code(),
          Json.encode(Map.of("error", "the last administrator cannot lose the ADMIN role")));
      return;
    }
    UserDirectoryProvider.directory().revokeRole(existing.get().id(), role.get());
    VersionBumper.bump(existing.get());
    Router.respondJson(exchange, HttpStatus.OK.code(), "{\"ok\":true}");
  }

  private static boolean isLastAdministrator(User user) {
    return user.roles().contains(AuthorizationRole.ADMIN)
        && UserDirectoryProvider.directory().all()
            .filter(u -> u.roles().contains(AuthorizationRole.ADMIN))
            .count() <= 1;
  }

  private static Long nextId() {
    return UserDirectoryProvider.directory().all()
        .mapToLong(User::id)
        .max()
        .orElse(0L) + 1L;
  }

  private static Map<String, Object> project(User user) {
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("id", user.id());
    out.put("name", user.name());
    out.put("roles", user.roles().stream().map(Enum::name).sorted().toList());
    return out;
  }

  /** The user named by the {@code {id}} path variable. */
  private static Optional<User> userFromPath(HttpExchange exchange) {
    try {
      return UserDirectoryProvider.directory()
          .findById(Long.parseLong(Router.pathVariable(exchange, "id")));
    } catch (NumberFormatException e) {
      return Optional.empty();
    }
  }

  /** The role named by the {@code {role}} path variable. */
  private static Optional<AuthorizationRole> roleFromPath(HttpExchange exchange) {
    String raw = Router.pathVariable(exchange, "role");
    if (raw == null) return Optional.empty();
    try {
      return Optional.of(AuthorizationRole.valueOf(raw));
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
  }
}
