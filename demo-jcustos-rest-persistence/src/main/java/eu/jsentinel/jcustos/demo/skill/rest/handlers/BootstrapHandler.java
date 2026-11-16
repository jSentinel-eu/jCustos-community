package eu.jsentinel.jcustos.demo.skill.rest.handlers;

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.bootstrap.CreateInitialAdminCommand;
import eu.jsentinel.jcustos.bootstrap.InitialAdminCreationResult;
import com.sun.net.httpserver.HttpExchange;
import eu.jsentinel.jcustos.demo.skill.rest.Json;
import eu.jsentinel.jcustos.demo.skill.rest.Router;
import eu.jsentinel.jcustos.demo.skill.rest.security.bootstrap.BootstrapWiring;

import java.io.IOException;
import java.util.Map;

/**
 * {@code POST /api/setup} — accepts the one-time bootstrap token plus
 * the admin's chosen username + password.
 *
 * <p>Body: {@code {"token":"…","username":"admin","password":"…"}}.
 *
 * <p>After a successful call the next bootstrap-required check
 * returns false and the Router lifts the 503 guard on every other
 * endpoint.
 */
public final class BootstrapHandler {

  private BootstrapHandler() {
  }

  @PublicRoute
  public static void setup(HttpExchange exchange, JCustosSubject ignored) throws IOException {
    if (!BootstrapWiring.instance().stateService().bootstrapRequired()) {
      Router.respondJson(exchange, HttpStatus.CONFLICT.code(), Json.encode(Map.of("error", "already initialised")));
      return;
    }
    Map<String, String> body = Json.parseFlat(Router.readBody(exchange));
    String token = body.get("token");
    String username = body.get("username");
    String password = body.get("password");
    if (token == null || username == null || password == null) {
      Router.respondJson(exchange, HttpStatus.BAD_REQUEST.code(), Json.encode(Map.of(
          "error", "token, username and password are required")));
      return;
    }
    InitialAdminCreationResult result = BootstrapWiring.instance().bootstrapService()
        .createInitialAdmin(new CreateInitialAdminCommand(
            token, username, password.toCharArray(),
            body.get("name"), body.get("email")));
    switch (result) {
      case InitialAdminCreationResult.Created created ->
          Router.respondJson(exchange, HttpStatus.CREATED.code(), Json.encode(Map.of(
              "status", "created",
              "username", created.username())));
      case InitialAdminCreationResult.AlreadyInitialized ignored2 ->
          Router.respondJson(exchange, HttpStatus.CONFLICT.code(), Json.encode(Map.of(
              "error", "already initialised")));
      // JS-SEC-086: a 401 is rendered by the published decision mapper, with its challenge.
      case InitialAdminCreationResult.InvalidBootstrapToken ignored2 ->
          Router.refuse(exchange, AuthorizationDecision.unauthenticated("invalid-bootstrap-token"));
      case InitialAdminCreationResult.PasswordPolicyViolation policy ->
          Router.respondJson(exchange, HttpStatus.UNPROCESSABLE_CONTENT.code(), Json.encode(Map.of(
              "error", policy.reason() == null ? "password policy violation" : policy.reason())));
      case InitialAdminCreationResult.InvalidUsername invalid ->
          Router.respondJson(exchange, HttpStatus.UNPROCESSABLE_CONTENT.code(), Json.encode(Map.of(
              "error", invalid.reason() == null ? "invalid username" : invalid.reason())));
      case InitialAdminCreationResult.InternalError ignored2 ->
          Router.respondJson(exchange, HttpStatus.INTERNAL_SERVER_ERROR.code(), Json.encode(Map.of(
              "error", "internal error")));
    }
  }
}
