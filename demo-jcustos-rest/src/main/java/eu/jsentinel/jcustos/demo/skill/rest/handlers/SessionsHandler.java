package eu.jsentinel.jcustos.demo.skill.rest.handlers;

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionStatus;
import eu.jsentinel.jcustos.session.SessionStore;
import com.sun.net.httpserver.HttpExchange;
import eu.jsentinel.jcustos.demo.skill.rest.Json;
import eu.jsentinel.jcustos.demo.skill.rest.Router;
import eu.jsentinel.jcustos.demo.skill.rest.security.SessionStoreProvider;
import eu.jsentinel.jcustos.demo.skill.rest.security.TokenStore;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code GET /api/sessions} — lists the live sessions.
 * {@code DELETE /api/sessions/{ref}} — revokes one.
 *
 * <p>A session is named by its {@code SessionRef} ({@code sref-…}), a
 * one-way reference to the token: listing sessions hands out no
 * credential, and revoking one never puts a token into a URL, a proxy
 * log or an access log (JS-SEC-117). The revocation marks the session
 * record {@code REVOKED} — the REST filters refuse it on the next
 * request, on every node that shares the store (JS-SEC-131) — and
 * drops the token on this node.
 *
 * <p>Requires permission {@code admin:sessions}.
 */
public final class SessionsHandler {

  private SessionsHandler() {
  }

  @RequiresPermission("admin:sessions")
  public static void list(HttpExchange exchange, JCustosSubject subject) throws IOException {
    List<Map<String, Object>> body = TokenStore.INSTANCE.all().stream()
        .map(SessionsHandler::project)
        .toList();
    Router.respondJson(exchange, HttpStatus.OK.code(), Json.encode(body));
  }

  @RequiresPermission("admin:sessions")
  public static void revoke(HttpExchange exchange, JCustosSubject subject) throws IOException {
    String reference = Router.pathVariable(exchange, "ref");
    if (!SessionRef.isReference(reference)) {
      Router.respond(exchange, HttpStatus.BAD_REQUEST.code(), HttpStatus.BAD_REQUEST.reason());
      return;
    }
    SessionStore store = SessionStoreProvider.sessionStore();
    SessionId id = SessionId.of(reference);
    boolean recorded = store.findById(id)
        .map(record -> {
          store.save(record.withStatus(SessionStatus.REVOKED));
          return true;
        })
        .orElse(false);
    boolean live = TokenStore.INSTANCE.revokeByReference(reference);
    if (!recorded && !live) {
      Router.respond(exchange, HttpStatus.NOT_FOUND.code(), HttpStatus.NOT_FOUND.reason());
      return;
    }
    Router.respondJson(exchange, HttpStatus.OK.code(), "{\"ok\":true}");
  }

  private static Map<String, Object> project(TokenStore.Session session) {
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("session", session.reference());
    out.put("userId", session.userId());
    out.put("createdAt", session.createdAt().toString());
    out.put("lastActivityAt", session.lastActivityAt().toString());
    return out;
  }
}
