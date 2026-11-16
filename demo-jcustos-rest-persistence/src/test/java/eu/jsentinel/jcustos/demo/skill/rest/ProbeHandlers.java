package eu.jsentinel.jcustos.demo.skill.rest;

import com.sun.net.httpserver.HttpExchange;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;

import java.io.IOException;

/**
 * Test fixture for JS-SEC-114: a handler method declared by a base class and
 * served through a subclass that carries the restriction.
 */
public class ProbeHandlers {

  public static void probe(HttpExchange exchange, JCustosSubject subject) throws IOException {
    Router.respondJson(exchange, 200, "{\"probe\":true}");
  }

  /** Serves the inherited {@link #probe} for administrators only. */
  @RequiresPermission("admin:roles")
  public static final class AdminProbe extends ProbeHandlers {
  }
}
