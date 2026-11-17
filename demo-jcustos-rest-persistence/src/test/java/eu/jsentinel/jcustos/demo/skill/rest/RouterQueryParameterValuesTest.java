package eu.jsentinel.jcustos.demo.skill.rest;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.jsentinel.jcustos.authorization.annotations.PublicRoute;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * RF31 (JS-SEC-098): the {@link RestRequest} the template's {@link Router} builds reports every
 * value of a repeated query parameter, so the OAuth2 callback handler can refuse a repeated
 * {@code state}, {@code code} or {@code iss}. Until the exit review of 00.84.00 the router kept
 * the lossy default of {@code queryParameterValues()}, which saw only the last value. Real JDK
 * {@code HttpServer} on loopback, no mocks.
 */
@DisplayName("RF31 — the Router reports every value of a repeated query parameter")
class RouterQueryParameterValuesTest {

  private HttpServer server;
  private DemoHttp http;

  @BeforeEach
  void start() throws IOException {
    List<Router.Route> routes = new Router.Builder()
        .add("GET", "/api/echo", QueryEcho.class, "echo")
        .build();
    server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    server.createContext("/api", new Router((RestSubjectResolver) request -> Optional.empty(), routes));
    server.start();
    http = new DemoHttp(server.getAddress().getPort());
  }

  @AfterEach
  void stop() {
    server.stop(0);
  }

  @Test
  @DisplayName("a repeated parameter keeps all its values in wire order; the single-valued view keeps the last one")
  void repeatedParameter_keepsEveryValue() throws Exception {
    DemoHttp.Response response = http.get("/api/echo?state=first&code=c1&state=second&flag", null);

    assertEquals(200, response.status(), response.body());
    assertEquals("{state=[first, second], code=[c1], flag=[]}|{state=second, code=c1, flag=}",
        response.body(), "until the exit review queryParameterValues() showed state=[second] only");
  }

  @Test
  @DisplayName("without a query both views are empty")
  void noQuery_isEmpty() throws Exception {
    assertEquals("{}|{}", http.get("/api/echo", null).body());
  }

  /** Echoes both query views of the request the router built. */
  public static final class QueryEcho {

    @PublicRoute
    public static void echo(HttpExchange exchange, JCustosSubject subject) throws IOException {
      RestRequest request = Router.restRequest(exchange);
      Map<String, List<String>> values = request.queryParameterValues();
      Router.respond(exchange, 200, values + "|" + request.queryParameters());
    }
  }
}
