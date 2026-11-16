package eu.jsentinel.jcustos.demo.skill.rest;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Minimal HTTP client for the end-to-end tests — real sockets, no mocks. */
final class DemoHttp {

  private static final Pattern TOKEN = Pattern.compile("\"token\":\"([^\"]+)\"");
  private static final Pattern ID = Pattern.compile("\"id\":(\\d+)");

  private final int port;
  private final HttpClient client = HttpClient.newHttpClient();

  DemoHttp(int port) {
    this.port = port;
  }

  record Response(int status, String body, HttpResponse<String> raw) {
    String header(String name) {
      return raw.headers().firstValue(name).orElse(null);
    }
  }

  Response get(String path, String token) throws IOException, InterruptedException {
    return send("GET", path, token, null);
  }

  Response post(String path, String json, String token) throws IOException, InterruptedException {
    return send("POST", path, token, json);
  }

  Response send(String method, String path, String token, String json)
      throws IOException, InterruptedException {
    HttpRequest.Builder builder = HttpRequest.newBuilder(
            URI.create("http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":" + port + path))
        .method(method, json == null
            ? HttpRequest.BodyPublishers.noBody()
            : HttpRequest.BodyPublishers.ofString(json));
    if (json != null) {
      builder.header("Content-Type", "application/json");
    }
    if (token != null) {
      builder.header("Authorization", "Bearer " + token);
    }
    HttpResponse<String> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    return new Response(response.statusCode(), response.body(), response);
  }

  String login(String username, String password) throws IOException, InterruptedException {
    Response response = post("/api/auth/login",
        "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}", null);
    if (response.status() != 200) {
      throw new AssertionError("login of " + username + " failed: " + response.status() + " " + response.body());
    }
    Matcher m = TOKEN.matcher(response.body());
    if (!m.find()) {
      throw new AssertionError("no token in " + response.body());
    }
    return m.group(1);
  }

  long createUser(String adminToken, String username, String password, String role)
      throws IOException, InterruptedException {
    Response response = post("/api/users", "{\"username\":\"" + username + "\",\"password\":\""
        + password + "\",\"name\":\"" + username + "\",\"role\":\"" + role + "\"}", adminToken);
    if (response.status() != 201) {
      throw new AssertionError("create " + username + " failed: " + response.status() + " " + response.body());
    }
    Matcher m = ID.matcher(response.body());
    if (!m.find()) {
      throw new AssertionError("no id in " + response.body());
    }
    return Long.parseLong(m.group(1));
  }

  /** Sends {@code request} verbatim over a raw socket and returns the whole answer. */
  String raw(String request) throws IOException {
    try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), port)) {
      socket.setSoTimeout(10_000);
      OutputStream out = socket.getOutputStream();
      out.write(request.getBytes(StandardCharsets.ISO_8859_1));
      out.flush();
      InputStream in = socket.getInputStream();
      return new String(in.readAllBytes(), StandardCharsets.ISO_8859_1);
    }
  }
}
