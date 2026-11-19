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
package eu.jsentinel.jcustos.oauth2.http;

import com.svenruppert.dependencies.core.net.MediaType;
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.util.BoundedHttpBody;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * The form-{@code POST} to an OAuth2 endpoint, in one place for every module that talks to one:
 * the token endpoint client, PAR, revocation, introspection and the device grant of
 * {@code jCustos-oauth2}, and the token-exchange and client-credentials strategies of
 * {@code jCustos-propagation-oidc} (JS-SEC-098, CWE-1041, CWE-770). It applies the client
 * authentication ({@code client_secret_basic}, {@code client_secret_post}, {@code private_key_jwt},
 * {@code client_secret_jwt} or a public client), bounds the exchange in time
 * ({@link #TIMEOUT}) and the response in size ({@link #MAX_RESPONSE_BYTES}) and maps transport
 * failures to {@link OAuth2Error}. JDK {@link HttpClient} only; a {@code private_key_jwt}
 * assertion is signed through the {@code JwtSigner} SPI, so the JOSE library stays in
 * {@code jCustos-jwt}.
 *
 * <p>Up to 00.83.00 the token endpoint client and the two propagation strategies carried their
 * own copies of this exchange; the 1 MiB response cap had to be added to each of them
 * separately (JS-SEC-036). The endpoint itself is checked when a client is built, with
 * {@link eu.jsentinel.jcustos.net.EndpointSecurity#requireHttps(URI, String)}.
 *
 * <p>Internal to jCustos: public so that several modules share it, not for application code.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi("Internal to jCustos; shared by the OAuth2, identity and propagation modules.")
public final class OAuth2FormPost {

  /** Time bound of one exchange, response body included. */
  public static final Duration TIMEOUT = Duration.ofSeconds(10);

  /** Largest accepted response body, in bytes (1 MiB). */
  public static final int MAX_RESPONSE_BYTES = 1024 * 1024;

  private static final String ACCEPT = "Accept";
  private static final String CONTENT_TYPE = "Content-Type";
  private static final String AUTHORIZATION = "Authorization";

  /**
   * A completed HTTP exchange.
   *
   * @param status the HTTP status code
   * @param body   the response body, decoded as UTF-8
   */
  public record Outcome(int status, String body) {

    /**
     * Shows the length of the body, not the body (JS-SEC-127, CWE-532): an introspection
     * response names the token's subject and scopes, a token response carries tokens.
     *
     * @return a description without the body
     */
    @Override
    public String toString() {
      return "Outcome[status=" + status + ", body=<"
          + (body == null ? 0 : body.length()) + " chars>]";
    }
  }

  private OAuth2FormPost() {
    throw new AssertionError("no instances");
  }

  /**
   * POSTs {@code form} with the client authentication {@code auth} to {@code endpoint}; a client
   * assertion is dated with the system clock.
   *
   * @param http     the HTTP client
   * @param endpoint the endpoint, already checked
   * @param form     the form fields; the map itself is not changed
   * @param auth     the client authentication
   * @return the exchange, or a {@code network-error} / {@code malformed-response}
   */
  public static Result<Outcome, OAuth2Error> post(HttpClient http, URI endpoint,
      Map<String, String> form, ClientAuthentication auth) {
    return post(http, endpoint, form, auth, Instant::now);
  }

  /**
   * POSTs {@code form} with the client authentication {@code auth} to {@code endpoint}.
   *
   * @param http     the HTTP client
   * @param endpoint the endpoint, already checked; it is also the {@code aud} of a client
   *                 assertion
   * @param form     the form fields; the map itself is not changed
   * @param auth     the client authentication
   * @param clock    the clock that dates a client assertion
   * @return the exchange, or a {@code network-error} / {@code malformed-response}
   */
  public static Result<Outcome, OAuth2Error> post(HttpClient http, URI endpoint,
      Map<String, String> form, ClientAuthentication auth, Supplier<Instant> clock) {
    Objects.requireNonNull(auth, "auth");
    Objects.requireNonNull(clock, "clock");
    Map<String, String> fields = new LinkedHashMap<>(Objects.requireNonNull(form, "form"));
    HttpRequest.Builder request = request(endpoint);
    switch (auth) {
      case ClientAuthentication.ClientSecretBasic basic ->
          request.header(AUTHORIZATION, basicHeader(basic.clientId(), basic.secret()));
      case ClientAuthentication.ClientSecretPost post -> {
        fields.put("client_id", post.clientId());
        byte[] secret = post.secret().asUtf8Bytes();
        fields.put("client_secret", new String(secret, StandardCharsets.UTF_8));
        Arrays.fill(secret, (byte) 0);
      }
      case ClientAuthentication.NoneAuthentication none -> fields.put("client_id", none.clientId());
      case ClientAuthentication.PrivateKeyJwt pk ->
          ClientAssertions.applyPrivateKeyJwt(pk, endpoint, clock, JwtSigners.require(), fields);
      case ClientAuthentication.ClientSecretJwt cs ->
          ClientAssertions.applyClientSecretJwt(cs, endpoint, clock, fields);
    }
    return send(http, request, fields);
  }

  /**
   * POSTs {@code form} to {@code endpoint} without any client authentication — for a caller
   * that has no client id at all.
   *
   * @param http     the HTTP client
   * @param endpoint the endpoint, already checked
   * @param form     the form fields; the map itself is not changed
   * @return the exchange, or a {@code network-error} / {@code malformed-response}
   */
  public static Result<Outcome, OAuth2Error> postWithoutClientAuthentication(HttpClient http,
      URI endpoint, Map<String, String> form) {
    return send(http, request(endpoint),
        new LinkedHashMap<>(Objects.requireNonNull(form, "form")));
  }

  private static HttpRequest.Builder request(URI endpoint) {
    return HttpRequest.newBuilder(Objects.requireNonNull(endpoint, "endpoint"))
        .timeout(TIMEOUT)
        .header(ACCEPT, MediaType.APPLICATION_JSON.mime())
        .header(CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED.mime());
  }

  private static Result<Outcome, OAuth2Error> send(HttpClient http, HttpRequest.Builder request,
      Map<String, String> fields) {
    HttpResponse<byte[]> response;
    try {
      // Materialising, size-limited handler: send() returns only once the body is complete, so
      // the request timeout bounds the transfer as well (CWE-400).
      response = Objects.requireNonNull(http, "http").send(
          request.POST(HttpRequest.BodyPublishers.ofString(encode(fields))).build(),
          BoundedHttpBody.ofByteArray(MAX_RESPONSE_BYTES + 1));
    } catch (HttpTimeoutException e) {
      return Result.failure(new OAuth2Error.NetworkError("timeout"));
    } catch (IOException e) {
      return Result.failure(new OAuth2Error.NetworkError(e.getClass().getSimpleName()));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return Result.failure(new OAuth2Error.NetworkError("interrupted"));
    }
    byte[] bytes = response.body();
    if (bytes.length > MAX_RESPONSE_BYTES) {
      return Result.failure(new OAuth2Error.MalformedResponse("body exceeds the size cap"));
    }
    return Result.success(new Outcome(response.statusCode(), new String(bytes, StandardCharsets.UTF_8)));
  }

  /**
   * The {@code client_secret_basic} credentials (RFC 6749 §2.3.1, CWE-116): the client id and
   * the secret are each encoded with {@code application/x-www-form-urlencoded} (Appendix B),
   * then {@code id:secret} is Base64-encoded. Up to 00.83.00 the raw values were joined, so a
   * {@code :} in the client id moved the split, and {@code %}, {@code +}, a space or a
   * non-ASCII character in the secret reached a compliant server as a different secret.
   *
   * <p>{@link URLEncoder} with UTF-8 produces the encoding of Appendix B: a space becomes
   * {@code +}, every other octet outside {@code A-Z a-z 0-9 - . _ *} becomes {@code %XX}, so
   * the separator {@code :} can only be the one between id and secret. It leaves {@code *}
   * unescaped and escapes {@code ~}; a form decoder reads an unescaped octet as itself and
   * {@code %7E} as {@code ~}, so both decode to the original value.
   *
   * <p>The secret passes through a {@link String} for the encoder, as the
   * {@code client_secret_post} form field always has; the header itself carries it in Base64.
   * The byte arrays built here are zeroed.
   */
  private static String basicHeader(String clientId, SecretValue secret) {
    char[] secretChars = secret.asChars();
    byte[] userInfo = (formEncode(clientId) + ':' + formEncode(new String(secretChars)))
        .getBytes(StandardCharsets.US_ASCII);
    Arrays.fill(secretChars, '\0');
    String header = "Basic " + Base64.getEncoder().encodeToString(userInfo);
    Arrays.fill(userInfo, (byte) 0);
    return header;
  }

  /** {@code application/x-www-form-urlencoded} with UTF-8 (RFC 6749 Appendix B). */
  private static String formEncode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  private static String encode(Map<String, String> form) {
    StringBuilder sb = new StringBuilder();
    for (Map.Entry<String, String> e : form.entrySet()) {
      if (sb.length() > 0) {
        sb.append('&');
      }
      sb.append(formEncode(e.getKey()))
          .append('=')
          .append(formEncode(e.getValue()));
    }
    return sb.toString();
  }
}
