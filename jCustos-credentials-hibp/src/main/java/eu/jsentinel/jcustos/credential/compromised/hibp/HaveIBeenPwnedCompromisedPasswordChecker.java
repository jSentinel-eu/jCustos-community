/*-
 * #%L
 * Security Credentials — HIBP (HaveIBeenPwned) Opt-In
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.compromised.hibp;

import com.svenruppert.dependencies.core.net.MediaType;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordChecker;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordResult;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.net.EndpointSecurity;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import java.util.function.Function;

/**
 * Opt-in online {@link CompromisedPasswordChecker} that talks to a
 * HaveIBeenPwned-style k-anonymity range API.
 *
 * <p>Protocol (CWE-359, CWE-201):</p>
 * <ol>
 *   <li>Compute the SHA-1 hex digest of the candidate password.</li>
 *   <li>Send only the first five hex characters to
 *       {@code GET https://api.pwnedpasswords.com/range/{prefix}}.</li>
 *   <li>The service returns a text body of {@code SUFFIX:COUNT} pairs
 *       — one per matching hash in its data set.</li>
 *   <li>Locally scan for the candidate's suffix (remaining 35 hex
 *       chars). If found, report {@link CompromisedPasswordResult.Pwned}
 *       with the reported count.</li>
 * </ol>
 *
 * <p>The plain candidate never leaves the JVM. The SHA-1 digest is
 * computed in process and only the 5-char prefix is transmitted.
 * SHA-1 is used for protocol compatibility — it is *not* used for
 * password storage (CWE-916).</p>
 *
 * <p>The implementation accepts an injected {@link Function range
 * lookup} so tests can run without network. The static factory
 * {@link #usingJdkHttpClient(URI, Duration)} wires a default
 * implementation built on {@link HttpClient}.</p>
 */
public final class HaveIBeenPwnedCompromisedPasswordChecker
    implements CompromisedPasswordChecker {

  /**
   * Default endpoint per the HaveIBeenPwned k-anonymity API.
   * Operators with private mirrors point this elsewhere.
   */
  public static final URI DEFAULT_ENDPOINT =
      URI.create("https://api.pwnedpasswords.com/range/");

  private final Function<String, RangeResponse> rangeLookup;

  HaveIBeenPwnedCompromisedPasswordChecker(
      Function<String, RangeResponse> rangeLookup) {
    this.rangeLookup = Objects.requireNonNull(rangeLookup, "rangeLookup");
  }

  /**
   * Builds an instance that performs the range lookup via the
   * JDK {@link HttpClient}.
   *
   * @param endpoint base URI; the 5-char prefix is appended as a
   *                 path segment. {@code https}; plain {@code http} only
   *                 to a loopback host with {@code -Djcustos.dev=true}
   *                 (since 00.84.00, see {@link EndpointSecurity})
   * @param timeout  per-request timeout
   */
  public static HaveIBeenPwnedCompromisedPasswordChecker usingJdkHttpClient(
      URI endpoint, Duration timeout) {
    Objects.requireNonNull(endpoint, "endpoint");
    Objects.requireNonNull(timeout, "timeout");
    // JS-SEC-046 (CWE-319): the operator-supplied endpoint must be https. A plaintext hop would
    // expose the 5-char SHA-1 prefix of every candidate password (eroding the documented
    // k-anonymity guarantee) and let a MITM strip the body to force every breached password to
    // 'Clean'. JS-SEC-098: the one https rule of jCustos - loopback http (a local mirror, a test
    // stub) only with -Djcustos.dev=true; up to 00.83.00 loopback http needed no flag.
    EndpointSecurity.requireHttps(endpoint, "hibp/endpoint-not-https");
    // R12 (V00.76.10): cap the response body so a hostile / compromised mirror
    // (operators may repoint the endpoint) cannot return a multi-GB body and OOM
    // the verifying JVM. A padded HIBP range response is a few tens of KB; 1 MiB
    // sits far above any legitimate response.
    final int maxRangeBytes = 1024 * 1024;
    HttpClient http = HttpClient.newBuilder()
        .connectTimeout(timeout)
        // R12: never follow redirects — the HIBP range API does not redirect, and
        // a redirect from a hostile mirror is a request-forwarding / SSRF vector.
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();
    Function<String, RangeResponse> lookup = prefix -> {
      try {
        HttpRequest req = HttpRequest.newBuilder()
            .uri(endpoint.resolve(prefix))
            .timeout(timeout)
            .header("Accept", MediaType.TEXT_PLAIN.mime())
            // R022: request padded range responses so a network observer cannot
            // infer the queried bucket size. Padding entries arrive with a count
            // of 0 and are tolerated by scan().
            .header("Add-Padding", "true")
            .GET()
            .build();
        HttpResponse<java.io.InputStream> res = http.send(req,
            HttpResponse.BodyHandlers.ofInputStream());
        if (res.statusCode() == 429) {
          return new RangeResponse(null,
              CompromisedPasswordResult.FailureReason.RATE_LIMITED);
        }
        if (res.statusCode() < 200 || res.statusCode() >= 300) {
          return new RangeResponse(null,
              CompromisedPasswordResult.FailureReason.NETWORK);
        }
        // R12: read at most maxRangeBytes + 1; a body over the cap is treated as
        // a network failure rather than buffered into the heap.
        byte[] body;
        try (java.io.InputStream in = res.body()) {
          body = in.readNBytes(maxRangeBytes + 1);
        }
        if (body.length > maxRangeBytes) {
          return new RangeResponse(null,
              CompromisedPasswordResult.FailureReason.NETWORK);
        }
        return new RangeResponse(new String(body, StandardCharsets.US_ASCII), null);
      } catch (java.net.http.HttpTimeoutException timeoutEx) {
        return new RangeResponse(null,
            CompromisedPasswordResult.FailureReason.TIMEOUT);
      } catch (java.io.IOException io) {
        return new RangeResponse(null,
            CompromisedPasswordResult.FailureReason.NETWORK);
      } catch (InterruptedException ie) {
        Thread.currentThread().interrupt();
        return new RangeResponse(null,
            CompromisedPasswordResult.FailureReason.NETWORK);
      }
    };
    return new HaveIBeenPwnedCompromisedPasswordChecker(lookup);
  }

  @Override
  public CompromisedPasswordResult check(SecretValue password) {
    Objects.requireNonNull(password, "password");
    char[] chars = password.asChars();
    byte[] utf8 = null;
    try {
      utf8 = toUtf8(chars);
      String hex = sha1Hex(utf8);
      String prefix = hex.substring(0, 5);
      String suffix = hex.substring(5);
      RangeResponse response = rangeLookup.apply(prefix);
      if (response.failure() != null) {
        return new CompromisedPasswordResult.CheckFailed(response.failure());
      }
      // JS-SEC-046 (CWE-319): with Add-Padding a legitimate range response is never empty, so a 2xx
      // with an empty/blank body means a hostile or broken mirror. Fail CLOSED (CheckFailed) rather
      // than treating it as Clean, so a stripped body cannot silently pass a breached password.
      if (response.body() == null || response.body().isBlank()) {
        // Exit-review F3: an empty 2xx body is a protocol anomaly, not a transport failure —
        // MALFORMED_RESPONSE labels it precisely (still fail-closed via CheckFailed).
        return new CompromisedPasswordResult.CheckFailed(
            CompromisedPasswordResult.FailureReason.MALFORMED_RESPONSE);
      }
      return scan(response.body(), suffix);
    } catch (RuntimeException unexpected) {
      return new CompromisedPasswordResult.CheckFailed(
          CompromisedPasswordResult.FailureReason.UNKNOWN);
    } finally {
      Arrays.fill(chars, '\0');
      if (utf8 != null) {
        Arrays.fill(utf8, (byte) 0);
      }
    }
  }

  private static CompromisedPasswordResult scan(
      String body, String suffix) {
    if (body == null || body.isEmpty()) {
      return CompromisedPasswordResult.Clean.INSTANCE;
    }
    int from = 0;
    int len = body.length();
    while (from < len) {
      int eol = body.indexOf('\n', from);
      int end = eol < 0 ? len : eol;
      int colon = body.indexOf(':', from);
      if (colon > from && colon < end) {
        if (equalsIgnoreCaseRange(body, from, colon, suffix)) {
          long count = parseCountSafe(body, colon + 1, end);
          // R022: with Add-Padding, padding entries carry a count of 0. A real
          // suffix match with count 0 means the password is NOT in any breach —
          // returning Pwned here would be a false positive.
          return count > 0
              ? new CompromisedPasswordResult.Pwned(count)
              : CompromisedPasswordResult.Clean.INSTANCE;
        }
      } else if (eol < 0) {
        break;
      }
      if (eol < 0) {
        break;
      }
      from = eol + 1;
    }
    return CompromisedPasswordResult.Clean.INSTANCE;
  }

  private static boolean equalsIgnoreCaseRange(
      String body, int start, int end, String suffix) {
    int rangeLen = end - start;
    while (rangeLen > 0
        && Character.isWhitespace(body.charAt(start + rangeLen - 1))) {
      rangeLen--;
    }
    if (rangeLen != suffix.length()) {
      return false;
    }
    for (int i = 0; i < rangeLen; i++) {
      char a = Character.toUpperCase(body.charAt(start + i));
      char b = Character.toUpperCase(suffix.charAt(i));
      if (a != b) {
        return false;
      }
    }
    return true;
  }

  private static long parseCountSafe(String body, int start, int end) {
    long result = 0L;
    boolean any = false;
    for (int i = start; i < end; i++) {
      char c = body.charAt(i);
      if (c >= '0' && c <= '9') {
        result = result * 10 + (c - '0');
        any = true;
      } else if (Character.isWhitespace(c)) {
        if (any) {
          break;
        }
      } else {
        if (any) {
          break;
        }
      }
    }
    return any ? result : 1L;
  }

  private static byte[] toUtf8(char[] chars) {
    java.nio.CharBuffer cb = java.nio.CharBuffer.wrap(chars);
    java.nio.ByteBuffer bb = StandardCharsets.UTF_8.encode(cb);
    byte[] out = new byte[bb.remaining()];
    bb.get(out);
    return out;
  }

  private static String sha1Hex(byte[] bytes) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      byte[] digest = md.digest(bytes);
      StringBuilder sb = new StringBuilder(digest.length * 2);
      for (byte b : digest) {
        sb.append(Character.forDigit((b >> 4) & 0xF, 16));
        sb.append(Character.forDigit(b & 0xF, 16));
      }
      return sb.toString().toUpperCase(Locale.ROOT);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(
          "JCA must always provide SHA-1", e);
    }
  }

  /**
   * Result envelope from the injected range lookup. Either
   * {@code body} or {@code failure} is non-null; never both.
   */
  public record RangeResponse(
      String body,
      CompromisedPasswordResult.FailureReason failure) {
    public RangeResponse {
      if ((body == null) == (failure == null)) {
        throw new IllegalArgumentException(
            "exactly one of body / failure must be non-null");
      }
    }
  }
}
