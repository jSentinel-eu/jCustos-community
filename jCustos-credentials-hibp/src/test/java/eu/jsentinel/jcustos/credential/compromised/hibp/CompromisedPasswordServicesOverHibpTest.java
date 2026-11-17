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

import com.sun.net.httpserver.HttpServer;
import eu.jsentinel.jcustos.audit.NoopJCustosAuditService;
import eu.jsentinel.jcustos.credential.change.PasswordChangeCommand;
import eu.jsentinel.jcustos.credential.change.PasswordChangeResult;
import eu.jsentinel.jcustos.credential.change.PasswordChangeService;
import eu.jsentinel.jcustos.credential.compromised.CheckFailurePolicy;
import eu.jsentinel.jcustos.credential.compromised.CompositeCompromisedPasswordChecker;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordPolicy;
import eu.jsentinel.jcustos.credential.compromised.LocalBlocklistCompromisedPasswordChecker;
import eu.jsentinel.jcustos.credential.input.PasswordInputPolicy;
import eu.jsentinel.jcustos.credential.input.PasswordInputValidator;
import eu.jsentinel.jcustos.credential.input.PasswordInputViolation;
import eu.jsentinel.jcustos.credential.lifecycle.CredentialLifecycleService;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.password.limiter.NoLimitKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.reset.InMemoryResetTokenStore;
import eu.jsentinel.jcustos.credential.reset.PasswordResetConsumeResult;
import eu.jsentinel.jcustos.credential.reset.PasswordResetService;
import eu.jsentinel.jcustos.credential.reset.ResetTokenCreationResult;
import eu.jsentinel.jcustos.credential.reset.ResetTokenStatus;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.credential.store.CredentialRecord;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.store.InMemoryCredentialStore;
import eu.jsentinel.jcustos.credential.token.SelectorVerifierToken;
import eu.jsentinel.jcustos.credential.token.TokenDigestService;
import eu.jsentinel.jcustos.net.EndpointSecurity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The password services with a {@link CompositeCompromisedPasswordChecker}
 * over a local list and the real {@link HaveIBeenPwnedCompromisedPasswordChecker}
 * against a JDK {@link HttpServer} on loopback that answers like the range API -
 * and, switched to an outage, with {@code 503}. Plain {@code http} to loopback
 * needs {@code -Djcustos.dev=true} since 00.84.00 (JS-SEC-098).
 */
@DisplayName("Password blocklists — change and reset over a loopback HIBP range API, listing and failing")
class CompromisedPasswordServicesOverHibpTest {

  private static final Instant T0 = Instant.parse("2026-11-17T10:00:00Z");
  private static final String CURRENT = "correct horse battery";
  /** Strong-looking, but listed by the loopback range API. */
  private static final String BREACHED = "Tangerine-Harbour-Kite-77";
  /** Listed by neither. */
  private static final String FRESH = "Glacier-Lantern-Orbit-42";
  /** Listed by the local list only. */
  private static final String COMMON = "password123";

  private final InMemoryCredentialStore credentials = new InMemoryCredentialStore();
  private final InMemoryResetTokenStore resetTokens = new InMemoryResetTokenStore();
  private final Clock clock = Clock.fixed(T0, ZoneOffset.UTC);
  private final PasswordHashingService hashing =
      PasswordHashingServices.defaults(fastPolicy(), NoLimitKdfExecutionLimiter.INSTANCE);
  private final LocalBlocklistCompromisedPasswordChecker local =
      LocalBlocklistCompromisedPasswordChecker.fromLines(Stream.of("# synthetic", COMMON));

  private final AtomicInteger rangeRequests = new AtomicInteger();
  private final AtomicBoolean outage = new AtomicBoolean();
  private HttpServer server;
  private HaveIBeenPwnedCompromisedPasswordChecker hibp;

  @BeforeEach
  void startRangeApi() throws IOException {
    System.setProperty(EndpointSecurity.DEV_MODE_PROPERTY, "true");
    String breached = sha1Hex(BREACHED);
    String breachedPrefix = breached.substring(0, 5);
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/range/", exchange -> {
      rangeRequests.incrementAndGet();
      if (outage.get()) {
        exchange.sendResponseHeaders(503, -1);
        exchange.close();
        return;
      }
      String prefix = exchange.getRequestURI().getPath().substring("/range/".length());
      // Padded like the real API: entries with a count of 0 are padding.
      String body = "0000000000000000000000000000000000A:0\r\n"
          + (prefix.equals(breachedPrefix) ? breached.substring(5) + ":1234\r\n" : "")
          + "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n";
      byte[] bytes = body.getBytes(StandardCharsets.US_ASCII);
      exchange.sendResponseHeaders(200, bytes.length);
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(bytes);
      }
    });
    server.start();
    hibp = HaveIBeenPwnedCompromisedPasswordChecker.usingJdkHttpClient(
        URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/range/"),
        Duration.ofSeconds(5));
  }

  @AfterEach
  void stopRangeApi() {
    if (server != null) {
      server.stop(0);
    }
    System.clearProperty(EndpointSecurity.DEV_MODE_PROPERTY);
  }

  private String register() {
    String encoded = hashing.hash(CURRENT.toCharArray()).encodedHash();
    credentials.register(new CredentialRecord("alice", encoded, CredentialStatus.ACTIVE, 1L,
        T0, T0));
    return encoded;
  }

  private String storedHash() {
    return credentials.findByUsername("alice").orElseThrow().encodedHash();
  }

  private boolean passwordIs(String password) {
    return hashing.verify(password.toCharArray(), storedHash())
        instanceof CredentialVerificationResult.Verified;
  }

  private CredentialLifecycleService lifecycle() {
    return new CredentialLifecycleService(credentials, NoopJCustosAuditService.INSTANCE, clock);
  }

  private PasswordChangeService change(CheckFailurePolicy onFailure,
                                       CompromisedPasswordPolicy policy) {
    return new PasswordChangeService(credentials, hashing, new PasswordInputValidator(),
        PasswordInputPolicy.defaults(), lifecycle(), clock)
        .withCompromisedPasswordCheck(
            CompositeCompromisedPasswordChecker.of(onFailure, local, hibp), policy);
  }

  private PasswordResetService reset(CheckFailurePolicy onFailure,
                                     CompromisedPasswordPolicy policy) {
    return new PasswordResetService(credentials, resetTokens, new TokenDigestService(), hashing,
        new PasswordInputValidator(), PasswordInputPolicy.defaults(), lifecycle(), clock,
        NoopJCustosAuditService.INSTANCE)
        .withCompromisedPasswordCheck(
            CompositeCompromisedPasswordChecker.of(onFailure, local, hibp), policy);
  }

  private static PasswordChangeCommand command(String next) {
    return new PasswordChangeCommand(
        "alice", SecretValue.ofString(CURRENT), SecretValue.ofString(next));
  }

  private static SelectorVerifierToken issue(PasswordResetService service) {
    return assertInstanceOf(ResetTokenCreationResult.Created.class,
        service.issue("alice", Duration.ofMinutes(15))).token();
  }

  @Test
  @DisplayName("a password the range API lists: the change is NewPasswordRejected(COMPROMISED), the reset Failed")
  void breachedPasswordIsRefused() {
    String stored = register();

    PasswordChangeResult changed = change(CheckFailurePolicy.BLOCK,
        CompromisedPasswordPolicy.failClosed()).change(command(BREACHED));
    assertEquals(PasswordInputViolation.COMPROMISED,
        assertInstanceOf(PasswordChangeResult.NewPasswordRejected.class, changed).violation());
    assertEquals(stored, storedHash());
    assertEquals(1, rangeRequests.get(), "the local list does not know it; the range API does");

    PasswordResetService service = reset(CheckFailurePolicy.BLOCK,
        CompromisedPasswordPolicy.failClosed());
    SelectorVerifierToken token = issue(service);
    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        service.consume(token.encode(), SecretValue.ofString(BREACHED)));
    assertEquals(stored, storedHash());
    assertEquals(ResetTokenStatus.ISSUED,
        resetTokens.findBySelector(token.selector()).orElseThrow().status());
  }

  @Test
  @DisplayName("a password the local list knows never reaches the range API")
  void localHitStaysLocal() {
    register();

    assertEquals(PasswordInputViolation.COMPROMISED,
        assertInstanceOf(PasswordChangeResult.NewPasswordRejected.class,
            change(CheckFailurePolicy.BLOCK, CompromisedPasswordPolicy.failClosed())
                .change(command("PASSWORD123"))).violation());
    assertEquals(0, rangeRequests.get());
  }

  @Test
  @DisplayName("range API down, BLOCK: the change is VerificationUnavailable, the reset Failed and the link survives")
  void outageUnderBlockRefusesWithoutAVerdict() {
    String stored = register();
    outage.set(true);

    assertSame(PasswordChangeResult.VerificationUnavailable.INSTANCE,
        change(CheckFailurePolicy.BLOCK, CompromisedPasswordPolicy.failClosed())
            .change(command(FRESH)));
    assertEquals(stored, storedHash());

    PasswordResetService service = reset(CheckFailurePolicy.BLOCK,
        CompromisedPasswordPolicy.failClosed());
    SelectorVerifierToken token = issue(service);
    assertSame(PasswordResetConsumeResult.Failed.INSTANCE,
        service.consume(token.encode(), SecretValue.ofString(FRESH)));
    assertEquals(stored, storedHash());
    assertEquals(2, rangeRequests.get(), "both refusals asked the range API");

    // The range API is back: the same link sets the password.
    outage.set(false);
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        service.consume(token.encode(), SecretValue.ofString(FRESH)));
    assertTrue(passwordIs(FRESH));
  }

  @Test
  @DisplayName("range API unreachable, BLOCK: refused as well")
  void unreachableUnderBlockIsRefused() {
    register();
    server.stop(0);
    server = null;

    assertSame(PasswordChangeResult.VerificationUnavailable.INSTANCE,
        change(CheckFailurePolicy.BLOCK, CompromisedPasswordPolicy.failClosed())
            .change(command(FRESH)));
    assertTrue(passwordIs(CURRENT));
  }

  @Test
  @DisplayName("range API down, ALLOW: change and reset proceed")
  void outageUnderAllowProceeds() {
    register();
    outage.set(true);

    assertInstanceOf(PasswordChangeResult.Succeeded.class,
        change(CheckFailurePolicy.ALLOW, CompromisedPasswordPolicy.defaults())
            .change(command(FRESH)));
    assertTrue(passwordIs(FRESH));

    PasswordResetService service = reset(CheckFailurePolicy.ALLOW,
        CompromisedPasswordPolicy.defaults());
    assertSame(PasswordResetConsumeResult.Succeeded.INSTANCE,
        service.consume(issue(service).encode(), SecretValue.ofString("Harbour-Quartz-Meadow-19")));
    assertTrue(passwordIs("Harbour-Quartz-Meadow-19"));
    assertEquals(2, rangeRequests.get());
  }

  private static String sha1Hex(String value) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-1")
          .digest(value.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest).toUpperCase(Locale.ROOT);
    } catch (NoSuchAlgorithmException impossible) {
      throw new IllegalStateException(impossible);
    }
  }

  private static PasswordHashPolicy fastPolicy() {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
    defaults.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    Map<String, String> min = new LinkedHashMap<>(defaults);
    min.put(Pbkdf2ParameterNames.SALT_LENGTH, "16");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(Pbkdf2ParameterNames.ITERATIONS, "2000");
    max.put(Pbkdf2ParameterNames.KEY_LENGTH, "64");
    max.put(Pbkdf2ParameterNames.SALT_LENGTH, "64");
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, defaults)
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, min)
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, max)
        .build();
  }
}
