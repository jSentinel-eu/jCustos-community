/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.credential.propagation.rest;

import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.credential.propagation.BearerToken;
import eu.jsentinel.jcustos.credential.propagation.HeaderValue;
import eu.jsentinel.jcustos.credential.propagation.OidcAccessToken;
import eu.jsentinel.jcustos.credential.propagation.OutboundCall;
import eu.jsentinel.jcustos.credential.propagation.PassThroughStrategy;
import eu.jsentinel.jcustos.credential.propagation.TokenCredential;
import eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore;
import eu.jsentinel.jcustos.jwt.api.JoseHeader;
import eu.jsentinel.jcustos.jwt.api.JwtValidationError;
import eu.jsentinel.jcustos.jwt.api.JwtValidator;
import eu.jsentinel.jcustos.jwt.api.ValidatedJwt;
import eu.jsentinel.jcustos.rest.RestRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-151 (CWE-441), follow-up: since {@code PassThroughStrategy} honours the declared
 * audience, the stock filter has to bind a credential whose audience is known, or
 * {@code @PropagateToken(audience = ...)} with pass-through forwards nothing behind it.
 *
 * <p>The filter, the store and {@code PassThroughStrategy} are the real ones. The
 * {@link JwtValidator} is a hand-written implementation of the SPI that knows a fixed set
 * of synthetic tokens; signature checking itself is the subject of {@code jCustos-jwt}.
 */
@DisplayName("RestTokenCredentialFilter - a known audience for pass-through (JS-SEC-151)")
class RestTokenCredentialFilterAudienceTest {

  private static final String BILLING_TOKEN = "synthetic.jwt.aud-billing";
  private static final String OTHER_TOKEN = "synthetic.jwt.aud-api-a";
  private static final String OPAQUE_TOKEN = "opaque-session-token-0123456789";

  /** {@code @PropagateToken(audience = "billing")} as the propagating proxy describes it. */
  private static final OutboundCall BILLING_CALL =
      new OutboundCall("BillingClient", "charge", "billing", Map.of());

  /** A call without a declared audience - forwarded unchanged, as before. */
  private static final OutboundCall UNDECLARED_CALL =
      new OutboundCall("LegacyClient", "ping", "", Map.of());

  private final TokenCredentialStore store = new ThreadLocalTokenCredentialStore();
  private final KnownTokensValidator validator = new KnownTokensValidator()
      .accept(BILLING_TOKEN, List.of("api-a", "billing"))
      .accept(OTHER_TOKEN, "api-a");

  @BeforeEach
  @AfterEach
  void reset() {
    store.clear();
    JCustosServiceResolver.resetAll();
  }

  // ── the regression: pass-through with a declared audience behind the stock filter ──

  @Test
  @DisplayName("stock filter + installed JwtValidator: a token issued for the declared audience is forwarded")
  void stockFilter_withInstalledValidator_forwardsForTheDeclaredAudience() {
    JCustosServiceResolver.setJwtValidator(validator); // what a .jwt(...) bootstrap does
    RestTokenCredentialFilter filter = new RestTokenCredentialFilter(store);

    Observed observed = run(filter, BILLING_TOKEN, BILLING_CALL);

    OidcAccessToken bound = assertInstanceOf(OidcAccessToken.class, observed.credential.orElseThrow());
    assertEquals(BILLING_TOKEN, bound.value());
    assertTrue(bound.validated().isPresent(), "the validation result travels with the credential");
    assertEquals(Optional.of("api-a,billing"), bound.audience());
    assertEquals(Optional.of(new HeaderValue("Authorization", "Bearer " + BILLING_TOKEN)), observed.header,
        "pass-through forwards a token that is known to be issued for 'billing'");
    assertTrue(store.current().isEmpty(), "the slot is cleared after the handler");
  }

  @Test
  @DisplayName("explicit JwtValidator: the same without a bootstrap")
  void explicitValidator_forwardsForTheDeclaredAudience() {
    RestTokenCredentialFilter filter = new RestTokenCredentialFilter(store, validator);

    Observed observed = run(filter, BILLING_TOKEN, BILLING_CALL);

    assertInstanceOf(OidcAccessToken.class, observed.credential.orElseThrow());
    assertEquals(Optional.of(new HeaderValue("Authorization", "Bearer " + BILLING_TOKEN)), observed.header);
  }

  // ── PassThroughStrategy is not weakened ──

  @Test
  @DisplayName("a validated token issued for another audience is still not forwarded")
  void validatedTokenForAnotherAudience_isNotForwarded() {
    RestTokenCredentialFilter filter = new RestTokenCredentialFilter(store, validator);

    Observed observed = run(filter, OTHER_TOKEN, BILLING_CALL);

    assertInstanceOf(OidcAccessToken.class, observed.credential.orElseThrow());
    assertTrue(observed.header.isEmpty(), "aud=api-a must not travel to 'billing'");
  }

  @Test
  @DisplayName("a token the validator does not accept is bound with an unknown audience and not forwarded for a declared one")
  void rejectedToken_staysOfUnknownAudience() {
    RestTokenCredentialFilter filter = new RestTokenCredentialFilter(store, validator);

    Observed observed = run(filter, OPAQUE_TOKEN, BILLING_CALL);

    BearerToken bound = assertInstanceOf(BearerToken.class, observed.credential.orElseThrow());
    assertEquals(OPAQUE_TOKEN, bound.value());
    assertTrue(bound.audience().isEmpty(), "the filter never states an audience nobody confirmed");
    assertTrue(observed.header.isEmpty());
  }

  @Test
  @DisplayName("a validator that throws leaves the audience unknown; the handler still runs and the message does not quote the token")
  void throwingValidator_staysOfUnknownAudience() {
    JwtValidator broken = compact -> {
      throw new IllegalStateException("JWKS endpoint down while checking " + compact);
    };
    RestTokenCredentialFilter filter = new RestTokenCredentialFilter(store, broken);

    Observed observed = run(filter, BILLING_TOKEN, BILLING_CALL);

    assertTrue(observed.handlerRan);
    assertInstanceOf(BearerToken.class, observed.credential.orElseThrow());
    assertTrue(observed.header.isEmpty());
  }

  // ── the present behaviour without a validator ──

  @Test
  @DisplayName("without any validator the filter binds a BearerToken of unknown audience, as before")
  void noValidator_presentBehaviour() {
    RestTokenCredentialFilter filter = new RestTokenCredentialFilter(store);

    Observed declared = run(filter, BILLING_TOKEN, BILLING_CALL);
    Observed undeclared = run(filter, BILLING_TOKEN, UNDECLARED_CALL);

    BearerToken bound = assertInstanceOf(BearerToken.class, declared.credential.orElseThrow());
    assertTrue(bound.audience().isEmpty());
    assertTrue(declared.header.isEmpty(), "unknown audience: nothing is forwarded for a declared one");
    assertEquals(Optional.of(new HeaderValue("Authorization", "Bearer " + BILLING_TOKEN)), undeclared.header,
        "a call without a declared audience keeps forwarding");
    assertEquals(0, validator.calls, "no validator was configured, none may be asked");
  }

  // ── a credential that is already bound ──

  @Test
  @DisplayName("a validated credential the resolver already bound for this token is kept, not downgraded")
  void alreadyBoundCredentialForThisToken_isKept() {
    RestTokenCredentialFilter filter = new RestTokenCredentialFilter(store); // no validator at hand
    OidcAccessToken fromResolver = OidcAccessToken.fromValidated(
        BILLING_TOKEN, validator.validate(BILLING_TOKEN).toOptional().orElseThrow());
    store.bind(fromResolver);

    Observed observed = run(filter, BILLING_TOKEN, BILLING_CALL);

    assertSame(fromResolver, observed.credential.orElseThrow());
    assertEquals(Optional.of(new HeaderValue("Authorization", "Bearer " + BILLING_TOKEN)), observed.header);
    assertTrue(store.current().isEmpty(), "the slot is cleared after the handler all the same");
  }

  @Test
  @DisplayName("a credential bound for a different token is replaced by the token of this request")
  void credentialOfAnotherToken_isReplaced() {
    RestTokenCredentialFilter filter = new RestTokenCredentialFilter(store, validator);
    store.bind(OidcAccessToken.fromValidated(
        BILLING_TOKEN, validator.validate(BILLING_TOKEN).toOptional().orElseThrow()));

    Observed observed = run(filter, OTHER_TOKEN, BILLING_CALL);

    assertEquals(OTHER_TOKEN, observed.credential.orElseThrow().value(),
        "a left-over credential of another token must not stand in for this request");
    assertTrue(observed.header.isEmpty());
  }

  @Test
  @DisplayName("the explicit validator takes precedence over the installed one")
  void explicitValidator_winsOverTheInstalledOne() {
    JCustosServiceResolver.setJwtValidator(new KnownTokensValidator()); // knows no token
    RestTokenCredentialFilter filter = new RestTokenCredentialFilter(store, validator);

    Observed observed = run(filter, BILLING_TOKEN, BILLING_CALL);

    assertInstanceOf(OidcAccessToken.class, observed.credential.orElseThrow());
    assertEquals(1, validator.calls);
  }

  // ── helpers ──

  /** Runs the filter and, inside the handler, what a propagating client does. */
  private Observed run(RestTokenCredentialFilter filter, String token, OutboundCall call) {
    Observed observed = new Observed();
    AtomicReference<Optional<TokenCredential>> credential = new AtomicReference<>(Optional.empty());
    AtomicReference<Optional<HeaderValue>> header = new AtomicReference<>(Optional.empty());
    AtomicBoolean ran = new AtomicBoolean();
    filter.runWithCredential(request(token), () -> {
      ran.set(true);
      credential.set(store.current());
      header.set(PassThroughStrategy.INSTANCE.resolve(call, store.current()));
    });
    observed.handlerRan = ran.get();
    observed.credential = credential.get();
    observed.header = header.get();
    return observed;
  }

  private static RestRequest request(String token) {
    Map<String, String> headers = Map.of("Authorization", "Bearer " + token);
    return new RestRequest() {
      @Override public String method() { return "GET"; }
      @Override public String path() { return "/api/invoices"; }
      @Override public Map<String, String> headers() { return headers; }
      @Override public Map<String, String> queryParameters() { return Map.of(); }
    };
  }

  private static final class Observed {
    boolean handlerRan;
    Optional<TokenCredential> credential = Optional.empty();
    Optional<HeaderValue> header = Optional.empty();
  }

  /** Hand-written {@link JwtValidator}: accepts the tokens it was told about, rejects the rest. */
  private static final class KnownTokensValidator implements JwtValidator {
    private final Map<String, Object> audiences = new HashMap<>();
    int calls;

    KnownTokensValidator accept(String token, Object audience) {
      audiences.put(token, audience);
      return this;
    }

    @Override
    public Result<ValidatedJwt, JwtValidationError> validate(String compactJwt) {
      calls++;
      Object audience = audiences.get(compactJwt);
      if (audience == null) {
        return Result.failure(new JwtValidationError.MalformedJwt("not a JWS"));
      }
      return Result.success(new ValidatedJwt(
          compactJwt,
          new JoseHeader("RS256", Optional.empty(), Optional.empty()),
          Map.of("iss", "https://op.example.com", "sub", "alice", "aud", audience,
              "exp", Instant.parse("2026-11-11T12:00:00Z").getEpochSecond()),
          Instant.parse("2026-11-11T11:00:00Z")));
    }
  }
}
