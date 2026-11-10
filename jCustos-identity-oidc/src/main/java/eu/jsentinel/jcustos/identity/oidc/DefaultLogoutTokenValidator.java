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
package eu.jsentinel.jcustos.identity.oidc;

/*-
 * #%L
 * jCustos OIDC — Relying-Party identity layer
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.jwt.api.ClockSkewPolicy;
import eu.jsentinel.jcustos.jwt.api.JwtValidationError;
import eu.jsentinel.jcustos.jwt.api.JwtValidator;
import eu.jsentinel.jcustos.jwt.api.ValidatedJwt;
import eu.jsentinel.jcustos.oidc.api.BackChannelLogoutToken;
import eu.jsentinel.jcustos.oidc.api.LogoutTokenValidationError;
import eu.jsentinel.jcustos.oidc.api.LogoutTokenValidator;
import eu.jsentinel.jcustos.replay.api.JtiStore;
import eu.jsentinel.jcustos.replay.impl.InMemoryJtiStore;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Default {@link LogoutTokenValidator} (V00.79). Composition, not inheritance: it wraps
 * a V00.76 {@link JwtValidator} for the signature, then applies the checks of OpenID Connect
 * Back-Channel Logout 1.0 §2.4 itself: issuer and audience, {@code exp} and {@code iat}, the
 * {@code events} back-channel-logout member, {@code sub}/{@code sid} presence,
 * {@code nonce} absence, and (via the {@link JtiStore}) single-use of {@code jti}.
 *
 * <p><strong>JS-SEC-087 (CWE-287):</strong> the validator enforces {@code iss} and {@code aud}
 * <em>itself</em>, against the issuer and client id it is constructed with — exactly as
 * {@link DefaultIdTokenValidator} has done since JS-SEC-007. Up to 00.83.x it relied on the
 * composed {@link JwtValidator} alone. The bootstrap permits a {@code JwtValidator} without issuer
 * and audience expectations; whoever reused such a validator here accepted the logout token of
 * every tenant that shares the signing keys, and terminated sessions on a stranger's request.
 *
 * <p><strong>JS-SEC-087 (CWE-294), replay window:</strong> a {@code jti} is now remembered for as
 * long as its token can be accepted — until {@code exp} plus the leeway, and for at least ten
 * minutes. {@code exp} and {@code iat} are required here, whatever the composed validator
 * demands, and a token whose {@code iat} lies more than ten minutes in the past is rejected.
 * Before, the window was a fixed ten minutes: a captured token with a longer lifetime could be
 * delivered again in the eleventh minute and logged the user out once more.
 *
 * @since 00.79.10
 */
@ExperimentalJCustosApi
public final class DefaultLogoutTokenValidator implements LogoutTokenValidator, HasLogger {

  /** OIDC Back-Channel Logout 1.0 §2.4: the required {@code events} member. */
  public static final String BACKCHANNEL_LOGOUT_EVENT =
      "http://schemas.openid.net/event/backchannel-logout";

  /** Error code of the issuer back-stop (JS-SEC-087). */
  static final String ISS_MISMATCH = "claims/iss-mismatch";
  /** Error code of the audience back-stop (JS-SEC-087). */
  static final String AUD_MISMATCH = "claims/aud-mismatch";
  /** Error code for a logout token without {@code exp} (JS-SEC-087). */
  static final String EXP_MISSING = "claims/exp-missing";
  /** Error code for a logout token without {@code iat} (JS-SEC-087). */
  static final String IAT_MISSING = "claims/iat-missing";
  /** Error code for a logout token issued too long ago (JS-SEC-087). */
  static final String IAT_TOO_OLD = "claims/iat-too-old";

  /** The shortest time a {@code jti} is remembered. */
  private static final Duration JTI_RETENTION = Duration.ofMinutes(10);
  /** The oldest {@code iat} accepted; the specification recommends a lifetime of two minutes. */
  private static final Duration MAX_TOKEN_AGE = Duration.ofMinutes(10);
  /**
   * The leeway on {@code exp} this validator tolerates at most. It is the most lenient preset on
   * purpose: the composed {@link JwtValidator} may be stricter, never more lenient, so the
   * {@code jti} retention below covers the whole time a token can be accepted.
   */
  private static final Duration EXP_LEEWAY = ClockSkewPolicy.LENIENT.leeway();

  private final JwtValidator jwtValidator;
  private final Optional<String> expectedIssuer;
  private final Optional<String> expectedClientId;
  private final JtiStore jtiStore;
  private final Supplier<Instant> clock;

  /**
   * Creates a validator for the logout tokens {@code expectedIssuer} sends to the client
   * {@code expectedClientId}, with an in-memory single-use {@code jti} store — back-channel-logout
   * replay protection is on by default (JS-SEC-021). A single-JVM store suffices for one node; a
   * multi-node RP must pass a shared {@link JtiStore} via
   * {@link #DefaultLogoutTokenValidator(JwtValidator, String, String, JtiStore)}.
   *
   * @param jwtValidator     verifies the signature (and whatever else it is configured for)
   * @param expectedIssuer   the issuer identifier of the OP; the token's {@code iss} must equal it
   * @param expectedClientId the RP's client id; the token's {@code aud} must contain it
   * @since 00.84.00
   */
  public DefaultLogoutTokenValidator(
      JwtValidator jwtValidator, String expectedIssuer, String expectedClientId) {
    this(jwtValidator, expectedIssuer, expectedClientId, new InMemoryJtiStore());
  }

  /**
   * As {@link #DefaultLogoutTokenValidator(JwtValidator, String, String)}, with a caller-supplied
   * (shared) {@link JtiStore}.
   *
   * @since 00.84.00
   */
  public DefaultLogoutTokenValidator(
      JwtValidator jwtValidator, String expectedIssuer, String expectedClientId, JtiStore jtiStore) {
    this(jwtValidator, expectedIssuer, expectedClientId, jtiStore, Instant::now);
  }

  /** Package-visible: inject a clock so the jti-retention window is testable. */
  DefaultLogoutTokenValidator(JwtValidator jwtValidator, String expectedIssuer, String expectedClientId,
      JtiStore jtiStore, Supplier<Instant> clock) {
    this(jwtValidator,
        Optional.of(requireText(expectedIssuer, "expectedIssuer")),
        Optional.of(requireText(expectedClientId, "expectedClientId")),
        jtiStore, clock);
  }

  /**
   * Creates a validator <strong>without</strong> an expected issuer and client id.
   *
   * @deprecated since 00.84.00 (JS-SEC-087, CWE-287): a logout-token validator that does not know
   *     its issuer and its client cannot tell its own logout tokens from those of another tenant.
   *     A validator built this way therefore <strong>rejects every token</strong> with
   *     {@code JwtInvalid(ClaimInvalid("claims/iss-mismatch"))} — it fails closed, and
   *     back-channel logout does not work until the caller moves to
   *     {@link #DefaultLogoutTokenValidator(JwtValidator, String, String)}.
   */
  @Deprecated(since = "00.84.00", forRemoval = true)
  public DefaultLogoutTokenValidator(JwtValidator jwtValidator) {
    this(jwtValidator, Optional.empty(), Optional.empty(), new InMemoryJtiStore(), Instant::now);
    warnNoExpectations();
  }

  /**
   * Creates a validator <strong>without</strong> an expected issuer and client id.
   *
   * @deprecated since 00.84.00 (JS-SEC-087, CWE-287): see
   *     {@link #DefaultLogoutTokenValidator(JwtValidator)} — a validator built this way rejects
   *     every token. Use
   *     {@link #DefaultLogoutTokenValidator(JwtValidator, String, String, JtiStore)}.
   */
  @Deprecated(since = "00.84.00", forRemoval = true)
  public DefaultLogoutTokenValidator(JwtValidator jwtValidator, JtiStore jtiStore) {
    this(jwtValidator, Optional.empty(), Optional.empty(), jtiStore, Instant::now);
    warnNoExpectations();
  }

  private void warnNoExpectations() {
    logger().warn("logout-token/no-expectations-configured: DefaultLogoutTokenValidator was created "
        + "without an expected issuer and client id; it rejects every logout token (JS-SEC-087). "
        + "Use the constructor that takes both.");
  }

  private DefaultLogoutTokenValidator(JwtValidator jwtValidator, Optional<String> expectedIssuer,
      Optional<String> expectedClientId, JtiStore jtiStore, Supplier<Instant> clock) {
    this.jwtValidator = Objects.requireNonNull(jwtValidator, "jwtValidator");
    this.expectedIssuer = expectedIssuer;
    this.expectedClientId = expectedClientId;
    this.jtiStore = Objects.requireNonNull(jtiStore, "jtiStore");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  private static String requireText(String value, String name) {
    Objects.requireNonNull(value, name);
    if (value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
    return value;
  }

  @Override
  public Result<BackChannelLogoutToken, LogoutTokenValidationError> validate(String compactLogoutToken) {
    Objects.requireNonNull(compactLogoutToken, "compactLogoutToken");

    Result<ValidatedJwt, JwtValidationError> jwtResult = jwtValidator.validate(compactLogoutToken);
    Optional<ValidatedJwt> ok = jwtResult.toOptional();
    if (ok.isEmpty()) {
      return Result.failure(new LogoutTokenValidationError.JwtInvalid(jwtResult.fold(v -> null, e -> e)));
    }
    ValidatedJwt jwt = ok.get();

    // JS-SEC-087 (CWE-287): issuer + audience back-stop, independent of the composed
    // JwtValidator's ClaimExpectations (the sibling of JS-SEC-007 in DefaultIdTokenValidator). A
    // validator without expectations (deprecated constructors) matches nothing — it fails closed.
    Optional<String> issuer = jwt.issuer();
    if (expectedIssuer.isEmpty() || issuer.isEmpty() || !issuer.get().equals(expectedIssuer.get())) {
      return invalid(new JwtValidationError.ClaimInvalid(
          ISS_MISMATCH, "logout token issuer does not match the expected issuer"));
    }
    if (expectedClientId.isEmpty()
        || !jwt.audience().orElse(List.of()).contains(expectedClientId.get())) {
      return invalid(new JwtValidationError.ClaimInvalid(
          AUD_MISMATCH, "logout token audience does not contain the expected client id"));
    }

    // JS-SEC-087 (CWE-294): exp and iat are REQUIRED for a logout token (§2.4) — demand them here,
    // whatever the composed validator requires, because the replay window below is built on them.
    Instant now = clock.get();
    Optional<Instant> expiresAt = jwt.expiresAt();
    if (expiresAt.isEmpty()) {
      return invalid(new JwtValidationError.ClaimInvalid(EXP_MISSING, "exp is required for a logout token"));
    }
    Optional<Instant> issuedAt = jwt.issuedAt();
    if (issuedAt.isEmpty()) {
      return invalid(new JwtValidationError.ClaimInvalid(IAT_MISSING, "iat is required for a logout token"));
    }
    Instant acceptedUntil = expiresAt.get().plus(EXP_LEEWAY);
    if (!now.isBefore(acceptedUntil)) {
      return invalid(new JwtValidationError.Expired("logout token is expired"));
    }

    // §2.4 step 7 — a nonce MUST NOT be present (this is what tells a logout token from an ID token).
    if (jwt.claim("nonce", Object.class).isPresent()) {
      return Result.failure(new LogoutTokenValidationError.NonceMustNotBePresent());
    }

    // §2.4 step 6 — the events claim must contain the back-channel-logout member.
    Optional<Map> events = jwt.claim("events", Map.class);
    if (events.isEmpty() || !events.get().containsKey(BACKCHANNEL_LOGOUT_EVENT)) {
      return Result.failure(new LogoutTokenValidationError.MissingBackchannelEvent());
    }

    // §2.4 step 5 — sub and/or sid.
    Optional<String> subject = jwt.claim("sub", String.class);
    Optional<String> sid = jwt.claim("sid", String.class);
    if (subject.isEmpty() && sid.isEmpty()) {
      return Result.failure(new LogoutTokenValidationError.MissingSubjectAndSid());
    }

    // §2.4 step 1 — jti is REQUIRED. Reject its absence rather than silently skipping
    // replay protection (a jti-less token would otherwise be infinitely replayable).
    Optional<String> jti = jwt.jwtId();
    if (jti.isEmpty() || jti.get().isBlank()) {
      return Result.failure(new LogoutTokenValidationError.MissingJwtId());
    }

    // JS-SEC-041 (CWE-294): anchor the replay-retention window on FIRST-SEEN time, not on the
    // token's iat. JS-SEC-087 (CWE-294): and never let it end before the token itself can no
    // longer be accepted — max(first-seen + retention, exp + leeway). The fixed ten minutes let a
    // token with a longer lifetime be delivered again in the eleventh minute.
    Instant firstSeenWindow = now.plus(JTI_RETENTION);
    Instant retainUntil = acceptedUntil.isAfter(firstSeenWindow) ? acceptedUntil : firstSeenWindow;
    if (!jtiStore.record(jti.get(), retainUntil).isSuccess()) {
      return Result.failure(new LogoutTokenValidationError.Replay());
    }

    // JS-SEC-087 (CWE-294): a logout token is short-lived by design; one issued more than ten
    // minutes ago is not acted upon. The check follows the jti record on purpose: a second
    // delivery of a token is reported as what it is (Replay), and recording the jti of a token
    // that is rejected for its age costs nothing — it can only grow older.
    if (issuedAt.get().isBefore(now.minus(MAX_TOKEN_AGE))) {
      return invalid(new JwtValidationError.ClaimInvalid(
          IAT_TOO_OLD, "logout token was issued too long ago"));
    }

    return Result.success(new BackChannelLogoutToken(issuer.get(), subject, sid, jti.get()));
  }

  /**
   * JS-SEC-087: the issuer / audience / exp / iat failures are reported through the existing
   * {@code JwtInvalid} variant, so the sealed {@link LogoutTokenValidationError} does not grow.
   */
  private static Result<BackChannelLogoutToken, LogoutTokenValidationError> invalid(JwtValidationError cause) {
    return Result.failure(new LogoutTokenValidationError.JwtInvalid(cause));
  }
}
