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

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.credential.propagation.BearerToken;
import eu.jsentinel.jcustos.credential.propagation.OidcAccessToken;
import eu.jsentinel.jcustos.credential.propagation.TokenCredential;
import eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore;
import eu.jsentinel.jcustos.jwt.api.JwtValidationError;
import eu.jsentinel.jcustos.jwt.api.JwtValidator;
import eu.jsentinel.jcustos.jwt.api.ValidatedJwt;
import eu.jsentinel.jcustos.rest.BearerTokenExtractor;
import eu.jsentinel.jcustos.rest.RestRequest;

import java.util.Objects;
import java.util.Optional;

/**
 * Request-scope filter that binds the inbound Bearer token into a
 * {@link TokenCredentialStore} and clears it in the {@code finally}
 * block. Wire <strong>after</strong>
 * {@code RestJCustosVersionFilter} but <strong>before</strong> the
 * authorization filter / handler so the credential is available to the
 * handler and downstream propagating wrappers.
 *
 * <p>Pattern parallel to {@code RestJCustosVersionFilter}.
 *
 * <p><strong>What is bound (JS-SEC-151, CWE-441).</strong> Since 00.84.00
 * {@code PassThroughStrategy} forwards a token for a declared audience
 * ({@code @PropagateToken(audience = ...)}) only when the token is
 * <em>known</em> to be issued for that audience. A bare
 * {@link BearerToken} knows nothing about its audience, so behind a filter
 * that binds nothing else such a call forwards nothing. The filter therefore
 * binds the most informed credential it can get, in this order:
 * <ol>
 *   <li>A credential that is already bound for the very token of the
 *       request - typically an
 *       {@link OidcAccessToken#fromValidated(String, ValidatedJwt)} the
 *       subject resolver bound when it validated the token - is kept. It is
 *       not replaced by a credential that knows less.</li>
 *   <li>With a {@link JwtValidator} - the one passed to
 *       {@link #RestTokenCredentialFilter(TokenCredentialStore, JwtValidator)},
 *       otherwise the one a {@code .jwt(...)} bootstrap installed
 *       ({@link JCustosServiceResolver#findJwtValidator()}, looked up per
 *       request) - a token the validator accepts is bound as
 *       {@code OidcAccessToken.fromValidated(...)}: expiry, issuer hash and
 *       the validated {@code aud} claim are known.</li>
 *   <li>Otherwise - no validator, or the validator does not accept the
 *       token - the token is bound as a {@link BearerToken} of unknown
 *       audience, as before 00.84.00. Pass-through forwards such a token
 *       only for calls that declare no audience.</li>
 * </ol>
 * The filter never states an audience the validator did not confirm, and it
 * does not authenticate: whether the request is served at all remains the
 * decision of the authentication and authorisation filters.
 *
 * @since 00.74.00
 */
@ExperimentalJCustosApi
public final class RestTokenCredentialFilter implements HasLogger {

  private final BearerTokenExtractor extractor = new BearerTokenExtractor();
  private final TokenCredentialStore store;
  /** Explicit validator, or {@code null} to look the installed one up per request. */
  private final JwtValidator validator;

  /**
   * Creates a filter that validates through the {@link JwtValidator} a
   * bootstrap installed, if there is one, and binds a {@link BearerToken} of
   * unknown audience otherwise.
   *
   * @param store the credential store to bind into; non-null
   */
  public RestTokenCredentialFilter(TokenCredentialStore store) {
    this.store = Objects.requireNonNull(store, "store");
    this.validator = null;
  }

  /**
   * Creates a filter that validates inbound tokens through
   * {@code validator}, so that a valid token is bound with its audience
   * (JS-SEC-151).
   *
   * @param store     the credential store to bind into; non-null
   * @param validator the validator for inbound bearer tokens; non-null
   * @since 00.84.00
   */
  public RestTokenCredentialFilter(TokenCredentialStore store, JwtValidator validator) {
    this.store = Objects.requireNonNull(store, "store");
    this.validator = Objects.requireNonNull(validator, "validator");
  }

  /**
   * Binds the Bearer token (if any) and runs the supplied handler. The
   * slot is cleared regardless of how the handler returns — normal or
   * exceptional.
   *
   * @param request the incoming request
   * @param handler the downstream work to run
   */
  public void runWithCredential(RestRequest request, Runnable handler) {
    Objects.requireNonNull(request, "request");
    Objects.requireNonNull(handler, "handler");
    Optional<String> bearer = extractor.extract(request);
    bearer.ifPresent(this::bind);
    try {
      handler.run();
    } finally {
      store.clear();
    }
  }

  private void bind(String value) {
    // JS-SEC-151: a credential already bound for this very token knows at least as much as
    // anything derived here - keep it instead of downgrading it to an unknown audience.
    Optional<TokenCredential> bound = store.current();
    if (bound.isPresent()
        && bound.get().isForwardableAsSubjectToken()
        && bound.get().value().equals(value)) {
      return;
    }
    store.bind(validated(value)
        .<TokenCredential>map(jwt -> OidcAccessToken.fromValidated(value, jwt))
        .orElseGet(() -> new BearerToken(value)));
  }

  /**
   * @return the validation result when a validator is available and accepts the token;
   *         empty in every other case - the audience then stays unknown
   */
  private Optional<ValidatedJwt> validated(String value) {
    JwtValidator effective = validator != null
        ? validator
        : JCustosServiceResolver.findJwtValidator().orElse(null);
    if (effective == null) {
      return Optional.empty();
    }
    try {
      Result<ValidatedJwt, JwtValidationError> result = effective.validate(value);
      if (result == null) {
        return Optional.empty();
      }
      Optional<ValidatedJwt> jwt = result.toOptional();
      if (jwt.isEmpty()) {
        // Opaque tokens and rejected JWTs end here on every request: debug, and never the token.
        logger().debug("propagation/inbound-token-not-validated: the bearer token is bound "
            + "with an unknown audience");
      }
      return jwt;
    } catch (RuntimeException validatorFailure) {
      // The exception text may quote the token: log the type only.
      logger().warn("propagation/inbound-validator-failed: {}; the bearer token is bound with "
          + "an unknown audience", validatorFailure.getClass().getName());
      return Optional.empty();
    }
  }
}
