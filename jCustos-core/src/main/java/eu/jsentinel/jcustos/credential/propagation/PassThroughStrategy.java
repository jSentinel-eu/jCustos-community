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
package eu.jsentinel.jcustos.credential.propagation;

import com.svenruppert.dependencies.core.logger.HasLogger;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default {@link OutboundTokenStrategy} — forwards a bearer-style
 * inbound token as {@code Authorization: Bearer <value>}.
 *
 * <p>Discipline:
 * <ul>
 *   <li>{@link RefreshToken} is <strong>never</strong> forwarded
 *       (Class-A secret, would leak via the outbound call).</li>
 *   <li>{@link ApiKey} is <strong>not</strong> prefixed with
 *       {@code Bearer }. Consumers register their own
 *       {@code ApiKeyHeaderStrategy} when they want one.</li>
 *   <li><strong>JS-SEC-151 (CWE-441):</strong> when the call declares an audience
 *       ({@code @PropagateToken(audience = "billing")}), the inbound token is forwarded only if
 *       its <em>known</em> audience contains that value. A token issued for another audience —
 *       or one whose audience is unknown — is <strong>not</strong> forwarded: the strategy
 *       returns empty and logs {@code propagation/audience-mismatch}. Up to 00.83.x the declared
 *       audience had no effect on this strategy, so the user's token left the service unchanged
 *       and the downstream service could replay it against the API it was issued for. Use the
 *       {@code exchange} strategy when the downstream service needs a token of its own.</li>
 *   <li>A call <em>without</em> a declared audience is forwarded as before (the compatible
 *       behaviour), and reported once per call site as
 *       {@code propagation/pass-through-without-audience}.</li>
 * </ul>
 *
 * <p>Singleton — share {@link #INSTANCE} across threads. The only state is the bounded set of
 * call sites already reported, so that a finding is logged at WARN once and not on every call.
 *
 * @since 00.74.00
 */
public final class PassThroughStrategy implements OutboundTokenStrategy, HasLogger {

  /** Stable lookup key under which the strategy registers. */
  public static final String NAME = "pass-through";

  /** Singleton instance — share across threads. */
  public static final PassThroughStrategy INSTANCE = new PassThroughStrategy();

  /** Log code: the declared audience is not among the token's known audiences (JS-SEC-151). */
  static final String AUDIENCE_MISMATCH = "propagation/audience-mismatch";

  /** Log code: a token is forwarded unchanged because the call declares no audience (JS-SEC-151). */
  static final String PASS_THROUGH_WITHOUT_AUDIENCE = "propagation/pass-through-without-audience";

  /** Upper bound on remembered call sites; they come from code, the bound is a back-stop. */
  private static final int MAX_REPORTED_CALL_SITES = 1024;

  private final Set<String> reportedCallSites = ConcurrentHashMap.newKeySet();

  private PassThroughStrategy() {
  }

  @Override
  public String name() {
    return NAME;
  }

  @Override
  public Optional<HeaderValue> resolve(OutboundCall call,
                                       Optional<TokenCredential> inbound) {
    // JS-SEC-044 (CWE-522): only forward access-token-shaped credentials; a RefreshToken / ApiKey
    // (Class-A secrets) must never leave as a bearer header. Defer to the single shared decision on
    // TokenCredential so this strategy cannot drift from TokenExchangeStrategy.
    if (inbound.isEmpty() || !inbound.get().isForwardableAsSubjectToken()) {
      return Optional.empty();
    }
    // JS-SEC-151 (CWE-441): a declared audience is a promise about where the token may go. Forward
    // only when the token is known to be issued for it; an unknown audience fails closed.
    String declared = call.declaredAudience();
    if (declared.isBlank()) {
      if (firstReport(PASS_THROUGH_WITHOUT_AUDIENCE, call, declared)) {
        logger().warn("{}: service={} method={} forwards the inbound token unchanged; declare "
                + "@PropagateToken(audience = ...) or use the exchange strategy",
            PASS_THROUGH_WITHOUT_AUDIENCE, call.targetServiceName(), call.methodName());
      }
    } else if (!knownAudiences(inbound.get()).contains(declared)) {
      if (firstReport(AUDIENCE_MISMATCH, call, declared)) {
        logger().warn("{}: service={} method={} declares audience={} but the inbound token is "
                + "not known to be issued for it; no token is forwarded",
            AUDIENCE_MISMATCH, call.targetServiceName(), call.methodName(), declared);
      } else {
        logger().debug("{}: service={} method={}", AUDIENCE_MISMATCH,
            call.targetServiceName(), call.methodName());
      }
      return Optional.empty();
    }
    return Optional.of(new HeaderValue("Authorization", "Bearer " + inbound.get().value()));
  }

  /**
   * The audiences the token is known to be issued for: the validated {@code aud} claim when the
   * token carries its validation result, otherwise the declared {@link TokenCredential#audience()}
   * (a comma-separated list, as {@link OidcAccessToken#fromValidated} writes it).
   */
  private static List<String> knownAudiences(TokenCredential token) {
    if (token instanceof OidcAccessToken oidc && oidc.validated().isPresent()) {
      return oidc.validated().get().audience().orElse(List.of());
    }
    return token.audience()
        .map(value -> Arrays.stream(value.split(","))
            .map(String::trim)
            .filter(part -> !part.isEmpty())
            .toList())
        .orElse(List.of());
  }

  private boolean firstReport(String code, OutboundCall call, String declared) {
    if (reportedCallSites.size() >= MAX_REPORTED_CALL_SITES) {
      return false;
    }
    return reportedCallSites.add(
        code + '|' + call.targetServiceName() + '#' + call.methodName() + '|' + declared);
  }
}
