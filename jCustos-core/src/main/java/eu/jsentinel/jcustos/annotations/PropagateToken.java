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
package eu.jsentinel.jcustos.annotations;

import eu.jsentinel.jcustos.authorization.annotations.JCustosAnnotation;
import eu.jsentinel.jcustos.credential.propagation.PropagateTokenAdvisor;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marker for client interfaces / methods whose outbound HTTP call must
 * carry a {@link PropagateTokenAdvisor}-resolved header (typically the
 * Bearer token of the current subject, optionally exchanged via
 * {@code TokenExchangeStrategy}).
 *
 * <p>Meta-annotated with
 * {@link JCustosAnnotation @JCustosAnnotation(PropagateTokenAdvisor.class)}
 * so the V00.70 {@code JCustosAnnotationScanner} discovers it
 * through the same cache as {@code @RequiresRole} /
 * {@code @RequiresPermission}.
 *
 * <p>Resolution at runtime (V00.74 Prompts 008 + 011 + 013):
 * <ul>
 *   <li>Method-level annotation overrides class-level. Identical to
 *       the {@code @RequiresRole} resolution rule.</li>
 *   <li>{@link #strategy()} is the lookup key against the named
 *       strategies registered in the bootstrap
 *       {@code .propagation(p -> p.strategy(name, ...))}.</li>
 *   <li>{@link #audience()} flows into {@code OutboundCall} so strategy
 *       implementations (in particular {@code TokenExchangeStrategy})
 *       know which downstream audience to mint a token for. The default
 *       {@code "pass-through"} strategy honours it as well (JS-SEC-151,
 *       CWE-441): it forwards the inbound token only when that token is
 *       known to be issued for the declared audience, and forwards
 *       nothing otherwise.</li>
 *   <li>{@link #header()} overrides the strategy's default header name
 *       (e.g. {@code "X-Service-Token"} for a custom flow).</li>
 *   <li>{@link #service()} is a logical service name used in
 *       diagnostics / audit metadata.</li>
 * </ul>
 *
 * @since 00.74.00
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
@JCustosAnnotation(PropagateTokenAdvisor.class)
public @interface PropagateToken {

  /**
   * Lookup key against the named strategies. Default {@code "pass-through"}.
   *
   * <p>{@code "pass-through"} hands the downstream service the very token the caller presented.
   * That service can then act as the user wherever the token is accepted, so pass-through fits
   * only a downstream service that belongs to the token's audience. For every other service use
   * {@code "exchange"} (RFC 8693), which obtains a token issued for that service alone.
   */
  String strategy() default "pass-through";

  /**
   * Declared audience for the downstream call. Default empty.
   *
   * <p>With {@code "exchange"} it names the audience the new token is requested for. With
   * {@code "pass-through"} it is a guard (JS-SEC-151, CWE-441): the inbound token is forwarded
   * only if its known audience contains this value; a token for another audience, or one whose
   * audience is unknown, is not forwarded and the call goes out without the header. Leaving it
   * empty keeps the unguarded pass-through and is reported as
   * {@code propagation/pass-through-without-audience}.
   */
  String audience() default "";

  /** Override of the strategy's default header name. Default empty (use strategy default). */
  String header() default "";

  /** Logical service name for diagnostics / audit metadata. Default empty. */
  String service() default "";
}
