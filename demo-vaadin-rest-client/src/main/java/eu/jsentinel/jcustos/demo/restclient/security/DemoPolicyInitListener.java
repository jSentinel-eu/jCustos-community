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
package eu.jsentinel.jcustos.demo.restclient.security;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.demo.restclient.security.resource.DemoDocumentResolver;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinSecurity;
import eu.jsentinel.jcustos.policy.api.Policy;
import eu.jsentinel.jcustos.policy.api.PolicyDecision;
import eu.jsentinel.jcustos.policy.api.ResourcePredicates;
import eu.jsentinel.jcustos.policy.api.SubjectPredicates;
import eu.jsentinel.jcustos.starter.profile.VaadinJCustosStarter;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.VaadinServiceInitListener;

import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * <strong>V00.73 reference: the simplest possible Vaadin-side bootstrap.</strong>
 * <p>
 * This file is the entire security-init surface of {@code demo-vaadin-rest-client}.
 * Everything else is wired through {@code @JCustosAutoService}:
 * <ul>
 *   <li>{@code RestBackedAuthenticationService}  — {@code @JCustosAutoService(AuthenticationService.class)}</li>
 *   <li>{@code RestBackedAuthorizationService}   — {@code @JCustosAutoService(AuthorizationService.class)}</li>
 *   <li>{@code BackedLoginListener}              — {@code @JCustosAutoService(LoginListener.class)}</li>
 *   <li>{@code ProjectRoleAccessEvaluator}       — {@code @JCustosAutoService(AuthorizationEvaluator.class)}</li>
 * </ul>
 * No hand-written {@code META-INF/services/*} files for those SPIs.
 * <p>
 * The {@link #serviceInit(ServiceInitEvent)} body shows the V00.73 way:
 * one fluent call to {@link VaadinSecurity#bootstrap()}, the
 * {@code VaadinJCustosStarter.developmentDefaults()} profile, and a
 * {@code .policies(...)} lambda that registers the three demo policies
 * and the document resource resolver — all inline through the fluent
 * surface, no direct {@code JCustosServiceResolver} calls.
 */
public final class DemoPolicyInitListener implements VaadinServiceInitListener, HasLogger {

  /** Name of the role-or-permission demo policy. */
  public static final String POLICY_EDITOR_OR_ADMIN = "documents.editor-or-admin";

  /** Name of the resource-based demo policy. */
  public static final String POLICY_DOCUMENT_OWNER_OR_ADMIN = "document.owner-or-admin";

  /**
   * Demo policy that unconditionally returns
   * {@link PolicyDecision.StepUpMethod#MFA StepUpRequired(MFA)} —
   * lets the Vaadin adapter reroute to the registered step-up route
   * without needing a real MFA backend.
   */
  public static final String POLICY_SENSITIVE_REQUIRES_MFA = "sensitive.requires-mfa";

  private static final AtomicBoolean DONE = new AtomicBoolean();

  @Override
  public void serviceInit(ServiceInitEvent event) {
    if (!DONE.compareAndSet(false, true)) {
      return;
    }
    AuthenticationService<?, ?> authn = ServiceLoader.load(AuthenticationService.class)
        .findFirst().orElseThrow(() -> new IllegalStateException(
            "No AuthenticationService registered. "
                + "Expected RestBackedAuthenticationService via @JCustosAutoService."));
    AuthorizationService<?> authz = ServiceLoader.load(AuthorizationService.class)
        .findFirst().orElseThrow(() -> new IllegalStateException(
            "No AuthorizationService registered. "
                + "Expected RestBackedAuthorizationService via @JCustosAutoService."));

    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .use(VaadinJCustosStarter.developmentDefaults())
        .authentication(authn)
        .authorization(authz)
        .loginRoute("login")
        // StepUpChallengeView is registered under this route (JS-SEC-152).
        .stepUpRoute("step-up")
        // JS-SEC-085 (CWE-1188): a route without a security annotation is denied
        // unless it is @PublicRoute (MyLoginView, SetupView, StepUpChallengeView).
        .denyByDefault(true)
        .policies(p -> p
            .resourceResolver(new DemoDocumentResolver())
            .register(Policy.named(POLICY_EDITOR_OR_ADMIN)
                .allowIf(SubjectPredicates.hasAnyRole("ROLE_ADMIN", "ROLE_EDITOR"))
                .orIf(SubjectPredicates.hasPermission("document:write"))
                .deny("must be ADMIN/EDITOR or hold document:write")
                .build())
            .register(Policy.named(POLICY_DOCUMENT_OWNER_OR_ADMIN)
                .allowIf(SubjectPredicates.hasRole("ROLE_ADMIN"))
                .orIf(ResourcePredicates.ownerMatchesSubject(
                    DemoDocumentResolver.RESOURCE_TYPE,
                    DemoDocumentResolver.OWNER_ATTRIBUTE))
                .deny("must be ADMIN or document owner")
                .build())
            .register(Policy.named(POLICY_SENSITIVE_REQUIRES_MFA)
                .stepUpRequiredIf(ctx -> true, PolicyDecision.StepUpMethod.MFA,
                    "MFA challenge required for sensitive operations")
                .build()))
        // V00.74: declarative token propagation. PassThrough is the
        // simplest default — every @PropagateToken-annotated call
        // forwards the cached Bearer to the downstream backend.
        // Token-exchange / client-credentials strategies ship in the
        // optional jCustos-propagation-oidc module.
        //
        // Note: this demo registers the strategy but does not yet use it.
        // Its DemoBackendClient still takes an explicit token parameter on
        // every method, so no @PropagateToken path runs here. The worked
        // example is demo-jcustos-vaadin-rest-client; converting this
        // client's token-threading API is separate work.
        .propagation(p -> p.passThrough())
        .install();

    logger().info("{}", runtime.log());
  }
}
