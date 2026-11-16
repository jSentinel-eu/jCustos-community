/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
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
package eu.jsentinel.jcustos.credential.change;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.authentication.StoreBackedRememberMeService;
import eu.jsentinel.jcustos.authentication.TokenService;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.JCustosVersionStore;

import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import java.util.function.IntSupplier;

/**
 * Shipped {@link CredentialChangeListener}: after a password change or reset
 * it invalidates what was issued under the old password (JS-SEC-128, CWE-613).
 *
 * <ul>
 *   <li>It raises the subject's
 *       {@link eu.jsentinel.jcustos.session.JCustosVersion} in the supplied
 *       {@link JCustosVersionStore}, so that every session which captured the
 *       older version at login is refused by the version check.</li>
 *   <li>It calls {@link StoreBackedRememberMeService#revokeAll} when a
 *       remember-me service is supplied.</li>
 *   <li>It calls {@link TokenService#revokeAll} when a token service is
 *       supplied.</li>
 * </ul>
 *
 * <p>Every part is optional; a listener built with none of them does nothing.
 * The three steps are independent: a failure of one is logged and the others
 * still run, because a half-revoked subject is better than an untouched one.
 * The current session of the user is hit by the version bump as well — an
 * adapter that wants to keep it signs the user in again after the change.</p>
 *
 * <p>The credential services identify the account by username. The listener
 * maps it to a {@link SubjectId} with {@link SubjectId#of(String)} unless
 * another mapping is configured with {@link Builder#subjectResolver}. The
 * mapping has to name the subject id the sessions and tokens were issued for:
 * an application that issues them for a user id, or for another spelling of
 * the name, configures the resolver, otherwise the version bump and the
 * revocations hit a subject nobody uses. That mistake is not silent: when the
 * remember-me and refresh-token steps that are configured all revoke nothing,
 * the listener logs {@code credential/change-revoked-nothing} - as a WARN with
 * the default mapping, at INFO with a configured one, where an account without
 * tokens is the likely reason.</p>
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class RevokingCredentialChangeListener
    implements CredentialChangeListener, HasLogger {

  private final JCustosVersionStore versionStore;
  private final StoreBackedRememberMeService rememberMeService;
  private final TokenService tokenService;
  private final TenantId tenant;
  private final Function<String, SubjectId> subjectResolver;
  /** {@code true} while the default {@link SubjectId#of(String)} mapping is in use. */
  private final boolean defaultSubjectResolver;
  /** Changes after which every configured token step revoked nothing - for tests. */
  private final AtomicLong emptyRevocations = new AtomicLong();

  private RevokingCredentialChangeListener(Builder builder) {
    this.versionStore = builder.versionStore;
    this.rememberMeService = builder.rememberMeService;
    this.tokenService = builder.tokenService;
    this.tenant = builder.tenant;
    this.subjectResolver = builder.subjectResolver;
    this.defaultSubjectResolver = builder.defaultSubjectResolver;
  }

  /**
   * @return a builder with no collaborator set, tenant
   *     {@link TenantId#DEFAULT} and {@link SubjectId#of(String)} as mapping
   */
  public static Builder builder() {
    return new Builder();
  }

  @Override
  public void credentialChanged(String username, Cause cause, Instant at) {
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(cause, "cause");
    SubjectId subject = Objects.requireNonNull(
        subjectResolver.apply(username), "subjectResolver returned null");
    if (versionStore != null) {
      attempt("security-version", username,
          () -> versionStore.increment(new JCustosVersionKey(tenant, subject)));
    }
    int tokenSteps = 0;
    int revoked = 0;
    boolean tokenStepFailed = false;
    if (rememberMeService != null) {
      tokenSteps++;
      int count = count("remember-me", username, () -> rememberMeService.revokeAll(subject));
      tokenStepFailed |= count < 0;
      revoked += Math.max(count, 0);
    }
    if (tokenService != null) {
      tokenSteps++;
      int count = count("refresh-token", username, () -> tokenService.revokeAll(subject));
      tokenStepFailed |= count < 0;
      revoked += Math.max(count, 0);
    }
    if (tokenSteps > 0 && !tokenStepFailed && revoked == 0) {
      reportEmptyRevocation(username, subject);
    }
  }

  /**
   * JS-SEC-128 (CWE-613): every configured token step revoked nothing. Either the
   * account held no remember-me or refresh token, or the tokens were issued for
   * another subject id than the one the listener derived from the user name - in
   * which case they all survived the password change.
   */
  private void reportEmptyRevocation(String username, SubjectId subject) {
    emptyRevocations.incrementAndGet();
    String message = "credential/change-revoked-nothing: after the password change of user '{}'"
        + " no remember-me or refresh token of subject '{}' was found. If the tokens are issued"
        + " for another subject id than this, they survived the change - configure"
        + " RevokingCredentialChangeListener.Builder.subjectResolver(...).";
    String user = LogFieldScrubber.scrub(username);
    String id = LogFieldScrubber.scrub(subject.value());
    if (defaultSubjectResolver) {
      logger().warn(message, user, id);
    } else {
      logger().info(message, user, id);
    }
  }

  /** Package-visible for tests: changes after which every token step revoked nothing. */
  long emptyRevocationCount() {
    return emptyRevocations.get();
  }

  /** @return what {@code action} revoked, or {@code -1} when it failed */
  private int count(String step, String username, IntSupplier action) {
    int[] revoked = {-1};
    attempt(step, username, () -> revoked[0] = action.getAsInt());
    return revoked[0];
  }

  private void attempt(String step, String username, Runnable action) {
    try {
      action.run();
    } catch (RuntimeException failure) {
      // JS-SEC-128: the password is already replaced. Report the artefact class
      // that survived instead of hiding it behind the first failure.
      logger().warn("credential/change-revocation-failed: step {} failed for user '{}': {}",
          step, LogFieldScrubber.scrub(username), failure.toString());
    }
  }

  /** Builder for {@link RevokingCredentialChangeListener}. */
  public static final class Builder {

    private JCustosVersionStore versionStore;
    private StoreBackedRememberMeService rememberMeService;
    private TokenService tokenService;
    private TenantId tenant = TenantId.DEFAULT;
    private Function<String, SubjectId> subjectResolver = SubjectId::of;
    private boolean defaultSubjectResolver = true;

    private Builder() {
    }

    /**
     * @param versionStore store whose version of the subject is raised; non-null
     * @return this builder
     */
    public Builder versionStore(JCustosVersionStore versionStore) {
      this.versionStore = Objects.requireNonNull(versionStore, "versionStore");
      return this;
    }

    /**
     * @param rememberMeService service whose tokens of the subject are revoked; non-null
     * @return this builder
     */
    public Builder rememberMe(StoreBackedRememberMeService rememberMeService) {
      this.rememberMeService = Objects.requireNonNull(rememberMeService, "rememberMeService");
      return this;
    }

    /**
     * @param tokenService service whose refresh tokens of the subject are revoked; non-null
     * @return this builder
     */
    public Builder refreshTokens(TokenService tokenService) {
      this.tokenService = Objects.requireNonNull(tokenService, "tokenService");
      return this;
    }

    /**
     * @param tenant tenant of the security version; {@code null} becomes
     *               {@link TenantId#DEFAULT}. The remember-me and token services
     *               carry their own tenant.
     * @return this builder
     */
    public Builder tenant(TenantId tenant) {
      this.tenant = tenant == null ? TenantId.DEFAULT : tenant;
      return this;
    }

    /**
     * @param subjectResolver maps the credential's username - the name the
     *                        credential store registered - to the subject id
     *                        the sessions and tokens were issued for; non-null.
     *                        The default is {@link SubjectId#of(String)}, which
     *                        is right only when the tokens carry exactly that
     *                        name.
     * @return this builder
     */
    public Builder subjectResolver(Function<String, SubjectId> subjectResolver) {
      this.subjectResolver = Objects.requireNonNull(subjectResolver, "subjectResolver");
      this.defaultSubjectResolver = false;
      return this;
    }

    /** @return the listener */
    public RevokingCredentialChangeListener build() {
      return new RevokingCredentialChangeListener(this);
    }
  }
}
