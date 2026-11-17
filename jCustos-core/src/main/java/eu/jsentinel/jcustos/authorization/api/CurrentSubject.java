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
package eu.jsentinel.jcustos.authorization.api;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * The one place that answers "who is the current subject, and what is its id"
 * (JS-SEC-097, CWE-1041).
 * <p>
 * Until 00.84.00 the sequence subject type, {@link SubjectStore}, current subject, roles and
 * id was written out six times in the Vaadin stack, with four different id derivations - the
 * {@link SubjectIdResolver}, an identity handle, an empty string and
 * {@code String.valueOf(subject)} - and with error handling that differed from copy to copy.
 * The last of them handed a subject's {@code toString()} - commonly an e-mail address, a
 * password hash or an internal key - to every policy as the subject id. Every adapter now
 * goes through this facade.
 *
 * <h2>The subject id rule</h2>
 * {@link #subjectIdOf(Object)} returns the value of the registered {@link SubjectIdResolver}.
 * Without one - or when it fails or yields a blank value - it returns the identity handle
 * {@code SimpleClassName@identityHash}: never empty, stable for the lifetime of the subject
 * object (within a session, as a rule), not correlatable across sessions, and free of
 * anything the subject's {@code toString()} would reveal. Applications that need correlated
 * audit trails register a resolver; the DX bootstrap of the Vaadin adapter reports a missing
 * one as {@code audit/no-subject-id-resolver}.
 *
 * <h2>Failures</h2>
 * The lookups never throw. A missing {@code AuthenticationService}, {@link SubjectStore} or
 * {@link AuthorizationService} and every runtime error on the way read as "no subject":
 * an authorisation decision without a subject denies. A check that <em>ends</em> a session
 * cannot use that reading - for it, "no subject" means "nothing to end" - and calls
 * {@link #currentPropagatingFailures()} instead.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class CurrentSubject {

  /** Separator between the class name and the identity hash of the identity handle. */
  private static final String IDENTITY_HANDLE_SEPARATOR = "@";

  private CurrentSubject() {
    throw new AssertionError("no instances");
  }

  /**
   * The subject type the registered {@code AuthenticationService} reports.
   *
   * @return the subject type; empty when no authentication service is registered, it
   *     reports no type or the lookup fails
   */
  public static Optional<Class<?>> subjectType() {
    try {
      return JCustosServiceResolver.<Object, Object>findAuthenticationService()
          .map(CurrentSubject::subjectTypeOf);
    } catch (RuntimeException lookupFailure) {
      HasLogger.staticLogger().debug("CurrentSubject: the subject type could not be resolved ({})",
          lookupFailure.getClass().getName());
      return Optional.empty();
    }
  }

  /**
   * The subject bound in the registered {@link SubjectStore} under {@link #subjectType()}.
   *
   * @return the subject; empty when none is bound, a prerequisite is missing or the lookup
   *     fails
   */
  public static Optional<Object> current() {
    try {
      return currentPropagatingFailures();
    } catch (RuntimeException lookupFailure) {
      HasLogger.staticLogger().debug("CurrentSubject: the current subject could not be read ({})",
          lookupFailure.getClass().getName());
      return Optional.empty();
    }
  }

  /**
   * As {@link #current()}, but a {@link SubjectStore} that cannot be resolved or read is
   * thrown instead of being reported as "no subject". Meant for a check that ends a session
   * on idle timeout, lifetime or revocation: there "no subject" means "nothing to end", so a
   * store failure must stop the request rather than let it pass (exit review XR05,
   * CWE-636). A missing {@code AuthenticationService} or {@code SubjectStore} still yields
   * empty.
   *
   * @return the subject; empty when none is bound or a prerequisite is missing
   * @throws RuntimeException what the subject store lookup or the store itself throws
   */
  public static Optional<Object> currentPropagatingFailures() {
    Optional<Class<?>> type = subjectType();
    if (type.isEmpty()) {
      return Optional.empty();
    }
    Optional<SubjectStore> store = SubjectStores.findSubjectStore();
    if (store.isEmpty()) {
      return Optional.empty();
    }
    return store.get().currentSubject(asObjectType(type.get()));
  }

  /**
   * The subject id of {@code subject}: the value of the registered {@link SubjectIdResolver};
   * without a resolver - or when it fails or yields a blank value - the identity handle
   * {@code SimpleClassName@identityHash}. Never {@code subject.toString()} and never empty.
   *
   * @param subject the typed subject; non-null
   * @return the subject id, never {@code null} or blank
   */
  public static String subjectIdOf(Object subject) {
    requireNonNull(subject, "subject must not be null");
    try {
      Optional<SubjectIdResolver<Object>> resolver = JCustosServiceResolver.findSubjectIdResolver();
      if (resolver.isPresent()) {
        SubjectId resolved = resolver.get().resolve(subject);
        if (resolved != null && resolved.value() != null && !resolved.value().isBlank()) {
          return resolved.value();
        }
      }
    } catch (RuntimeException resolverFailure) {
      // the class only - the message of a failing resolver may carry what it was asked about.
      // No warn-once flag: a JVM-wide flag would be state outside JCustosServiceResolver.resetAll().
      HasLogger.staticLogger().warn("The SubjectIdResolver failed ({}); the identity handle stands "
          + "in for the subject id.", resolverFailure.getClass().getName());
    }
    return identityHandleOf(subject);
  }

  /**
   * The current subject reduced to what an access decision needs: the id of
   * {@link #subjectIdOf(Object)} - also as the display name, never {@code toString()} - and
   * the roles and permissions the registered {@link AuthorizationService} reports.
   *
   * @return the snapshot; empty when no subject is bound, a prerequisite is missing or a
   *     lookup fails
   */
  public static Optional<JCustosSubject> currentJCustosSubject() {
    Optional<Object> subject = current();
    if (subject.isEmpty()) {
      return Optional.empty();
    }
    try {
      Optional<AuthorizationService<Object>> authorization =
          JCustosServiceResolver.findAuthorizationService();
      if (authorization.isEmpty()) {
        return Optional.empty();
      }
      Set<RoleName> roles = Set.copyOf(authorization.get().rolesFor(subject.get()).roleNames());
      Set<PermissionName> permissions =
          Set.copyOf(authorization.get().permissionsFor(subject.get()).permissionNames());
      String subjectId = subjectIdOf(subject.get());
      return Optional.of(new JCustosSubject(subjectId, subjectId, roles, permissions));
    } catch (RuntimeException lookupFailure) {
      HasLogger.staticLogger().debug("CurrentSubject: roles or permissions could not be resolved ({})",
          lookupFailure.getClass().getName());
      return Optional.empty();
    }
  }

  /**
   * Removes the current subject from the registered {@link SubjectStore}. Best effort: a
   * missing prerequisite leaves nothing to remove, and a failure is logged with its class
   * only. Never throws.
   */
  public static void clear() {
    try {
      Optional<Class<?>> type = subjectType();
      Optional<SubjectStore> store = SubjectStores.findSubjectStore();
      if (type.isPresent() && store.isPresent()) {
        store.get().deleteCurrentSubject(asObjectType(type.get()));
      }
    } catch (RuntimeException removalFailure) {
      HasLogger.staticLogger().warn("The current subject could not be removed from the subject "
          + "store ({})", removalFailure.getClass().getName());
    }
  }

  private static Class<?> subjectTypeOf(AuthenticationService<?, ?> authentication) {
    return authentication.subjectType();
  }

  private static String identityHandleOf(Object subject) {
    return subject.getClass().getSimpleName() + IDENTITY_HANDLE_SEPARATOR
        + Integer.toHexString(System.identityHashCode(subject));
  }

  @SuppressWarnings("unchecked")
  private static Class<Object> asObjectType(Class<?> type) {
    return (Class<Object>) type;
  }
}
