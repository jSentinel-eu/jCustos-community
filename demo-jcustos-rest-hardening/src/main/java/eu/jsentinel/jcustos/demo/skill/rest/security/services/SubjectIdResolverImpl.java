package eu.jsentinel.jcustos.demo.skill.rest.security.services;

import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.User;

/**
 * Maps the application's typed {@link User} to the framework's
 * {@link SubjectId} key. Required for Phase-4c drift detection: the
 * login ({@code AuthHandler.login}) derives a stable {@code SubjectId} from
 * the just-authenticated user to capture a
 * {@code JCustosVersion} snapshot, and the
 * {@code VersionBumper} needs the same mapping to increment that
 * key on role changes.
 *
 * <p>SPI-registered via
 * {@code META-INF/services/eu.jsentinel.jcustos.authorization.api.SubjectIdResolver}.
 */
public final class SubjectIdResolverImpl implements SubjectIdResolver<User> {

  @Override
  public SubjectId resolve(User subject) {
    return SubjectId.of(String.valueOf(subject.id()));
  }

  @Override
  public TenantId tenantFor(User subject) {
    return TenantId.DEFAULT;
  }
}
