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
package eu.jsentinel.jcustos.demo.rest.server;

import eu.jsentinel.jcustos.authentication.ApiKeyAuthenticationService;
import eu.jsentinel.jcustos.authentication.ApiKeyRecord;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.demo.rest.domain.DemoRolePermissionMapping;
import eu.jsentinel.jcustos.demo.rest.domain.DemoUser;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.rest.BearerTokenExtractor;
import eu.jsentinel.jcustos.rest.RestHeaders;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestJCustosVersionContext;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionMetadata;

import java.util.Optional;
import java.util.Set;

/**
 * Demo {@link RestSubjectResolver} that resolves a {@code Bearer} token from
 * the {@code Authorization} header (parsed via {@link BearerTokenExtractor})
 * and looks it up in {@link DemoTokenStore}.
 * <p>
 * Also implements {@link #resolveSessionMetadata(RestRequest)}: builds a
 * {@link SessionMetadata} from the token's {@link DemoTokenStore.Metadata}
 * and reports the {@code lastActivityAt} as it stood <em>before</em> the
 * current request, so the {@code SessionPolicy.evaluate(...)} idle check
 * sees the actual idle gap. After exposing the metadata the resolver
 * bumps {@code lastActivityAt} to "now" so the next request observes the
 * updated value.
 * <p>
 * JS-SEC-131 (CWE-613) and JS-SEC-117 (CWE-522): {@link #resolveSessionId(RestRequest)}
 * names the session of a bearer token by its {@linkplain DemoTokenStore#sessionReference
 * session reference} - the key {@link DemoTokenStore} records the session under - so the
 * REST filters refuse a token whose record was revoked. The version context carries the
 * same reference, never the token.
 */
public final class DemoSubjectResolver implements RestSubjectResolver {

  /** Header carrying the long-lived API key (plain value). */
  public static final String API_KEY_HEADER = "X-Api-Key";

  private static final BearerTokenExtractor BEARER = new BearerTokenExtractor();

  private final DemoTokenStore tokens;
  private final DemoRolePermissionMapping mapping;
  private final ApiKeyAuthenticationService apiKeyAuth;

  public DemoSubjectResolver(DemoTokenStore tokens, DemoRolePermissionMapping mapping) {
    this(tokens, mapping, null);
  }

  public DemoSubjectResolver(DemoTokenStore tokens,
                             DemoRolePermissionMapping mapping,
                             ApiKeyAuthenticationService apiKeyAuth) {
    this.tokens = tokens;
    this.mapping = mapping;
    this.apiKeyAuth = apiKeyAuth;
  }

  @Override
  public Optional<JCustosSubject> resolveSubject(RestRequest request) {
    // V00.70 Phase-7b API-key path takes precedence — a request that
    // ships an X-Api-Key uses the scopes recorded on the key as its
    // entire authorization surface (no role inheritance from any
    // session token).
    Optional<JCustosSubject> apiKeySubject = resolveApiKeySubject(request);
    if (apiKeySubject.isPresent()) {
      return apiKeySubject;
    }
    return extractToken(request).flatMap(tokens::resolve).map(this::toSubject);
  }

  private Optional<JCustosSubject> resolveApiKeySubject(RestRequest request) {
    if (apiKeyAuth == null) {
      return Optional.empty();
    }
    Optional<String> headerValue = RestHeaders.first(request, API_KEY_HEADER);
    return headerValue
        .flatMap(s -> apiKeyAuth.authenticate(s)
        .map(DemoSubjectResolver::toApiKeySubject));
  }

  private static JCustosSubject toApiKeySubject(ApiKeyRecord record) {
    return new JCustosSubject(
        record.subjectId().value(),
        record.name(),
        Set.of(),
        Set.copyOf(record.scopes()));
  }

  @Override
  public Optional<RestJCustosVersionContext> resolveJCustosVersionContext(RestRequest request) {
    Optional<String> token = extractToken(request);
    return token
        .flatMap(s -> tokens.resolveMetadata(s)
        .map(metadata -> new RestJCustosVersionContext(
            SubjectId.of(metadata.user().username()),
            TenantId.DEFAULT,
            metadata.snapshot(),
            DemoTokenStore.sessionReference(s))));
  }

  @Override
  public Optional<SessionId> resolveSessionId(RestRequest request) {
    return extractToken(request)
        .map(token -> SessionId.of(DemoTokenStore.sessionReference(token)));
  }

  @Override
  public Optional<SessionMetadata> resolveSessionMetadata(RestRequest request) {
    Optional<String> token = extractToken(request);
    if (token.isEmpty()) {
      return Optional.empty();
    }
    Optional<DemoTokenStore.Metadata> metadata = tokens.resolveMetadata(token.get());
    if (metadata.isEmpty()) {
      return Optional.empty();
    }
    DemoTokenStore.Metadata m = metadata.get();
    SessionMetadata snapshot = new SessionMetadata(
        m.user().username(), m.createdAt(), m.lastActivityAt());
    // Bump lastActivity so the *next* request observes the updated value.
    // Using the snapshot above means the current request still sees the
    // gap from the previous activity — that's the value the policy needs
    // to detect an idle timeout.
    tokens.markActivity(token.get());
    return Optional.of(snapshot);
  }

  static Optional<String> extractToken(RestRequest request) {
    return BEARER.extract(request);
  }

  private JCustosSubject toSubject(DemoUser user) {
    RoleName roleName = user.role().roleName();
    Set<PermissionName> permissions = mapping.permissionsFor(roleName);
    return new JCustosSubject(
        user.username(),
        user.displayName(),
        Set.of(roleName),
        permissions);
  }
}