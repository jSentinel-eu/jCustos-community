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
package eu.jsentinel.jcustos.authentication;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Objects.requireNonNull;

/**
 * In-memory {@link RememberMeTokenStore} backed by a
 * {@link ConcurrentHashMap} keyed on the token hash.
 */
@ExperimentalJCustosApi
public final class InMemoryRememberMeTokenStore implements RememberMeTokenStore {

  private final ConcurrentHashMap<String, RememberMeTokenRecord> tokens = new ConcurrentHashMap<>();
  /**
   * hash → trail of a token consumed by a rotation (JS-SEC-128). Entries live
   * until the consumed record's expiry and go with the subject's tokens.
   */
  private final ConcurrentHashMap<String, RotatedToken> rotated = new ConcurrentHashMap<>();

  /** Creates an empty store. */
  public InMemoryRememberMeTokenStore() {
  }

  @Override
  public Optional<RememberMeTokenRecord> findByHash(String tokenHash) {
    requireNonBlank(tokenHash, "tokenHash");
    return Optional.ofNullable(tokens.get(tokenHash));
  }

  @Override
  public void save(RememberMeTokenRecord record) {
    requireNonNull(record, "record must not be null");
    tokens.put(record.tokenHash(), record);
  }

  @Override
  public boolean deleteByHash(String tokenHash) {
    requireNonBlank(tokenHash, "tokenHash");
    return tokens.remove(tokenHash) != null;
  }

  @Override
  public boolean markRotated(String tokenHash, Instant at) {
    requireNonBlank(tokenHash, "tokenHash");
    requireNonNull(at, "at must not be null");
    boolean[] claimed = {false};
    // JS-SEC-128: retire and leave the trail in one atomic step per hash, so
    // that of two concurrent presentations exactly one obtains the successor.
    tokens.computeIfPresent(tokenHash, (hash, live) -> {
      rotated.put(hash, new RotatedToken(live, at));
      claimed[0] = true;
      return null;
    });
    return claimed[0];
  }

  @Override
  public Optional<RotatedToken> findRotated(String tokenHash) {
    requireNonBlank(tokenHash, "tokenHash");
    return Optional.ofNullable(rotated.get(tokenHash));
  }

  @Override
  public int deleteBySubject(TenantId tenant, SubjectId subjectId) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    int before = tokens.size();
    tokens.values().removeIf(record ->
        record.tenant().equals(tenant) && record.subjectId().equals(subjectId));
    rotated.values().removeIf(trail ->
        trail.record().tenant().equals(tenant)
            && trail.record().subjectId().equals(subjectId));
    return before - tokens.size();
  }

  @Override
  public int purgeExpired(Instant now) {
    requireNonNull(now, "now must not be null");
    int before = tokens.size();
    tokens.values().removeIf(record -> record.isExpired(now));
    rotated.values().removeIf(trail -> trail.record().isExpired(now));
    return before - tokens.size();
  }

  private static void requireNonBlank(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
  }
}
