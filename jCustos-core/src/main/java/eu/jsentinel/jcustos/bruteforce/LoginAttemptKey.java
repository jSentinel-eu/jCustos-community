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
package eu.jsentinel.jcustos.bruteforce;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;

/**
 * Composite key under which {@link LoginAttemptStore} tracks
 * failed-attempt counters and the last failure instant.
 * <p>
 * Both dimensions are recorded independently: {@code userId} catches
 * an attacker hopping IPs against the same account, {@code ip}
 * catches one cycling usernames from the same source. Brute-force
 * policies typically consult both keys per attempt and back off as
 * soon as either counter trips.
 *
 * <p><strong>Address keys (JS-SEC-062, CWE-307).</strong> A key built by
 * {@link #forAddress(TenantId, String)} counts the failures of one client
 * address across all accounts. It is an ordinary key whose {@code userId}
 * is the reserved {@link #ADDRESS_USER_ID}, so a store keeps it like any
 * other - the Eclipse-Store format is unchanged. No account can own that
 * user id: {@link #accountUserId(String)} rewrites every user name that
 * starts with {@link #RESERVED_PREFIX}, and
 * {@link StoreBackedLoginAttemptPolicy} passes every user name through it.
 *
 * @param tenant tenant scope; {@code null} becomes {@link TenantId#DEFAULT}
 * @param userId username dimension; non-blank
 * @param ip     client-address dimension; non-blank
 */
@ExperimentalJCustosApi
public record LoginAttemptKey(TenantId tenant, String userId, String ip) {

  /**
   * First character of every reserved user id: {@value}. An account user
   * id that starts with it is escaped by {@link #accountUserId(String)}.
   *
   * @since 00.84.00
   */
  public static final String RESERVED_PREFIX = "#";

  /**
   * The {@code userId} of every address key (JS-SEC-062): {@value}.
   *
   * @since 00.84.00
   */
  public static final String ADDRESS_USER_ID = RESERVED_PREFIX + "address";

  /**
   * Validates the record components and normalises a {@code null}
   * tenant to {@link TenantId#DEFAULT}.
   *
   * @param tenant tenant scope; {@code null} becomes DEFAULT
   * @param userId non-blank username
   * @param ip     non-blank client address
   */
  public LoginAttemptKey {
    tenant = tenant == null ? TenantId.DEFAULT : tenant;
    if (userId == null || userId.isBlank()) {
      throw new IllegalArgumentException("userId must not be blank");
    }
    if (ip == null || ip.isBlank()) {
      throw new IllegalArgumentException("ip must not be blank");
    }
  }

  /**
   * The key that counts the failures of {@code ip} across all accounts
   * (JS-SEC-062, CWE-307).
   *
   * @param tenant tenant scope; {@code null} becomes {@link TenantId#DEFAULT}
   * @param ip     non-blank client address
   * @return the address key
   * @since 00.84.00
   */
  public static LoginAttemptKey forAddress(TenantId tenant, String ip) {
    return new LoginAttemptKey(tenant, ADDRESS_USER_ID, ip);
  }

  /**
   * Maps a canonical user name onto the {@code userId} of its account key.
   * A name that starts with {@link #RESERVED_PREFIX} gets the prefix once
   * more; every other name stays as it is. The mapping is injective and
   * never yields {@link #ADDRESS_USER_ID} - an escaped name starts with the
   * prefix twice - so no user name can share the counter of an address.
   *
   * @param canonicalUserName the user name after canonicalisation; non-null
   * @return the user id of the account key
   * @since 00.84.00
   */
  public static String accountUserId(String canonicalUserName) {
    return canonicalUserName.startsWith(RESERVED_PREFIX)
        ? RESERVED_PREFIX + canonicalUserName
        : canonicalUserName;
  }

  /**
   * @return {@code true} for a key built by {@link #forAddress(TenantId, String)}
   * @since 00.84.00
   */
  public boolean addressScoped() {
    return ADDRESS_USER_ID.equals(userId);
  }
}
