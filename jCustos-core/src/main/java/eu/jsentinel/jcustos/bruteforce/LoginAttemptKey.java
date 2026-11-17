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
 * A key built with the constructor counts one user name from one client
 * address - the {@code (tenant, user, address)} tuple. It does not see an
 * attacker who hops addresses against one account, nor one who cycles user
 * names from one address. The two factories below build the keys that do;
 * {@link StoreBackedLoginAttemptPolicy} asks all of them per attempt and
 * refuses as soon as one of them is locked.
 *
 * <p><strong>Account keys (JS-SEC-166, CWE-307).</strong> A key built by
 * {@link #forAccount(TenantId, String)} counts the failures of one account
 * across all client addresses - the user-name counter of
 * {@link InMemoryLoginAttemptPolicy}. Its {@code userId} is
 * {@link #ACCOUNT_USER_ID_PREFIX} followed by the canonical user name and its
 * {@code ip} the reserved {@link #ANY_ADDRESS}, so a store keeps it like any
 * other key and the Eclipse-Store format is unchanged.
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
 * <p><strong>Reserved user ids.</strong> A user id that starts with exactly one
 * {@link #RESERVED_PREFIX} belongs to a factory key: {@link #ADDRESS_USER_ID}
 * and every id that starts with {@link #ACCOUNT_USER_ID_PREFIX}. The user id of
 * a tuple key passes through {@link #accountUserId(String)} and therefore either
 * does not start with the prefix or starts with it twice, so the three kinds of
 * key never share a counter.
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
   * Start of the {@code userId} of every account key (JS-SEC-166): {@value}. The
   * canonical user name follows it unchanged.
   *
   * @since 00.84.00
   */
  public static final String ACCOUNT_USER_ID_PREFIX = RESERVED_PREFIX + "account:";

  /**
   * The {@code ip} of every account key (JS-SEC-166): {@value}. An account key
   * counts the failures from every address.
   *
   * @since 00.84.00
   */
  public static final String ANY_ADDRESS = RESERVED_PREFIX + "any";

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
   * The key that counts the failures of one account across all client
   * addresses (JS-SEC-166, CWE-307): {@code userId} is
   * {@link #ACCOUNT_USER_ID_PREFIX} followed by {@code canonicalUserName},
   * {@code ip} is {@link #ANY_ADDRESS}. The mapping is injective, and the
   * user id starts with exactly one {@link #RESERVED_PREFIX}, so the key never
   * equals a tuple key or an address key.
   *
   * @param tenant            tenant scope; {@code null} becomes {@link TenantId#DEFAULT}
   * @param canonicalUserName the user name after canonicalisation; non-blank
   * @return the account key
   * @since 00.84.00
   */
  public static LoginAttemptKey forAccount(TenantId tenant, String canonicalUserName) {
    if (canonicalUserName == null || canonicalUserName.isBlank()) {
      throw new IllegalArgumentException("canonicalUserName must not be blank");
    }
    return new LoginAttemptKey(tenant, ACCOUNT_USER_ID_PREFIX + canonicalUserName, ANY_ADDRESS);
  }

  /**
   * Maps a canonical user name onto the {@code userId} of its account key.
   * A name that starts with {@link #RESERVED_PREFIX} gets the prefix once
   * more; every other name stays as it is. The mapping is injective and
   * never yields a reserved user id - {@link #ADDRESS_USER_ID} or one that
   * starts with {@link #ACCOUNT_USER_ID_PREFIX}; an escaped name starts with
   * the prefix twice - so no tuple key can share the counter of an address or
   * of an account key.
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

  /**
   * @return {@code true} for a key built by {@link #forAccount(TenantId, String)}
   * @since 00.84.00
   */
  public boolean accountScoped() {
    return userId.startsWith(ACCOUNT_USER_ID_PREFIX);
  }
}
