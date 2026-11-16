/*-
 * #%L
 * Security Crypto — BouncyCastle
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
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
package eu.jsentinel.jcustos.credential.password.bouncycastle.bcrypt;

import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Phase-1b reference parameters for the bcrypt password hashing path.
 *
 * <p>Defaults follow OWASP 2023 guidance for interactive logins:
 * cost&nbsp;= 12 (~400&nbsp;ms on commodity hardware). Lower bound is
 * the OWASP minimum of 10; upper bound is 16 (~25&nbsp;s) to keep a
 * single verification from monopolising a worker thread (CWE-400).</p>
 *
 * <p>bcrypt is intentionally <em>not</em> the modern-profile default
 * (see Argon2id). It is offered for interoperability with existing
 * deployments and for operator choice.</p>
 */
public final class BcryptDefaults {

  public static final int DEFAULT_COST = 12;
  public static final int MIN_COST = 10;
  public static final int MAX_COST = 16;

  private BcryptDefaults() { }

  /**
   * Default parameters of a bcrypt policy: the cost factor and the
   * password framing.
   *
   * <p>JS-SEC-133 (CWE-327): the map carries
   * {@link BcryptParameterNames#TERMINATOR} so that the rehash engine,
   * which reports {@code PARAMETERS_OUTDATED} for an envelope that lacks
   * a parameter named in the policy defaults, flags every legacy hash
   * (derived without the terminating NUL byte) on its next successful
   * verification. The provider writes the terminator into every new hash
   * regardless of the policy. A policy that assembles its bcrypt defaults
   * by hand without the entry still obtains the signal: since 00.84.00 the
   * provider reports a legacy envelope itself through
   * {@link BcryptPasswordHashProvider#rehashHint}.</p>
   */
  public static Map<String, String> defaultParameters() {
    Map<String, String> m = new LinkedHashMap<>();
    m.put(BcryptParameterNames.COST, Integer.toString(DEFAULT_COST));
    m.put(BcryptParameterNames.TERMINATOR, BcryptParameterNames.TERMINATOR_NUL);
    return m;
  }

  public static Map<String, String> minimumParameters() {
    Map<String, String> m = new LinkedHashMap<>();
    m.put(BcryptParameterNames.COST, Integer.toString(MIN_COST));
    return m;
  }

  public static Map<String, String> maximumParameters() {
    Map<String, String> m = new LinkedHashMap<>();
    m.put(BcryptParameterNames.COST, Integer.toString(MAX_COST));
    return m;
  }

  /**
   * Single-algorithm reference policy that emits bcrypt envelopes under
   * the Phase-1b defaults.
   */
  public static PasswordHashPolicy referencePolicy() {
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(BcryptParameterNames.ALGORITHM)
        .preferredProviderId(BcryptParameterNames.PROVIDER_ID)
        .defaultParameters(BcryptParameterNames.ALGORITHM, defaultParameters())
        .minimumParameters(BcryptParameterNames.ALGORITHM, minimumParameters())
        .maximumParameters(BcryptParameterNames.ALGORITHM, maximumParameters())
        .build();
  }
}
