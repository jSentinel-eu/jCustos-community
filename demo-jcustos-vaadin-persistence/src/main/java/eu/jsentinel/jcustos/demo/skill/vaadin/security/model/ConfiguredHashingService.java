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
package eu.jsentinel.jcustos.demo.skill.vaadin.security.model;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.RehashDecision;

/**
 * The password-hashing service the bootstrap configured with
 * {@code .credentials(c -> c.hashing(...))}, resolved on every call
 * (JS-SEC-134; CWE-684, CWE-916).
 *
 * <p>{@code .hashing(...)} publishes the service through
 * {@link JCustosServiceResolver#credentialHashingService()} when
 * {@code install()} runs. The user directory and the first-administrator
 * setup are created earlier - a layer's bootstrap extension may build them
 * while the chain is still being assembled - so they must not capture the
 * service they find at construction time: that would be the default
 * (PBKDF2), not the Argon2id profile the hardening layer configures.
 * Delegating at call time gives both the same, configured service, and an
 * administrator created by the setup can log in.
 */
public final class ConfiguredHashingService implements PasswordHashingService {

  /** The shared instance; the class holds no state. */
  public static final ConfiguredHashingService INSTANCE = new ConfiguredHashingService();

  private ConfiguredHashingService() {
  }

  private static PasswordHashingService configured() {
    return JCustosServiceResolver.credentialHashingService();
  }

  @Override
  public PasswordHashResult hash(char[] password) {
    return configured().hash(password);
  }

  @Override
  public CredentialVerificationResult verify(char[] password, String encodedHash) {
    return configured().verify(password, encodedHash);
  }

  @Override
  public RehashDecision needsRehash(String encodedHash) {
    return configured().needsRehash(encodedHash);
  }

  @Override
  public CredentialVerificationResult verifyAgainstNothing(char[] password) {
    return configured().verifyAgainstNothing(password);
  }
}
