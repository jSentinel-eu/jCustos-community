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
package eu.jsentinel.jcustos.credential.password.pepper;

import java.util.Optional;

/**
 * The {@link PepperService} that peppers nothing.
 *
 * <p>This implementation deliberately performs no pepper protection. It
 * publishes no active key id, and a lookup of any non-empty
 * {@code keyId} resolves to {@link Optional#empty()}. The verification
 * pipeline interprets that as
 * {@code VERIFICATION_FAILED_UNKNOWN_PEPPER_KEY} so an envelope that
 * was peppered cannot be silently downgraded.</p>
 *
 * <p>It is what every factory uses unless a pepper is passed. To pepper,
 * hand a {@link KeyStorePepperService} or {@link FilePepperService} to the
 * factory instead (see {@link PepperService}).</p>
 */
public final class NoOpPepperService implements PepperService {

  public static final NoOpPepperService INSTANCE = new NoOpPepperService();

  @Override
  public Optional<String> activeKeyId() {
    return Optional.empty();
  }

  @Override
  public Optional<byte[]> resolve(String keyId) {
    return Optional.empty();
  }
}
