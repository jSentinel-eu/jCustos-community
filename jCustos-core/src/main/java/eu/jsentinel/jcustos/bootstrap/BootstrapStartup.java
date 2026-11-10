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
package eu.jsentinel.jcustos.bootstrap;

/**
 * One-shot startup orchestrator. Call this once during server boot.
 * <p>
 * If bootstrap is required and no token is currently stored, generates a
 * fresh token, persists it, and emits the operator-facing setup banner via
 * the configured {@link BootstrapTokenOutput}. If a token already exists
 * (persistent mode after restart), it is reused so the user can resume the
 * setup.
 * <p>
 * A stored token is only reused when the store vouches for it and it is
 * neither expired nor stamped with a creation instant in the future
 * (JS-SEC-130, CWE-345, CWE-613). {@link FileBootstrapTokenStore#load()}
 * reports a file it does not trust as absent — foreign owner, permissions
 * beyond the owner, or a value the generator cannot have produced — and this
 * method then generates a fresh token and replaces the file.
 */
public final class BootstrapStartup {

  private BootstrapStartup() {
  }

  public static void initializeIfRequired(
      BootstrapStateService stateService,
      BootstrapTokenStore tokenStore,
      BootstrapTokenGenerator generator,
      BootstrapTokenOutput output,
      BootstrapConfiguration configuration) {
    if (stateService.mode() == BootstrapMode.DISABLED && !stateService.hasAdministrator()) {
      throw new IllegalStateException(
          "Bootstrap is DISABLED but no administrator account exists. "
              + "The application would be unusable in this state. Set "
              + "SECURITY_BOOTSTRAP_MODE=TRANSIENT_CONSOLE or "
              + "SECURITY_BOOTSTRAP_MODE=PERSISTENT_FILE (or the matching "
              + "security.bootstrap.mode system property) to enable initial "
              + "administrator setup, or pre-provision an administrator before "
              + "starting the server.");
    }
    if (!stateService.bootstrapRequired()) return;
    // JS-SEC-130: load() already dropped a token file it does not trust, and
    // isExpired also rejects a creation instant in the future — both end in a
    // fresh token that overwrites whatever was found.
    BootstrapToken token = tokenStore.load()
        .filter(existing -> !existing.isExpired(java.time.Instant.now(), configuration.tokenValidity()))
        .orElseGet(() -> {
          BootstrapToken fresh = generator.generate();
          tokenStore.save(fresh);
          return fresh;
        });
    output.emit(token, configuration);
  }
}
