/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
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
package eu.jsentinel.jcustos.dx.standalone.bootstrap;


/**
 * SPI handed to a standalone / CLI application's interactive login
 * loop. Implementations gather credentials from {@code System.console()},
 * a Swing/JavaFX dialog, etc., and return the entered tuple. The
 * library wires nothing automatically — the consumer drives its own
 * login flow and calls this to prompt the user.
 *
 * <p>Returning {@code null} from {@link #prompt(String)} signals
 * "cancelled" and aborts the login loop.
 *
 * @since 00.74.00
 */
@FunctionalInterface
public interface InteractiveLoginPrompt {

  /**
   * Prompts the user once.
   *
   * @param message message to display (e.g. {@code "Please log in"})
   * @return entered credentials, or {@code null} if the user
   *         cancelled
   */
  Credentials prompt(String message);

  /**
   * Username + secret tuple. {@link #secret()} is a plain {@code char[]}
   * for the consumer to zero out after use.
   *
   * @param username username; non-null, non-blank
   * @param secret   secret; non-null, may be empty
   */
  record Credentials(String username, char[] secret) {

    /** Validates inputs. */
    public Credentials {
      if (username == null || username.isBlank()) {
        throw new IllegalArgumentException("username must not be blank");
      }
      if (secret == null) {
        throw new IllegalArgumentException("secret must not be null");
      }
    }

    /**
     * Masks the secret (JS-SEC-127, CWE-532): no description of the credentials carries it,
     * whatever a later change does to the component's type.
     *
     * @return a description without the secret
     */
    @Override
    public String toString() {
      return "Credentials[username=" + username + ", secret=***]";
    }
  }
}
