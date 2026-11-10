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
package eu.jsentinel.jcustos.dpop;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

/**
 * A sealed taxonomy of the reasons a DPoP proof is rejected (RFC 9449 §4.3, §11),
 * V00.79. Each variant carries a stable {@link #code()} for diagnostics/audit and a
 * short, leak-free {@link #detail()}; the validator never echoes the offending proof.
 *
 * @since 00.79.10
 */
@ExperimentalJCustosApi
public sealed interface DpopValidationError {

  String code();

  String detail();

  /** The compact string was not a well-formed {@code dpop+jwt} JWS, or a claim is missing. */
  record ProofMalformed(String detail) implements DpopValidationError {
    @Override
    public String code() {
      return "dpop/proof-malformed";
    }
  }

  /** The embedded public key did not verify the proof's signature. */
  record SignatureInvalid(String detail) implements DpopValidationError {
    @Override
    public String code() {
      return "dpop/signature-invalid";
    }
  }

  /** The {@code htm} claim did not match the actual HTTP method. */
  record HtmMismatch(String detail) implements DpopValidationError {
    @Override
    public String code() {
      return "dpop/htm-mismatch";
    }
  }

  /** The {@code htu} claim did not match the actual request URI (scheme+host+path). */
  record HtuMismatch(String detail) implements DpopValidationError {
    @Override
    public String code() {
      return "dpop/htu-mismatch";
    }
  }

  /** {@code iat} is outside the accepted freshness window (too old or too far future). */
  record ProofExpired(String detail) implements DpopValidationError {
    @Override
    public String code() {
      return "dpop/proof-expired";
    }
  }

  /** The {@code jti} has already been seen within its window (replay). */
  record Replay(String detail) implements DpopValidationError {
    @Override
    public String code() {
      return "dpop/replay";
    }
  }

  /** The {@code ath} claim did not match the SHA-256 hash of the presented access token. */
  record AccessTokenHashMismatch(String detail) implements DpopValidationError {
    @Override
    public String code() {
      return "dpop/ath-mismatch";
    }
  }

  /**
   * The proof is not signed with the key the access token is bound to: the thumbprint of the
   * proof key differs from the expected {@code cnf.jkt} (RFC 9449 §6.1), or an access token was
   * supplied without an expected thumbprint, so the binding could not be checked (JS-SEC-148,
   * CWE-345).
   *
   * @since 00.84.00
   */
  record KeyBindingMismatch(String detail) implements DpopValidationError {
    @Override
    public String code() {
      return "dpop/key-binding-mismatch";
    }
  }
}
