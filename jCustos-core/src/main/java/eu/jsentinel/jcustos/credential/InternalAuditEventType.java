/*-
 * #%L
 * Security Core
 * $Id:$
 * $HeadURL:$
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

package eu.jsentinel.jcustos.credential;


/**
 * Differentiated, internal-only classification of credential verification
 * outcomes. These values are intended for audit sinks, metrics and forensic
 * analysis. They must never be exposed in HTTP responses, UI messages,
 * exception messages or other public surfaces.
 *
 * <p>Public callers consume {@link PublicFailureType} instead; the two
 * vocabularies are deliberately separate so the audit trail can grow over
 * time without weakening enumeration resistance at the perimeter.</p>
 */
public enum InternalAuditEventType {
  VERIFICATION_SUCCESS,
  VERIFICATION_FAILED_MISMATCH,
  VERIFICATION_FAILED_DECODE_ERROR,
  VERIFICATION_FAILED_UNSUPPORTED_FORMAT_VERSION,
  VERIFICATION_FAILED_UNSUPPORTED_ALGORITHM,
  VERIFICATION_FAILED_UNKNOWN_PROVIDER,
  VERIFICATION_FAILED_UNKNOWN_PEPPER_KEY,
  VERIFICATION_FAILED_INVALID_PARAMETERS,
  VERIFICATION_FAILED_PROVIDER_ERROR,
  VERIFICATION_REJECTED_KDF_LIMIT,
  VERIFICATION_DUMMY_PATH,
  /**
   * A refresh token that had already been consumed by a rotation was presented
   * again (JS-SEC-071, CWE-294). The token family is revoked when this is
   * recorded; the perimeter sees only the generic refusal.
   *
   * @since 00.84.00
   */
  REFRESH_TOKEN_REPLAY
}
