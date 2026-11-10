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
package eu.jsentinel.jcustos.audit;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/**
 * The non-secret reference that stands in for a session identifier in audit output
 * (JS-SEC-079, JS-SEC-117; CWE-532, CWE-522).
 *
 * <p>A session identifier is a credential: the servlet session cookie in a Vaadin
 * application, usually the bearer token itself in a REST integration. Audit output is
 * read by people and systems that must not hold it. A reference is the marker
 * {@value #PREFIX} followed by the first {@value #HEX_LENGTH} hex characters of the
 * SHA-256 of the identifier: stable, so the events of one session can be correlated, and
 * useless for taking the session over.
 *
 * <p><strong>Why the marker.</strong> The {@code sessionId} component of the audit events
 * is a plain {@code String}, and it is filled by two kinds of producers: those that pass
 * the raw identifier and leave the reduction to the sink (the Vaadin adapter), and those
 * that reduce at the source because the raw value must not reach any sink (the REST
 * filters). A sink therefore has to tell the two apart. Without the marker it could not,
 * and {@code LoggingAuditSink} hashed a reference a second time: the log line then showed
 * a different value from the event it described. {@link #of(String)} is idempotent — a
 * value that already is a reference is returned as it is — so producer and sink can both
 * call it and every output shows the same reference for the same session.
 *
 * <p>Recognition is by shape. An identifier that happens to consist of the marker and
 * {@value #HEX_LENGTH} lower-case hex characters is taken for a reference and passed
 * through. No session mechanism the library ships produces such identifiers; an
 * application that issues its own must not issue them in this shape.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class SessionRef {

  /** Marker every reference starts with. */
  public static final String PREFIX = "sref-";

  /** Number of hex characters after the marker: 64 bits of the SHA-256. */
  public static final int HEX_LENGTH = 16;

  private SessionRef() {
    throw new AssertionError("no instances");
  }

  /**
   * Reduces a session identifier to its reference. Idempotent: a value that already
   * {@linkplain #isReference(String) is a reference} is returned unchanged.
   *
   * @param sessionId the raw session identifier, a token, or a reference; non-null
   * @return the reference, never the identifier itself
   */
  public static String of(String sessionId) {
    Objects.requireNonNull(sessionId, "sessionId");
    if (isReference(sessionId)) {
      return sessionId;
    }
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256")
          .digest(sessionId.getBytes(StandardCharsets.UTF_8));
      return PREFIX + HexFormat.of().formatHex(digest, 0, HEX_LENGTH / 2);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  /**
   * Null-tolerant variant of {@link #of(String)} for event components that may be
   * absent.
   *
   * @param sessionId the raw session identifier, a token, or a reference; may be
   *                  {@code null}
   * @return the reference, or {@code null} when {@code sessionId} is {@code null}
   */
  public static String ofNullable(String sessionId) {
    return sessionId == null ? null : of(sessionId);
  }

  /**
   * Tells whether a value has the shape of a reference: the marker followed by exactly
   * {@value #HEX_LENGTH} lower-case hex characters.
   *
   * @param value the value to test; may be {@code null}
   * @return {@code true} when {@code value} is a reference
   */
  public static boolean isReference(String value) {
    if (value == null || value.length() != PREFIX.length() + HEX_LENGTH
        || !value.startsWith(PREFIX)) {
      return false;
    }
    for (int i = PREFIX.length(); i < value.length(); i++) {
      char c = value.charAt(i);
      boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
      if (!hex) {
        return false;
      }
    }
    return true;
  }
}
