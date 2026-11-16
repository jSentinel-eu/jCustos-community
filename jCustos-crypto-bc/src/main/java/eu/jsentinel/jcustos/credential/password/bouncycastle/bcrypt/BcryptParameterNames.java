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

import eu.jsentinel.jcustos.credential.password.bouncycastle.BouncyCastleModuleInfo;

/**
 * Stable wire-format parameter names for the bcrypt envelope.
 *
 * <p>Phase-1b stores the bcrypt salt and derived bytes as base64 inside
 * the standard Phase-1a envelope rather than wrapping the OpenBSD MCF
 * string verbatim — the MCF format uses {@code $} as a field separator,
 * which collides with the Phase-1a envelope separator.</p>
 */
public final class BcryptParameterNames {

  public static final String ALGORITHM = BouncyCastleModuleInfo.BCRYPT_ALGORITHM;
  public static final String PROVIDER_ID = BouncyCastleModuleInfo.BCRYPT_PROVIDER_ID;

  /** bcrypt cost factor (log2 of the number of rounds). */
  public static final String COST = "c";

  /** Base64-encoded 16-byte salt. */
  public static final String SALT = "s";

  /**
   * Password framing marker, JS-SEC-133 (CWE-327). The value
   * {@link #TERMINATOR_NUL} states that the provider appended the
   * terminating {@code 0x00} byte of standard bcrypt to the UTF-8 bytes
   * of the password before the key schedule ran. An envelope
   * <em>without</em> this parameter is a legacy hash, derived from the
   * raw UTF-8 bytes: Blowfish repeats its key cyclically, so without the
   * terminator a periodic password ({@code abcabcabcabc}) is equivalent
   * to its shortest period ({@code abc}). Legacy hashes still verify, in
   * legacy framing, and are reported for a rehash under every policy - by
   * the provider's {@code rehashHint}, and through the policy defaults (see
   * {@link BcryptDefaults#defaultParameters()}).
   *
   * @since 00.84.00
   */
  public static final String TERMINATOR = "term";

  /**
   * The only supported value of {@link #TERMINATOR}: a single trailing
   * {@code 0x00} byte, as in OpenBSD bcrypt ({@code $2a$}/{@code $2b$}/{@code $2y$}).
   *
   * @since 00.84.00
   */
  public static final String TERMINATOR_NUL = "1";

  /**
   * bcrypt's hard 72-byte limit on the key that enters the Blowfish key
   * schedule. Inputs longer than this are silently truncated by the
   * bcrypt algorithm itself; this provider rejects them explicitly. For
   * new hashes the terminator occupies one of the 72 bytes, so the
   * password itself is limited to {@link #MAX_TERMINATED_PASSWORD_BYTES};
   * the full 72 bytes are accepted only when a legacy envelope (no
   * {@link #TERMINATOR} parameter) is verified.
   */
  public static final int MAX_PASSWORD_BYTES = 72;

  /**
   * Upper bound on the UTF-8 length of a password in a new,
   * NUL-terminated hash: 71 password bytes plus the terminator fill the
   * 72-byte bcrypt key. JS-SEC-133 (CWE-327).
   *
   * @since 00.84.00
   */
  public static final int MAX_TERMINATED_PASSWORD_BYTES = MAX_PASSWORD_BYTES - 1;

  /** Fixed bcrypt salt length in bytes. */
  public static final int SALT_BYTES = 16;

  /** Fixed bcrypt derived-key length in bytes. */
  public static final int DERIVED_BYTES = 24;

  private BcryptParameterNames() { }
}
