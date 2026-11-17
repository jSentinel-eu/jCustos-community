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
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;

import static java.util.Objects.requireNonNull;

/**
 * Persisted form of an {@link AuditEvent}. Pairs the event with a
 * store-assigned identifier and the tenant scope so a queryable audit
 * store can return events that survived past one in-process buffer.
 * <p>
 * The {@code id} is opaque to the framework: implementations of
 * {@code AuditEventStore} are free to use UUIDs, monotonic counters,
 * or any other stable identifier — the only contract is that
 * {@code id} uniquely identifies the envelope within the store.
 * <p>
 * <strong>Correlation id (R5, JS-SEC-066, CWE-778).</strong> The optional
 * {@code correlationId} names the request the event was recorded in, so an
 * audit record can be matched with the line a reverse proxy or the
 * application logged for the same request. It is taken from the
 * {@link AuditCorrelation} scope the web adapters open per request and
 * resolved by the {@link CorrelationIdResolver}: a proxy-supplied
 * {@code X-Request-ID} only from a trusted proxy, otherwise a server-side
 * UUID. Outside a request — background threads, schedulers — it is
 * {@code null}; no id is invented there. Envelopes written before 00.84.00
 * load with {@code null}. A value must be at most
 * {@value #MAX_CORRELATION_ID_LENGTH} characters from {@code [A-Za-z0-9._:-]}
 * ({@link #isValidCorrelationId(String)}); it shares the value space of the
 * event-bus {@code CorrelationId} of {@code jCustos-events}.
 * <p>
 * The enterprise audit chain binds the correlation id into payload 2 as an
 * optional key, so it is tamper-evident like the event itself; a chain entry
 * of an envelope without one carries no key.
 * <p>
 * <strong>Since 00.84.00 the record has a fourth component.</strong> The
 * three-argument constructor remains and leaves the correlation id empty;
 * record deconstruction patterns must name all four components.
 *
 * @param id            non-blank store-assigned identifier
 * @param tenant        tenant scope of the event; {@code null} becomes
 *                      {@link TenantId#DEFAULT}
 * @param event         the wrapped audit event; never {@code null}
 * @param correlationId the request the event was recorded in, or
 *                      {@code null} when there was none
 */
@ExperimentalJCustosApi
public record AuditEnvelope(String id, TenantId tenant, AuditEvent event, String correlationId) {

  /**
   * Longest correlation id an envelope accepts (R5, JS-SEC-066). A UUID has 36
   * characters; the bound leaves room for proxy-generated ids with a prefix
   * and keeps a hostile header from inflating every audit record.
   *
   * @since 00.84.00
   */
  public static final int MAX_CORRELATION_ID_LENGTH = 128;

  /**
   * Validates the record components and substitutes
   * {@link TenantId#DEFAULT} for a {@code null} tenant.
   *
   * @param id            non-blank store-assigned identifier
   * @param tenant        tenant scope; {@code null} becomes {@link TenantId#DEFAULT}
   * @param event         non-null audit event
   * @param correlationId {@code null}, or a value that passes
   *                      {@link #isValidCorrelationId(String)}
   * @throws IllegalArgumentException when {@code id} is blank or the
   *                                  correlation id is malformed
   */
  public AuditEnvelope {
    if (id == null || id.isBlank()) {
      throw new IllegalArgumentException("id must not be blank");
    }
    tenant = tenant == null ? TenantId.DEFAULT : tenant;
    requireNonNull(event, "event must not be null");
    if (correlationId != null && !isValidCorrelationId(correlationId)) {
      // the value is not echoed: it may come from a request header
      throw new IllegalArgumentException("correlationId must be 1 to "
          + MAX_CORRELATION_ID_LENGTH + " characters from [A-Za-z0-9._:-]");
    }
  }

  /**
   * Envelope without a correlation id — the shape before 00.84.00.
   *
   * @param id     non-blank store-assigned identifier
   * @param tenant tenant scope; {@code null} becomes {@link TenantId#DEFAULT}
   * @param event  non-null audit event
   */
  public AuditEnvelope(String id, TenantId tenant, AuditEvent event) {
    this(id, tenant, event, null);
  }

  /**
   * Tells whether a value may serve as correlation id: 1 to
   * {@value #MAX_CORRELATION_ID_LENGTH} characters, each a letter or digit of
   * ASCII or one of {@code . _ : -}. Neither separators nor control, space or
   * non-ASCII characters can therefore reach an audit line or record through
   * it (CWE-117).
   *
   * @param value the candidate, may be {@code null}
   * @return {@code true} if the value is a well-formed correlation id
   * @since 00.84.00
   */
  public static boolean isValidCorrelationId(String value) {
    if (value == null || value.isEmpty() || value.length() > MAX_CORRELATION_ID_LENGTH) {
      return false;
    }
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      boolean allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
          || c == '.' || c == '_' || c == ':' || c == '-';
      if (!allowed) {
        return false;
      }
    }
    return true;
  }
}
