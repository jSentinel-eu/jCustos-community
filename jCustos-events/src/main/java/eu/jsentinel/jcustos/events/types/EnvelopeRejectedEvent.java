package eu.jsentinel.jcustos.events.types;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.EventType;
import eu.jsentinel.jcustos.events.api.JCustosEventCategory;

import java.util.Objects;

/**
 * An incoming envelope was rejected during verification (Konzept §288). Short
 * name for the Konzept's {@code JCustosEventEnvelopeRejectedEvent}.
 *
 * @param metadata variable per-instance metadata
 * @param rejectedEnvelopeId the rejected envelope id
 * @param reason structured rejection reason code
 * @param keyId the key the envelope's signature verified under, for a
 *     rejection reached after the signature check that names a key holder —
 *     {@code key-not-authorized-for-producer} (JS-SEC-101) — so the operator
 *     knows whose key signed in another producer's name; {@code null}
 *     otherwise. A {@code null} key id is left out of the canonical form, so
 *     events without one canonicalise as before (since 00.84.00)
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public record EnvelopeRejectedEvent(EventMetadata metadata, String rejectedEnvelopeId,
    String reason, String keyId)
    implements EventBusSelfObservabilityEvent {

  public static final EventType TYPE = EventType.of("EnvelopeRejected");

  public EnvelopeRejectedEvent {
    Objects.requireNonNull(metadata, "metadata");
  }

  /**
   * A rejection that names no verified key.
   *
   * @param metadata variable per-instance metadata
   * @param rejectedEnvelopeId the rejected envelope id
   * @param reason structured rejection reason code
   */
  public EnvelopeRejectedEvent(EventMetadata metadata, String rejectedEnvelopeId, String reason) {
    this(metadata, rejectedEnvelopeId, reason, null);
  }

  @Override
  public EventType eventType() {
    return TYPE;
  }

  @Override
  public JCustosEventCategory category() {
    return JCustosEventCategory.INTEGRITY;
  }
}
