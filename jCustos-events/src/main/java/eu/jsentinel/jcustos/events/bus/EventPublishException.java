package eu.jsentinel.jcustos.events.bus;

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

import java.util.Objects;

/**
 * Thrown by the publish pipeline when an event cannot be published — e.g. the
 * producer is not allowed to publish the event type (Konzept §835).
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class EventPublishException extends RuntimeException {

  private final String reason;

  public EventPublishException(String message) {
    this(message, SelfObservabilityEvents.REASON_PRODUCER_NOT_ALLOWED);
  }

  /**
   * @param message the description for the caller
   * @param reason the structured rejection reason — one of the
   *     {@code SelfObservabilityEvents.REASON_*} constants; the bus reports
   *     the rejection with it
   * @since 00.84.00
   */
  public EventPublishException(String message, String reason) {
    super(message);
    this.reason = Objects.requireNonNull(reason, "reason");
  }

  /**
   * @return the structured rejection reason;
   *     {@link SelfObservabilityEvents#REASON_PRODUCER_NOT_ALLOWED} for an
   *     exception created without one
   * @since 00.84.00
   */
  public String reason() {
    return reason;
  }
}
