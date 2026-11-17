package eu.jsentinel.jcustos.events.store;

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

/**
 * Why an envelope was dead-lettered (Konzept §743).
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public enum RejectionReason {

  /** The signature did not verify. */
  INVALID_SIGNATURE,

  /** The referenced key id is unknown. */
  UNKNOWN_KEY,

  /** The referenced key has been revoked. */
  KEY_REVOKED,

  /** The envelope was a replay of an already-seen envelope. */
  REPLAY_DETECTED,

  /** The sequence violated the configured policy. */
  SEQUENCE_VIOLATION,

  /** The producer is not allowed to publish this event type. */
  PRODUCER_NOT_ALLOWED,

  /** The payload could not be deserialized. */
  DESERIALIZATION_ERROR,

  /** A listener failed and the configuration routes such failures here. */
  LISTENER_FAILED,

  /**
   * The envelope was past its acceptance window — or, since 00.84.00, its
   * acceptance window was longer than the consumer accepts (ER27).
   */
  EXPIRED
}
