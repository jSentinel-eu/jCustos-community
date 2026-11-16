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

import eu.jsentinel.jcustos.audit.SessionRef;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.EventType;
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.api.JCustosEventCategory;

import java.util.Objects;

/**
 * A session expired by timeout (Konzept §246).
 *
 * @param metadata variable per-instance metadata
 * @param sessionId the {@link SessionRef} of the expired session id, or {@code null};
 *                  a raw identifier passed in is reduced to its reference
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public record SessionExpiredEvent(EventMetadata metadata, String sessionId)
    implements JCustosEvent {

  public static final EventType TYPE = EventType.of("SessionExpired");

  public SessionExpiredEvent {
    Objects.requireNonNull(metadata, "metadata");
    // JS-SEC-117 (CWE-532, CWE-522): a session id is a credential, and this event is signed,
    // stored, exported and forwarded (SIEM, webhook). It carries the reference only, whoever
    // produced it; SessionRef.ofNullable is idempotent.
    sessionId = SessionRef.ofNullable(sessionId);
  }

  @Override
  public EventType eventType() {
    return TYPE;
  }

  @Override
  public JCustosEventCategory category() {
    return JCustosEventCategory.SESSION;
  }
}
