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
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.codec.CanonicalJsonPayloadCodec;
import eu.jsentinel.jcustos.events.codec.RecordReflectionCanonicalizer;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-117 (CWE-532, CWE-522): the session events of the bus name a session by its
 * {@link SessionRef}. A bus event is canonicalised, signed, stored and forwarded to SIEM
 * and webhook endpoints; a live session id in it is a credential handed to every one of
 * them. The reduction sits in the record itself, so it holds for every producer.
 */
@DisplayName("JS-SEC-117 — session events on the bus carry a session reference")
class SessionEventReferenceTest {

  private static final String RAW = "node0x7Q2bW9cN4kL1pZ8vT3yR6sD0fG5hJ";

  private static final List<Function<String, JCustosEvent>> FACTORIES = List.of(
      id -> new SessionCreatedEvent(meta(), id),
      id -> new SessionExpiredEvent(meta(), id),
      id -> new SessionRevokedEvent(meta(), id, "admin-revoked"),
      id -> new LogoutSucceededEvent(meta(), id));

  @Test
  @DisplayName("a raw id becomes its reference, in the record and in the canonical payload")
  void rawIdIsReduced() {
    RecordReflectionCanonicalizer canonicalizer = new RecordReflectionCanonicalizer();
    CanonicalJsonPayloadCodec codec = new CanonicalJsonPayloadCodec();
    for (Function<String, JCustosEvent> factory : FACTORIES) {
      JCustosEvent event = factory.apply(RAW);
      assertEquals(SessionRef.of(RAW), sessionIdOf(event), event.getClass().getSimpleName());
      String payload = new String(codec.encode(canonicalizer.canonicalize(event)),
          StandardCharsets.UTF_8);
      assertFalse(payload.contains(RAW), "raw session id in the signed payload: " + payload);
      assertTrue(payload.contains(SessionRef.of(RAW)), payload);
    }
  }

  @Test
  @DisplayName("a reference passes unchanged and a missing id stays null")
  void referenceAndNull() {
    for (Function<String, JCustosEvent> factory : FACTORIES) {
      assertEquals(SessionRef.of(RAW), sessionIdOf(factory.apply(SessionRef.of(RAW))));
      assertNull(sessionIdOf(factory.apply(null)));
    }
  }

  private static String sessionIdOf(JCustosEvent event) {
    return switch (event) {
      case SessionCreatedEvent e -> e.sessionId();
      case SessionExpiredEvent e -> e.sessionId();
      case SessionRevokedEvent e -> e.sessionId();
      case LogoutSucceededEvent e -> e.sessionId();
      default -> throw new AssertionError("unexpected " + event.getClass());
    };
  }

  private static EventMetadata meta() {
    return EventMetadata.create(TenantId.DEFAULT, SubjectId.of("alice"),
        Instant.parse("2026-11-16T10:15:30Z"), JCustosEventSeverity.INFO);
  }
}
