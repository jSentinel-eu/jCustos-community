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
package eu.jsentinel.jcustos.demo.skill.vaadin;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.ConfiguredHashingService;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.InMemoryUserDirectory;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.UserDirectory;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.SessionId;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;

import java.time.Instant;

/** Fixtures of the layer-1 demo: everything lives in memory. */
final class TestDirectories {

  private TestDirectories() {
  }

  /** Nothing to isolate: layer 1 keeps users and sessions in memory. */
  static void isolateStorage() {
  }

  /** Layer 1 has no first-administrator setup. */
  static void resetBootstrapWiring() {
  }

  /** An empty directory on the demo's configured hashing service, without demo accounts. */
  static UserDirectory fresh() {
    return new InMemoryUserDirectory(ConfiguredHashingService.INSTANCE, false);
  }

  static SessionRecord record(String sessionId, String subjectId) {
    Instant now = Instant.now();
    return new SessionRecord(SessionId.of(sessionId), SubjectId.of(subjectId), TenantId.DEFAULT,
        now, now, JCustosVersion.INITIAL, SessionStatus.ACTIVE);
  }
}
