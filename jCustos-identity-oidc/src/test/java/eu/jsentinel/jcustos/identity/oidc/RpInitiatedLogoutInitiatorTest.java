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
package eu.jsentinel.jcustos.identity.oidc;

/*-
 * #%L
 * jCustos OIDC — Relying-Party identity layer
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

import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.jsentinel.jcustos.oidc.api.LogoutRequest;
import eu.jsentinel.jcustos.oidc.api.PostLogoutRedirectValidator;

import java.net.URI;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("RpInitiatedLogoutInitiator — builds the end_session URL with encoded params")
class RpInitiatedLogoutInitiatorTest {

  /** JS-SEC-089: a post_logout_redirect_uri is sent only when an allowlist names it. */
  private final RpInitiatedLogoutInitiator initiator = new RpInitiatedLogoutInitiator(
      PostLogoutRedirectValidator.allowOnly(URI.create("https://app.example/after")));

  @Test
  @DisplayName("includes id_token_hint, post_logout_redirect_uri and state, percent-encoded")
  void buildsFullUrl() {
    URI url = initiator.buildLogoutUri(URI.create("https://idp.example/logout"),
        new LogoutRequest("ID.TOKEN.HINT",
            Optional.of(URI.create("https://app.example/after?x=1")), Optional.of("st 123")));
    String s = url.toString();
    assertTrue(s.startsWith("https://idp.example/logout?"));
    assertTrue(s.contains("id_token_hint=ID.TOKEN.HINT"));
    assertTrue(s.contains("post_logout_redirect_uri=https%3A%2F%2Fapp.example%2Fafter%3Fx%3D1"),
        "redirect uri must be percent-encoded: " + s);
    assertTrue(s.contains("state=st+123") || s.contains("state=st%20123"), s);
  }

  @Test
  @DisplayName("appends with & when the end_session_endpoint already has a query")
  void appendsToExistingQuery() {
    URI url = initiator.buildLogoutUri(URI.create("https://idp.example/logout?ui_locales=en"),
        new LogoutRequest("HINT", Optional.empty(), Optional.empty()));
    assertTrue(url.toString().startsWith("https://idp.example/logout?ui_locales=en&id_token_hint=HINT"));
  }
}
