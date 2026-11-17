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
package eu.jsentinel.jcustos.oauth2;

/*-
 * #%L
 * jCustos OAuth2 — RP flows (token endpoint, auth-code, refresh, device)
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

import com.svenruppert.dependencies.core.net.HttpStatus;
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.net.EndpointSecurity;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oauth2.api.RevocationClient;
import eu.jsentinel.jcustos.oauth2.api.TokenTypeHint;
import eu.jsentinel.jcustos.oauth2.http.OAuth2FormPost;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * RFC 7009 token revocation over JDK {@link HttpClient} (V00.77). RFC 7009 §2.2
 * makes the server return {@code 200} even for an unknown token, so a {@code 2xx}
 * is success; only a transport failure or a non-{@code 2xx} status surfaces as an
 * {@link OAuth2Error}. The token is never logged.
 */
public final class HttpRevocationClient implements RevocationClient {

  private static final String CODE = "oauth2/revocation-endpoint";

  private final HttpClient http;
  private final URI endpoint;
  private final ClientAuthentication clientAuthentication;

  public HttpRevocationClient(HttpClient http, URI endpoint,
      ClientAuthentication clientAuthentication) {
    this.http = Objects.requireNonNull(http, "http");
    this.endpoint = EndpointSecurity.requireHttps(Objects.requireNonNull(endpoint, "endpoint"), CODE);
    this.clientAuthentication = Objects.requireNonNull(clientAuthentication, "clientAuthentication");
  }

  @Override
  public Result<Boolean, OAuth2Error> revoke(String token, TokenTypeHint hint) {
    Objects.requireNonNull(token, "token");
    Objects.requireNonNull(hint, "hint");
    Map<String, String> form = new LinkedHashMap<>();
    form.put("token", token);
    form.put("token_type_hint", hint.wire());
    return OAuth2FormPost.post(http, endpoint, form, clientAuthentication).flatMap(outcome ->
        (outcome.status() >= HttpStatus.OK.code()
            && outcome.status() < HttpStatus.MULTIPLE_CHOICES.code())
            ? Result.success(Boolean.TRUE)
            : Result.failure(new OAuth2Error.EndpointError(outcome.status())));
  }
}
