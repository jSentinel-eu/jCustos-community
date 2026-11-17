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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.net.EndpointSecurity;

import java.net.URI;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * Builds a TLS-1.3 {@link SSLContext} that presents a client certificate for OAuth2
 * mutual-TLS client authentication (V00.79, RFC 8705), and remaps endpoints to their
 * {@code mtls_endpoint_aliases} (RFC 8705 §5) when the provider supplies them. The
 * resulting {@code SSLContext} is handed to {@code HttpClient.newBuilder().sslContext(…)}
 * and that client to {@code HttpTokenEndpointClient}.
 *
 * <p><strong>Protocol pinning:</strong> the context is created with {@code "TLSv1.3"} so
 * TLS 1.3 is negotiated, but an {@code SSLContext} alone does not disable a 1.2 fallback —
 * to forbid downgrade entirely, pin {@code SSLParameters.setProtocols("TLSv1.3")} on the
 * {@code HttpClient} ({@code .sslParameters(...)}) / socket. See {@code mtls-setup.md}.
 *
 * @since 00.79.20
 */
@ExperimentalJCustosApi
public final class MutualTls {

  private MutualTls() {
  }

  /** {@link SSLContext} (TLS 1.3) presenting the client key, trusting the JVM default trust store. */
  public static SSLContext sslContext(MutualTlsClientConfig config) {
    return sslContext(config, null);
  }

  /**
   * {@link SSLContext} (TLS 1.3) presenting the client key from {@code config} and trusting
   * {@code trustStore} (or the JVM default when {@code null}). Pin {@code enabledProtocols}
   * to {@code TLSv1.3} on the socket / {@code HttpClient} to forbid a 1.2 downgrade.
   *
   * @throws IllegalStateException if the keystore holds no key entry under the alias
   *                               ({@code oauth2/mtls-keystore-empty})
   */
  public static SSLContext sslContext(MutualTlsClientConfig config, KeyStore trustStore) {
    Objects.requireNonNull(config, "config");
    requireKeyEntry(config);
    char[] password = config.password();
    try {
      KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(config.keyStore(), password);
      TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      tmf.init(trustStore); // null → JVM default trust store
      SSLContext ctx = SSLContext.getInstance("TLSv1.3");
      ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
      return ctx;
    } catch (Exception e) {
      throw new IllegalStateException("failed to build mTLS SSLContext", e);
    } finally {
      java.util.Arrays.fill(password, '\0');
    }
  }

  private static void requireKeyEntry(MutualTlsClientConfig config) {
    try {
      if (!config.keyStore().isKeyEntry(config.alias())) {
        throw new IllegalStateException(
            "oauth2/mtls-keystore-empty: no client key entry under alias '" + config.alias() + "'");
      }
    } catch (KeyStoreException e) {
      throw new IllegalStateException("oauth2/mtls-keystore-empty: keystore is not initialised", e);
    }
  }

  /**
   * Returns the {@code mtls_endpoint_aliases} override for {@code endpointName} (e.g.
   * {@code "token_endpoint"}) when the provider published one, else {@code fallback}
   * (RFC 8705 §5). A mTLS client MUST use the aliased endpoint when present. The aliased
   * URI is https-enforced: a tampered discovery document cannot redirect the
   * client-certificate-bearing request to a plaintext / attacker endpoint.
   */
  public static URI endpointAlias(Map<String, URI> mtlsEndpointAliases, String endpointName, URI fallback) {
    Objects.requireNonNull(endpointName, "endpointName");
    Objects.requireNonNull(fallback, "fallback");
    URI alias = Optional.ofNullable(mtlsEndpointAliases).map(m -> m.get(endpointName)).orElse(null);
    if (alias == null) {
      return fallback;
    }
    return EndpointSecurity.requireHttps(alias, "oauth2/mtls-alias-not-https");
  }
}
