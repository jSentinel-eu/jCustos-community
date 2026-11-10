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
package eu.jsentinel.jcustos.oidc.api;

import java.net.URI;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * OIDC provider metadata from {@code .well-known/openid-configuration} (OIDC
 * Discovery 1.0 / RFC 8414, V00.78). Carries the endpoints + capabilities a
 * Relying-Party needs to wire its OAuth2 + OIDC clients. {@code issuer},
 * {@code authorizationEndpoint}, {@code tokenEndpoint} and {@code jwksUri} are
 * mandatory per spec; the rest are optional.
 *
 * <p>JS-SEC-150 (CWE-346): since 00.84.00 the record carries
 * {@code authorization_response_iss_parameter_supported} (RFC 9207 §3). An issuer that announces
 * it puts an {@code iss} parameter on every authorisation response; a relying party passes the
 * flag to {@code OAuth2ClientConfig.withExpectedIssuer(issuer, flag)} so that a response without
 * the parameter is rejected.
 *
 * @since 00.78.00
 */
public record OidcProviderMetadata(
    String issuer,
    URI authorizationEndpoint,
    URI tokenEndpoint,
    URI jwksUri,
    Optional<URI> userinfoEndpoint,
    Optional<URI> endSessionEndpoint,
    Optional<URI> introspectionEndpoint,
    Optional<URI> revocationEndpoint,
    Optional<URI> deviceAuthorizationEndpoint,
    Set<String> scopesSupported,
    Set<String> responseTypesSupported,
    Set<String> idTokenSigningAlgValuesSupported,
    boolean authorizationResponseIssParameterSupported) {

  public OidcProviderMetadata {
    Objects.requireNonNull(issuer, "issuer");
    Objects.requireNonNull(authorizationEndpoint, "authorizationEndpoint");
    Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
    Objects.requireNonNull(jwksUri, "jwksUri");
    Objects.requireNonNull(userinfoEndpoint, "userinfoEndpoint");
    Objects.requireNonNull(endSessionEndpoint, "endSessionEndpoint");
    Objects.requireNonNull(introspectionEndpoint, "introspectionEndpoint");
    Objects.requireNonNull(revocationEndpoint, "revocationEndpoint");
    Objects.requireNonNull(deviceAuthorizationEndpoint, "deviceAuthorizationEndpoint");
    scopesSupported = Set.copyOf(Objects.requireNonNull(scopesSupported, "scopesSupported"));
    responseTypesSupported =
        Set.copyOf(Objects.requireNonNull(responseTypesSupported, "responseTypesSupported"));
    idTokenSigningAlgValuesSupported = Set.copyOf(
        Objects.requireNonNull(idTokenSigningAlgValuesSupported, "idTokenSigningAlgValuesSupported"));
  }

  /**
   * The pre-00.84.00 shape, without {@code authorization_response_iss_parameter_supported}
   * (treated as {@code false}, the default of RFC 9207 §3).
   */
  public OidcProviderMetadata(
      String issuer,
      URI authorizationEndpoint,
      URI tokenEndpoint,
      URI jwksUri,
      Optional<URI> userinfoEndpoint,
      Optional<URI> endSessionEndpoint,
      Optional<URI> introspectionEndpoint,
      Optional<URI> revocationEndpoint,
      Optional<URI> deviceAuthorizationEndpoint,
      Set<String> scopesSupported,
      Set<String> responseTypesSupported,
      Set<String> idTokenSigningAlgValuesSupported) {
    this(issuer, authorizationEndpoint, tokenEndpoint, jwksUri, userinfoEndpoint, endSessionEndpoint,
        introspectionEndpoint, revocationEndpoint, deviceAuthorizationEndpoint, scopesSupported,
        responseTypesSupported, idTokenSigningAlgValuesSupported, false);
  }
}
