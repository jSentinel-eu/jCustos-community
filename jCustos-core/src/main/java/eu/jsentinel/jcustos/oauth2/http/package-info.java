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
/**
 * The form-{@code POST} to an OAuth2 endpoint that {@code jCustos-oauth2} and
 * {@code jCustos-propagation-oidc} share
 * ({@link eu.jsentinel.jcustos.oauth2.http.OAuth2FormPost}, JS-SEC-098, CWE-1041): client
 * authentication including the signed client assertions, time bound, response size cap and
 * transport-error mapping, on the JDK {@code HttpClient} alone.
 *
 * <p>Internal to jCustos: the package is public because several modules use it, not as an API
 * for application code, and may change in any release.
 *
 * @since 00.84.00
 */
package eu.jsentinel.jcustos.oauth2.http;
