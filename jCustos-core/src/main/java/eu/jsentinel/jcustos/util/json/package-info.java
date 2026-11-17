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
 * The bounded JSON reader the identity, OAuth2 and propagation modules share
 * ({@link eu.jsentinel.jcustos.util.json.BoundedJson}, JS-SEC-098, CWE-1041).
 *
 * <p>Internal to jCustos: the package is public because several modules use it, not as an API
 * for application code, and may change in any release. The release gate
 * ({@code scripts/gate.sh}, stage {@code definitions}) keeps it the only JSON reader in the
 * library modules; the event wire codec is the documented exception.
 *
 * @since 00.84.00
 */
package eu.jsentinel.jcustos.util.json;
