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
 * Client-address resolution (JS-SEC-061, CWE-348).
 * <p>
 * Behind a reverse proxy the connection peer is the proxy, not the client. The
 * {@link eu.jsentinel.jcustos.net.ClientAddressResolver} SPI decides which address
 * keys brute-force throttling, rate limiting and audit lines:
 * {@link eu.jsentinel.jcustos.net.DefaultClientAddressResolver} takes the peer
 * address, {@link eu.jsentinel.jcustos.net.TrustedProxyClientAddressResolver}
 * honours {@code X-Forwarded-For} from configured proxies only.
 *
 * @since 00.84.00
 */
package eu.jsentinel.jcustos.net;
