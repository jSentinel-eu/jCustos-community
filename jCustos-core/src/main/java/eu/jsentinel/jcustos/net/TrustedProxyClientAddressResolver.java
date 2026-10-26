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
package eu.jsentinel.jcustos.net;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Resolves the client address behind one or more reverse proxies
 * (JS-SEC-061, CWE-348).
 * <p>
 * Only {@code X-Forwarded-For} is consulted, and only when the connection
 * peer is one of the configured trusted proxies. RFC 7239 {@code Forwarded},
 * {@code X-Real-IP}, {@code X-Client-IP} and similar headers are ignored
 * regardless of the peer: a proxy that does not rewrite them lets the client
 * choose its own address.
 * <p>
 * The header is read from the right, which is where each proxy appends the
 * address it saw. Entries that are themselves trusted proxies are skipped, so
 * a chain of trusted hops yields the first address outside the trusted set.
 * Whatever a client sent in its own {@code X-Forwarded-For} sits further left
 * and is never reached. When the peer is not trusted, or the proxy appended
 * something that is not an IP literal, the peer address is returned and a
 * warning is logged once per resolver instance.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class TrustedProxyClientAddressResolver implements ClientAddressResolver, HasLogger {

  /** The only header this resolver reads. */
  public static final String X_FORWARDED_FOR = "X-Forwarded-For";

  private final List<AddressRange> trustedPeers;
  private final AtomicBoolean untrustedPeerWarned = new AtomicBoolean();
  private final AtomicBoolean malformedEntryWarned = new AtomicBoolean();

  /**
   * @param trustedPeers proxy addresses or CIDR ranges; at least one
   * @throws IllegalArgumentException when empty or when an entry is not an IP literal or CIDR range
   */
  public TrustedProxyClientAddressResolver(Collection<String> trustedPeers) {
    Objects.requireNonNull(trustedPeers, "trustedPeers");
    if (trustedPeers.isEmpty()) {
      throw new IllegalArgumentException("at least one trusted proxy is required");
    }
    List<AddressRange> parsed = new ArrayList<>(trustedPeers.size());
    for (String peer : trustedPeers) {
      parsed.add(AddressRange.parse(Objects.requireNonNull(peer, "trusted proxy")));
    }
    this.trustedPeers = List.copyOf(parsed);
  }

  @Override
  public Optional<String> resolve(ClientRequestView request) {
    Objects.requireNonNull(request, "request");
    Optional<InetAddress> peer = IpLiterals.parse(request.remoteAddress());
    if (peer.isEmpty()) {
      return DefaultClientAddressResolver.INSTANCE.resolve(request);
    }
    String peerAddress = peer.get().getHostAddress();
    if (!isTrusted(peer.get())) {
      if (untrustedPeerWarned.compareAndSet(false, true)) {
        logger().warn("Client address taken from the connection peer {}: it is not a configured "
            + "trusted proxy, so X-Forwarded-For is ignored. Add the proxy to the trusted peers "
            + "if its header should be honoured (JS-SEC-061).", peerAddress);
      }
      return Optional.of(peerAddress);
    }
    List<String> hops = forwardedFor(request);
    if (hops.isEmpty()) {
      return Optional.of(peerAddress);
    }
    for (int i = hops.size() - 1; i >= 0; i--) {
      Optional<InetAddress> hop = IpLiterals.parse(hops.get(i));
      if (hop.isEmpty()) {
        if (malformedEntryWarned.compareAndSet(false, true)) {
          logger().warn("Client address taken from the connection peer {}: trusted proxy appended "
              + "an X-Forwarded-For entry that is not an IP literal (JS-SEC-061).", peerAddress);
        }
        return Optional.of(peerAddress);
      }
      if (!isTrusted(hop.get())) {
        return Optional.of(hop.get().getHostAddress());
      }
    }
    // every hop is a trusted proxy: the request originated inside the trusted set
    return IpLiterals.parse(hops.get(0)).map(InetAddress::getHostAddress);
  }

  private boolean isTrusted(InetAddress address) {
    for (AddressRange range : trustedPeers) {
      if (range.contains(address)) {
        return true;
      }
    }
    return false;
  }

  private static List<String> forwardedFor(ClientRequestView request) {
    List<String> hops = new ArrayList<>();
    for (String headerValue : request.headers(X_FORWARDED_FOR)) {
      if (headerValue == null) {
        continue;
      }
      for (String entry : headerValue.split(",")) {
        String trimmed = entry.trim();
        if (!trimmed.isEmpty()) {
          hops.add(trimmed);
        }
      }
    }
    return hops;
  }

  @Override
  public String toString() {
    return "TrustedProxyClientAddressResolver" + trustedPeers;
  }
}
