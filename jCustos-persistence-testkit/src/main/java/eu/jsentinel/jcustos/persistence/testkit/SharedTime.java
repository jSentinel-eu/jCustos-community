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
package eu.jsentinel.jcustos.persistence.testkit;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;

import static java.util.Objects.requireNonNull;

/**
 * The time of the multi-node contract tests (JS-SEC-166): one "real" instant that the test moves,
 * and a {@link Clock} per simulated node that reads it with the node's skew. Thread-safe, so the
 * nodes can run on threads of their own.
 */
final class SharedTime {

  private final AtomicReference<Instant> now;

  SharedTime(Instant start) {
    this.now = new AtomicReference<>(requireNonNull(start, "start"));
  }

  /** @return the real time, without any skew */
  Instant now() {
    return now.get();
  }

  /** Moves the real time to {@code instant}. */
  void set(Instant instant) {
    now.set(requireNonNull(instant, "instant"));
  }

  /**
   * The clock of a node whose clock is {@code skew} ahead of the real time - behind for a
   * negative skew.
   */
  Clock node(Duration skew) {
    return new NodeClock(this, requireNonNull(skew, "skew"), ZoneOffset.UTC);
  }

  private static final class NodeClock extends Clock {
    private final SharedTime time;
    private final Duration skew;
    private final ZoneId zone;

    private NodeClock(SharedTime time, Duration skew, ZoneId zone) {
      this.time = time;
      this.skew = skew;
      this.zone = zone;
    }

    @Override
    public Instant instant() {
      return time.now().plus(skew);
    }

    @Override
    public ZoneId getZone() {
      return zone;
    }

    @Override
    public Clock withZone(ZoneId newZone) {
      return new NodeClock(time, skew, newZone);
    }
  }
}
