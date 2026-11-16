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
package eu.jsentinel.jcustos.rest;

import org.slf4j.Logger;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

import static java.util.Objects.requireNonNull;

/**
 * A WARN line that is written at most once per interval (CWE-778, CWE-779). The REST
 * filters must survive a failing audit sink or session store - the request decision never
 * depends on them - but they used to do so without a word, or with one line per request,
 * which buries the log during an outage. The first occurrence is logged at once; further
 * ones within the interval are counted, and the next line names how many were not logged.
 *
 * <p>The detail handed to {@link #warn(String)} is written as it is: it must name types
 * and fixed facts only, never a token, a session id or text a client chose.
 */
final class RateLimitedWarning {

  private final String code;
  private final Duration interval;
  private final long intervalNanos;
  private final Logger logger;
  private final LongSupplier nanoTime;
  private final AtomicLong warned = new AtomicLong();
  private final AtomicLong suppressed = new AtomicLong();
  // Guarded by `this`.
  private boolean everWarned;
  private long lastWarnedAt;
  private long suppressedSinceLastWarning;

  /**
   * @param code     the stable {@code rest/...} code the line starts with
   * @param interval minimum time between two lines; positive
   * @param logger   the logger of the class the warning belongs to
   */
  RateLimitedWarning(String code, Duration interval, Logger logger) {
    this(code, interval, logger, System::nanoTime);
  }

  RateLimitedWarning(String code, Duration interval, Logger logger, LongSupplier nanoTime) {
    this.code = requireNonNull(code, "code must not be null");
    this.interval = requireNonNull(interval, "interval must not be null");
    if (interval.isZero() || interval.isNegative()) {
      throw new IllegalArgumentException("interval must be positive");
    }
    this.intervalNanos = interval.toNanos();
    this.logger = requireNonNull(logger, "logger must not be null");
    this.nanoTime = requireNonNull(nanoTime, "nanoTime must not be null");
  }

  /**
   * Logs {@code detail} under the code, unless a line of this warning was written less than
   * the interval ago; then the occurrence is only counted.
   *
   * @param detail what happened and what it means; types and fixed facts only
   */
  void warn(String detail) {
    long notLogged;
    synchronized (this) {
      long now = nanoTime.getAsLong();
      if (everWarned && now - lastWarnedAt < intervalNanos) {
        suppressedSinceLastWarning++;
        suppressed.incrementAndGet();
        return;
      }
      notLogged = suppressedSinceLastWarning;
      suppressedSinceLastWarning = 0;
      everWarned = true;
      lastWarnedAt = now;
    }
    warned.incrementAndGet();
    if (notLogged == 0) {
      logger.warn("{}: {}", code, detail);
    } else {
      logger.warn("{}: {} ({} further occurrences within {} were not logged.)",
          code, detail, notLogged, interval);
    }
  }

  /** @return how many lines this warning wrote */
  long warnedCount() {
    return warned.get();
  }

  /** @return how many occurrences were counted without a line */
  long suppressedCount() {
    return suppressed.get();
  }
}
