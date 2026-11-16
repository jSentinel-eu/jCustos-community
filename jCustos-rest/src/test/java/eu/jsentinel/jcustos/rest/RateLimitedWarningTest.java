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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Marker;
import org.slf4j.event.Level;
import org.slf4j.helpers.AbstractLogger;
import org.slf4j.helpers.MessageFormatter;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The rate limit of the WARN lines of the REST filters: a hand-written SLF4J logger records
 * the lines, a hand-written clock moves the time. No mocks.
 */
@DisplayName("RateLimitedWarning - one line per interval, the rest counted")
class RateLimitedWarningTest {

  /** Records the formatted message of every call. */
  static final class RecordingLogger extends AbstractLogger {
    final List<String> lines = new ArrayList<>();
    final List<Level> levels = new ArrayList<>();

    RecordingLogger() {
      this.name = "recording";
    }

    @Override protected String getFullyQualifiedCallerName() {
      return RecordingLogger.class.getName();
    }

    @Override protected void handleNormalizedLoggingCall(Level level, Marker marker,
        String messagePattern, Object[] arguments, Throwable throwable) {
      levels.add(level);
      lines.add(arguments == null || arguments.length == 0
          ? messagePattern
          : MessageFormatter.basicArrayFormat(messagePattern, arguments));
    }

    @Override public boolean isTraceEnabled() {
      return true;
    }

    @Override public boolean isTraceEnabled(Marker marker) {
      return true;
    }

    @Override public boolean isDebugEnabled() {
      return true;
    }

    @Override public boolean isDebugEnabled(Marker marker) {
      return true;
    }

    @Override public boolean isInfoEnabled() {
      return true;
    }

    @Override public boolean isInfoEnabled(Marker marker) {
      return true;
    }

    @Override public boolean isWarnEnabled() {
      return true;
    }

    @Override public boolean isWarnEnabled(Marker marker) {
      return true;
    }

    @Override public boolean isErrorEnabled() {
      return true;
    }

    @Override public boolean isErrorEnabled(Marker marker) {
      return true;
    }
  }

  @Test
  @DisplayName("the first occurrence is logged, the next ones within the interval are counted and named later")
  void oneLinePerInterval() {
    RecordingLogger logger = new RecordingLogger();
    AtomicLong now = new AtomicLong(1_000L);
    RateLimitedWarning warning = new RateLimitedWarning(
        "rest/test-failed", Duration.ofMinutes(1), logger, now::get);

    warning.warn("the store failed");
    for (int i = 0; i < 99; i++) {
      now.addAndGet(Duration.ofMillis(500).toNanos());
      warning.warn("the store failed");
    }

    assertEquals(List.of("rest/test-failed: the store failed"), logger.lines);
    assertEquals(List.of(Level.WARN), logger.levels);
    assertEquals(1L, warning.warnedCount());
    assertEquals(99L, warning.suppressedCount());

    now.addAndGet(Duration.ofMinutes(1).toNanos());
    warning.warn("the store failed");
    assertEquals(2, logger.lines.size());
    assertEquals("rest/test-failed: the store failed (99 further occurrences within PT1M were "
        + "not logged.)", logger.lines.get(1));

    now.addAndGet(Duration.ofMinutes(2).toNanos());
    warning.warn("the store failed");
    assertEquals("rest/test-failed: the store failed", logger.lines.get(2),
        "nothing was suppressed in between");
  }

  @Test
  @DisplayName("the interval must be positive")
  void intervalMustBePositive() {
    RecordingLogger logger = new RecordingLogger();
    assertThrows(IllegalArgumentException.class,
        () -> new RateLimitedWarning("rest/x", Duration.ZERO, logger));
    assertThrows(IllegalArgumentException.class,
        () -> new RateLimitedWarning("rest/x", Duration.ofSeconds(-1), logger));
    assertTrue(RestSessionRevocation.FAILURE_LOG_INTERVAL.compareTo(Duration.ZERO) > 0);
  }
}
