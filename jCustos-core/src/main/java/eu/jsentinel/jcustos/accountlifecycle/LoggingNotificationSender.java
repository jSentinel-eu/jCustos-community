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
package eu.jsentinel.jcustos.accountlifecycle;

import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Objects;

/**
 * Default {@link JCustosNotificationSender} that writes a single
 * INFO line per notification — useful for demos and tests that
 * need lifecycle flows to complete without a real mail provider.
 * <p>
 * The line format mirrors {@code LoggingAuditSink}: a stable
 * {@code NOTIFY type=…} prefix followed by key=value pairs so log
 * scrapers can pivot on the {@link JCustosNotification.Kind} and
 * the attribute keys without parsing free-form text.
 *
 * <p>Secret-bearing attribute values (the plaintext reset /
 * verification token under {@code tokenPlain}, and any key whose name
 * contains {@code token} / {@code secret} / {@code password}) are
 * <strong>redacted</strong> to {@code ***} — the shipped default must
 * never write a single-use token into a log (CWE-532, V00.75.20 R020).
 * Production deployments register their own transport.
 */
@ExperimentalJCustosApi
public final class LoggingNotificationSender implements JCustosNotificationSender {

  /** Notification stream name; route to a dedicated appender if desired. */
  public static final String NOTIFY_LOGGER_NAME =
      "eu.jsentinel.jcustos.accountlifecycle";

  private static final Logger DEFAULT_LOGGER = LoggerFactory.getLogger(NOTIFY_LOGGER_NAME);

  private final Logger logger;

  /** Uses the default {@code accountlifecycle} logger. */
  public LoggingNotificationSender() {
    this(DEFAULT_LOGGER);
  }

  /**
   * @param logger non-null target SLF4J logger
   */
  public LoggingNotificationSender(Logger logger) {
    this.logger = Objects.requireNonNull(logger, "logger must not be null");
  }

  @Override
  public void send(JCustosNotification notification) {
    if (notification == null) return;
    try {
      logger.info(format(notification));
    } catch (RuntimeException ignored) {
      // Senders must never throw.
    }
  }

  private static String format(JCustosNotification n) {
    // JS-SEC-045 (CWE-117): scrub every attacker-influenced field (subject / tenant / attribute
    // key + value) through the shared LogFieldScrubber before it enters this space-separated
    // key=value NOTIFY line — the sink's javadoc claims it "mirrors LoggingAuditSink", and this is
    // the neutralization LoggingAuditSink already applies. Without it a value containing CR/LF or a
    // bare space could forge a second NOTIFY line or an extra key=value token.
    StringBuilder sb = new StringBuilder("NOTIFY ");
    sb.append("type=").append(n.kind().name());
    sb.append(' ').append("subject=").append(LogFieldScrubber.scrub(n.subjectId().value()));
    sb.append(' ').append("tenant=").append(LogFieldScrubber.scrub(n.tenant().value()));
    for (Map.Entry<String, String> entry : n.attributes().entrySet()) {
      String key = entry.getKey();
      String value = entry.getValue();
      if (value == null) continue;
      sb.append(' ').append(LogFieldScrubber.scrub(key)).append('=')
          // JS-SEC-127 (CWE-532): one rule for what counts as a secret attribute,
          // shared with JCustosNotification.toString().
          .append(JCustosNotification.isSensitiveAttribute(key)
              ? "***" : LogFieldScrubber.scrub(value));
    }
    return sb.toString();
  }
}
