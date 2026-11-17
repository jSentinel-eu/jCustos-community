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
package eu.jsentinel.jcustos.audit;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.net.ClientRequestView;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Carries the correlation id of the request the current thread works for
 * (R5, JS-SEC-066, CWE-778), so audit records and audit lines can name it
 * without every producer of an {@link AuditEvent} passing it along.
 * <p>
 * The web adapters open a {@link Scope} when a request starts and close it
 * when it ends: {@code VaadinAuditCorrelation} as a Vaadin request
 * interceptor, {@code RestAuditCorrelation} around the REST filters.
 * {@link StoreBackedJCustosAuditService} hands {@link #current()} to the
 * {@link AuditEventStore}, {@link LoggingAuditSink} appends it to the line as
 * {@code corr=}. Outside a scope — background threads, schedulers,
 * {@code UI.access} from a foreign thread, standalone applications —
 * {@link #current()} is empty and no id is invented.
 * <p>
 * A thread-local and not a {@code ScopedValue}: the Vaadin interceptor is
 * called at the start and at the end of a request and does not wrap the
 * call in between. Scopes nest; closing one restores the value that was
 * current when it was opened. A scope must be closed on the thread that
 * opened it, in a {@code finally} block or through try-with-resources.
 * {@code JCustosServiceResolver.resetAll()} ends every scope of the calling
 * thread ({@link #resetCurrentThread()}), so a scope a test leaves open does
 * not hand its id to the next test on the same thread.
 *
 * @since 00.84.00
 */
@ExperimentalJCustosApi
public final class AuditCorrelation {

  /** The innermost open scope of the thread, or {@code null}. */
  private static final ThreadLocal<Scope> CURRENT = new ThreadLocal<>();

  /**
   * One warning per JVM when a correlation-id resolver fails or returns a
   * malformed id; every further request falls back to a UUID silently.
   */
  private static final AtomicBoolean RESOLVER_FAILURE_WARNED = new AtomicBoolean(false);

  private static final String RESOLVER_FAILURE_WARNING = "audit/correlation-resolver-failure: "
      + "the correlation-id resolver {} {}; audit events of such requests carry a server-side "
      + "UUID instead (reported once per JVM)";

  private AuditCorrelation() {
  }

  /**
   * The correlation id of the innermost open scope of this thread.
   *
   * @return the id, or empty outside a request
   */
  public static Optional<String> current() {
    Scope scope = CURRENT.get();
    return scope == null ? Optional.empty() : Optional.of(scope.correlationId);
  }

  /**
   * Opens a scope for {@code correlationId} on the calling thread. It stays
   * current until it is closed or a nested scope is opened.
   *
   * @param correlationId a value that passes
   *                      {@link AuditEnvelope#isValidCorrelationId(String)}
   * @return the scope; close it on this thread
   * @throws NullPointerException     when {@code correlationId} is {@code null}
   * @throws IllegalArgumentException when it is malformed
   */
  public static Scope open(String correlationId) {
    Objects.requireNonNull(correlationId, "correlationId");
    if (!AuditEnvelope.isValidCorrelationId(correlationId)) {
      throw new IllegalArgumentException("correlationId must be 1 to "
          + AuditEnvelope.MAX_CORRELATION_ID_LENGTH + " characters from [A-Za-z0-9._:-]");
    }
    Scope scope = new Scope(correlationId, CURRENT.get(), Thread.currentThread());
    CURRENT.set(scope);
    return scope;
  }

  /**
   * Resolves the correlation id of a request through
   * {@link JCustosServiceResolver#correlationIdResolver()} and opens a scope
   * for it. Never fails for a misbehaving resolver: one that throws or returns
   * a malformed id is replaced by {@link #newId()} and reported once per JVM as
   * {@code audit/correlation-resolver-failure}. So is a resolver that cannot be
   * looked up - more than one registered through {@code META-INF/services};
   * the warning then names the registered implementations.
   *
   * @param request the request the scope stands for
   * @return the scope; close it on this thread
   */
  public static Scope openFor(ClientRequestView request) {
    Objects.requireNonNull(request, "request");
    return open(resolve(request));
  }

  /**
   * A fresh server-side correlation id: a random UUID, the same form as the
   * event-bus {@code CorrelationId.random()}.
   *
   * @return a well-formed correlation id
   */
  public static String newId() {
    return UUID.randomUUID().toString();
  }

  /**
   * Ends every scope of the calling thread and leaves it without a correlation
   * id (exit review RF21, ER29, CWE-459). Called by
   * {@code JCustosServiceResolver.resetAll()}: a scope a test left open - or a
   * request whose end was never signalled - must not lend its id to whatever
   * the thread does next. The scopes count as closed afterwards; closing one of
   * them again has no effect. Other threads are not touched.
   */
  public static void resetCurrentThread() {
    for (Scope scope = CURRENT.get(); scope != null; scope = scope.previous) {
      scope.closed = true;
    }
    CURRENT.remove();
  }

  private static String resolve(ClientRequestView request) {
    CorrelationIdResolver resolver;
    try {
      resolver = JCustosServiceResolver.correlationIdResolver();
    } catch (RuntimeException lookupFailure) {
      // RF22: more than one registration; the message names the implementations and
      // nothing of the request
      warnResolverFailure("audit/correlation-resolver-failure: no correlation-id resolver can "
          + "be resolved ({}); audit events carry a server-side UUID instead (reported once per "
          + "JVM)", LogFieldScrubber.scrubMessage(String.valueOf(lookupFailure.getMessage())));
      return newId();
    }
    String resolved;
    try {
      resolved = resolver.resolve(request);
    } catch (RuntimeException resolverFailure) {
      warnResolverFailure(RESOLVER_FAILURE_WARNING, resolver.getClass().getName(),
          "threw " + resolverFailure.getClass().getName());
      return newId();
    }
    if (!AuditEnvelope.isValidCorrelationId(resolved)) {
      // the value itself is not logged: it may be taken from a request header
      warnResolverFailure(RESOLVER_FAILURE_WARNING, resolver.getClass().getName(),
          "returned a malformed id");
      return newId();
    }
    return resolved;
  }

  private static void warnResolverFailure(String format, Object... arguments) {
    if (RESOLVER_FAILURE_WARNED.compareAndSet(false, true)) {
      HasLogger.staticLogger().warn(format, arguments);
    }
  }

  /** Re-arms the once-per-JVM warning; for the tests of this package only. */
  static void resetResolverFailureWarning() {
    RESOLVER_FAILURE_WARNED.set(false);
  }

  /**
   * An open correlation scope. Closing it restores the value that was current
   * when it was opened; closing it twice has no effect. Closing an enclosing
   * scope first also ends the scopes opened inside it.
   */
  public static final class Scope implements AutoCloseable {

    private final String correlationId;
    private final Scope previous;
    private final Thread owner;
    private boolean closed;

    private Scope(String correlationId, Scope previous, Thread owner) {
      this.correlationId = correlationId;
      this.previous = previous;
      this.owner = owner;
    }

    /**
     * The id this scope makes current.
     *
     * @return the correlation id
     */
    public String correlationId() {
      return correlationId;
    }

    /**
     * Whether the scope is still open: neither closed itself, nor ended by
     * closing an enclosing scope, nor by {@link #resetCurrentThread()}. Meant
     * for the thread that opened it.
     *
     * @return {@code true} while the scope is open
     */
    public boolean isOpen() {
      return !closed;
    }

    @Override
    public void close() {
      if (closed) {
        return;
      }
      Scope top = CURRENT.get();
      boolean onStack = false;
      for (Scope scope = top; scope != null; scope = scope.previous) {
        if (scope == this) {
          onStack = true;
          break;
        }
      }
      if (!onStack) {
        if (Thread.currentThread() != owner) {
          HasLogger.staticLogger().warn("audit/correlation-scope-foreign-thread: a correlation "
              + "scope was closed on a thread that did not open it; the opening thread keeps "
              + "its correlation id until it closes the scope itself");
          return;
        }
        // an enclosing scope was closed first and ended this one with it
        closed = true;
        return;
      }
      for (Scope scope = top; scope != this; scope = scope.previous) {
        scope.closed = true;
      }
      closed = true;
      if (previous == null) {
        CURRENT.remove();
      } else {
        CURRENT.set(previous);
      }
    }
  }
}
