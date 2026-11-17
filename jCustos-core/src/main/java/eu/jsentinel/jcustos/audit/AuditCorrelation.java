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
   * {@code audit/correlation-resolver-failure}.
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

  private static String resolve(ClientRequestView request) {
    String resolved;
    try {
      resolved = JCustosServiceResolver.correlationIdResolver().resolve(request);
    } catch (RuntimeException resolverFailure) {
      warnResolverFailure("threw " + resolverFailure.getClass().getName());
      return newId();
    }
    if (!AuditEnvelope.isValidCorrelationId(resolved)) {
      // the value itself is not logged: it may be taken from a request header
      warnResolverFailure("returned a malformed id");
      return newId();
    }
    return resolved;
  }

  private static void warnResolverFailure(String what) {
    if (RESOLVER_FAILURE_WARNED.compareAndSet(false, true)) {
      HasLogger.staticLogger().warn("audit/correlation-resolver-failure: the correlation-id "
          + "resolver {} {}; audit events of such requests carry a server-side UUID instead "
          + "(reported once per JVM)", resolverName(), what);
    }
  }

  private static String resolverName() {
    try {
      return JCustosServiceResolver.correlationIdResolver().getClass().getName();
    } catch (RuntimeException unavailable) {
      return "(unavailable)";
    }
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
