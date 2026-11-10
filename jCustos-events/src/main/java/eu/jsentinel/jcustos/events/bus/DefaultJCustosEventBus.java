package eu.jsentinel.jcustos.events.bus;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.api.WellFormedText;
import eu.jsentinel.jcustos.events.publisher.SignedEnvelopePublisher;
import eu.jsentinel.jcustos.events.store.JCustosEventEnvelopeStore;
import eu.jsentinel.jcustos.events.types.EnvelopeRejectedEvent;
import eu.jsentinel.jcustos.events.types.EventBusSelfObservabilityEvent;
import eu.jsentinel.jcustos.events.types.ListenerFailedEvent;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

/**
 * Default in-process {@link JCustosEventBus}. Publishing runs the
 * {@link PublishPipeline} (build + sign + replay-mark), optionally appends the
 * signed envelope to an envelope store, fans the envelope out to the
 * registered {@link SignedEnvelopePublisher} taps, then dispatches the event
 * to matching local listeners under the configured
 * {@link ListenerErrorStrategy}.
 *
 * <p>A non-critical listener failure is isolated, logged, and reported as a
 * {@link ListenerFailedEvent} dispatched directly to its listeners (never
 * re-published through the signing pipeline, so a failure in the failure event
 * cannot loop — Konzept §789). A critical listener's failure always propagates.
 *
 * <p>The bus is its own {@link EventBusObservabilityPublisher}: every
 * {@link EventBusSelfObservabilityEvent} is dispatched through
 * {@link #publishObservability(EventBusSelfObservabilityEvent)}, which never
 * touches the pipeline or the envelope store and treats listener failures as
 * log-only. A publish-side pipeline rejection additionally emits an
 * {@link EnvelopeRejectedEvent} before the {@link EventPublishException}
 * propagates unchanged.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class DefaultJCustosEventBus
    implements JCustosEventBus, EventBusObservabilityPublisher, HasLogger {

  private record Subscription(Class<? extends JCustosEvent> type,
      JCustosEventListener<? super JCustosEvent> listener,
      JCustosEventListenerOptions options) {
  }

  // Same identity trick as Subscription (R02): the wrapper record gives every
  // subscribeEnvelope() call its own entry object, so registering the same
  // (or an equal) publisher twice yields separable registrations.
  private record EnvelopePublisherEntry(SignedEnvelopePublisher publisher) {
  }

  /**
   * The envelope-publisher-failure WARN is emitted on the 1st failure and
   * every Nth failure thereafter, mirroring the SSE broadcaster's drop-log
   * policy so a persistently-failing tap cannot flood the log.
   */
  static final long ENVELOPE_PUBLISHER_FAILURE_LOG_INTERVAL = 100L;

  private final PublishPipeline publishPipeline;
  private final JCustosEventEnvelopeStore envelopeStore;
  private final ListenerErrorStrategy errorStrategy;
  private final Executor executor;
  private final Supplier<Instant> clock;
  private final List<Subscription> subscriptions = new CopyOnWriteArrayList<>();
  private final List<EnvelopePublisherEntry> envelopePublishers = new CopyOnWriteArrayList<>();
  private final AtomicLong envelopePublisherFailures = new AtomicLong();

  public DefaultJCustosEventBus(PublishPipeline publishPipeline,
      JCustosEventEnvelopeStore envelopeStore, ListenerErrorStrategy errorStrategy,
      Executor executor, Supplier<Instant> clock) {
    this.publishPipeline = Objects.requireNonNull(publishPipeline, "publishPipeline");
    this.envelopeStore = envelopeStore; // optional
    this.errorStrategy = Objects.requireNonNull(errorStrategy, "errorStrategy");
    this.executor = Objects.requireNonNull(executor, "executor");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Convenience constructor: ISOLATE_AND_CONTINUE, common-pool executor, system
   * clock, no envelope store.
   */
  public DefaultJCustosEventBus(PublishPipeline publishPipeline) {
    this(publishPipeline, null, ListenerErrorStrategy.ISOLATE_AND_CONTINUE,
        ForkJoinPool.commonPool(), Instant::now);
  }

  @Override
  public void publish(JCustosEvent event) {
    Objects.requireNonNull(event, "event");
    SignedJCustosEventEnvelope envelope;
    try {
      envelope = publishPipeline.toEnvelope(event);
    } catch (EventPublishException rejection) {
      reportPublishRejected(event, rejection.reason());
      throw rejection;
    }
    if (envelopeStore != null) {
      envelopeStore.append(envelope);
    }
    fanOutEnvelope(envelope);
    dispatch(event);
  }

  // publishAsync delegates to publish() on the executor, so a pipeline
  // rejection emits the same EnvelopeRejectedEvent there and the future
  // completes exceptionally with the unchanged EventPublishException.
  @Override
  public CompletionStage<Void> publishAsync(JCustosEvent event) {
    Objects.requireNonNull(event, "event");
    return CompletableFuture.runAsync(() -> publish(event), executor);
  }

  /**
   * Dispatches a bus self-observability event <em>directly</em> to matching
   * listeners — never through the {@link PublishPipeline}, never into the
   * envelope store (see {@link EventBusSelfObservabilityEvent}). A listener
   * failure on this path is log-only: it is never reported as a
   * {@link ListenerFailedEvent}, so observability dispatch cannot cascade.
   * Consequently this method honors the never-throws contract of
   * {@link EventBusObservabilityPublisher} for every listener, critical ones
   * included.
   */
  @Override
  public void publishObservability(EventBusSelfObservabilityEvent event) {
    Objects.requireNonNull(event, "event");
    for (Subscription subscription : subscriptions) {
      if (!subscription.type().isInstance(event)) {
        continue;
      }
      try {
        subscription.listener().onJCustosEvent(event);
      } catch (RuntimeException failure) {
        logger().warn("events/observability-listener-failed: listener {} threw on {} ({})",
            subscription.listener().getClass().getName(), event.eventType().value(),
            failure.toString());
      }
    }
  }

  @Override
  public <E extends JCustosEvent> Registration subscribe(
      Class<E> eventType, JCustosEventListener<? super E> listener) {
    return subscribe(eventType, JCustosEventListenerOptions.defaults(), listener);
  }

  @Override
  @SuppressWarnings("unchecked")
  public <E extends JCustosEvent> Registration subscribe(
      Class<E> eventType, JCustosEventListenerOptions options,
      JCustosEventListener<? super E> listener) {
    Objects.requireNonNull(eventType, "eventType");
    Objects.requireNonNull(options, "options");
    Objects.requireNonNull(listener, "listener");
    Subscription subscription = new Subscription(eventType,
        (JCustosEventListener<? super JCustosEvent>) listener, options);
    subscriptions.add(subscription);
    // R02: Subscription is a value record, so two subscribe() calls with the
    // same arguments create equal-but-distinct entries. The registration must
    // (a) remove by identity, so it can only ever detach ITS OWN entry, and
    // (b) remove at most once, so closing the same registration twice can
    // never detach an equal sibling subscription.
    AtomicBoolean closed = new AtomicBoolean();
    return () -> {
      if (closed.compareAndSet(false, true)) {
        subscriptions.removeIf(s -> s == subscription);
      }
    };
  }

  @Override
  public Registration subscribeEnvelope(SignedEnvelopePublisher publisher) {
    Objects.requireNonNull(publisher, "publisher");
    EnvelopePublisherEntry entry = new EnvelopePublisherEntry(publisher);
    envelopePublishers.add(entry);
    // Identity-based removal with a once-guard, exactly like subscribe():
    // closing this registration detaches ITS OWN entry, at most once.
    AtomicBoolean closed = new AtomicBoolean();
    return () -> {
      if (closed.compareAndSet(false, true)) {
        envelopePublishers.removeIf(e -> e == entry);
      }
    };
  }

  /**
   * @return the number of {@link SignedEnvelopePublisher} invocations that
   *     threw and were isolated, over this bus's lifetime
   */
  public long envelopePublisherFailureCount() {
    return envelopePublisherFailures.get();
  }

  // Runs after the envelope-store append and before typed dispatch. A
  // publisher failure is isolated per entry: counted, WARN-logged
  // (rate-limited), and never breaks the publish or the remaining taps.
  private void fanOutEnvelope(SignedJCustosEventEnvelope envelope) {
    for (EnvelopePublisherEntry entry : envelopePublishers) {
      try {
        entry.publisher().onEnvelope(envelope);
      } catch (RuntimeException failure) {
        long failures = envelopePublisherFailures.incrementAndGet();
        if (failures % ENVELOPE_PUBLISHER_FAILURE_LOG_INTERVAL == 1) {
          // CWE-117: the envelopeId is only validated non-blank — scrub it so
          // a hostile id cannot forge log lines. Never payload or signature
          // bytes here.
          logger().warn("events/envelope-publisher-failed: publisher {} threw on envelope {} ({})",
              entry.publisher().getClass().getName(),
              LogFieldScrubber.scrub(envelope.envelopeId().value()), failure.toString());
        }
      }
    }
  }

  private void dispatch(JCustosEvent event) {
    for (Subscription subscription : subscriptions) {
      if (!subscription.type().isInstance(event)) {
        continue;
      }
      try {
        subscription.listener().onJCustosEvent(event);
      } catch (RuntimeException failure) {
        handleListenerFailure(subscription, event, failure);
      }
    }
  }

  private void handleListenerFailure(Subscription subscription, JCustosEvent event,
      RuntimeException failure) {
    String listenerName = subscription.listener().getClass().getName();
    logger().warn("events/listener-failed: listener {} threw on {} ({})",
        listenerName, event.eventType().value(), failure.toString());

    if (subscription.options().critical() || errorStrategy == ListenerErrorStrategy.ABORT_ON_FIRST_ERROR) {
      throw failure;
    }
    // ISOLATE_AND_CONTINUE for a non-critical listener: report, do not loop.
    reportListenerFailure(listenerName, failure, event);
  }

  private void reportListenerFailure(String listenerName, RuntimeException failure,
      JCustosEvent failedOn) {
    if (failedOn instanceof EventBusSelfObservabilityEvent) {
      // Generalized recursion guard: a listener throwing on ANY observability
      // event (not just ListenerFailedEvent) must never spawn a
      // ListenerFailedEvent cascade about it.
      return;
    }
    EventMetadata meta = EventMetadata.create(TenantId.DEFAULT,
        JCustosEvent.SYSTEM_SUBJECT, clock.get(), JCustosEventSeverity.ERROR);
    publishObservability(new ListenerFailedEvent(meta, listenerName,
        failure.getClass().getSimpleName()));
  }

  // No envelope exists on the publish side — the pipeline rejected before
  // building one — so the event id doubles as the rejectedEnvelopeId (see
  // SelfObservabilityEvents). The reason comes from the exception: the
  // producer-policy denial, or (JS-SEC-111) a field that is not well-formed
  // text. In the latter case tenant and id are reported in a form that is
  // safe to carry on: the malformed value itself must not travel into
  // listeners that sign or hash the event.
  private void reportPublishRejected(JCustosEvent event, String reason) {
    boolean wellFormed = WellFormedText.isWellFormed(event.tenantId().value())
        && WellFormedText.isWellFormed(event.eventId().value());
    EventMetadata meta = EventMetadata.create(
        wellFormed ? event.tenantId() : TenantId.DEFAULT,
        JCustosEvent.SYSTEM_SUBJECT, clock.get(), JCustosEventSeverity.ERROR);
    publishObservability(new EnvelopeRejectedEvent(meta,
        wellFormed ? event.eventId().value() : "malformed", reason));
  }
}
