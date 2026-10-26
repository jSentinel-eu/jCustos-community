/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.dx.vaadin.routes;

import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStore;

import java.util.Objects;
import eu.jsentinel.jcustos.components.SecuredVisibility.Requirement;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Static holder that the V00.73 Vaadin bootstrap uses to publish the
 * configured {@link SessionStore} and the optional revoke callback
 * for {@link SessionManagementRoute} to read at route construction
 * time (Vaadin instantiates {@code @Route} classes via their no-arg
 * constructor).
 *
 * <p>Package-private accessors are used by
 * {@link SessionManagementRoute}; the {@code set...} methods are
 * called from the bootstrap implementation.
 *
 * <p><strong>Thread-safety.</strong> The holder is process-wide.
 * A second bootstrap call replaces the previous configuration —
 * matches the "single-use builder" contract on
 * {@code VaadinJCustosBootstrapImpl}.
 *
 * <p><strong>Access requirement (JS-SEC-068, CWE-306).</strong> Since
 * 00.84.00 the holder also carries the {@link Requirement} a subject
 * must satisfy to open {@link SessionManagementRoute} and to revoke
 * from it. {@link SessionManagementAccess} evaluates it on
 * navigation; without a published requirement the route denies
 * everyone.
 *
 * @since 00.73.00
 */
public final class SessionManagementContext {

  private static final AtomicReference<SessionStore> STORE = new AtomicReference<>();
  private static final AtomicReference<Consumer<SessionRecord>> REVOKE = new AtomicReference<>();
  private static final AtomicReference<Requirement> REQUIREMENT = new AtomicReference<>();

  private SessionManagementContext() {
    throw new AssertionError("no instances");
  }

  /**
   * Publishes the SessionStore + optional revoke callback that
   * {@link SessionManagementRoute} should consume.
   *
   * @param store  the configured SessionStore; never {@code null}
   * @param revoke revoke handler; {@code null} → drop-from-store on revoke
   */
  public static void publish(SessionStore store, Consumer<SessionRecord> revoke) {
    publish(store, revoke, null);
  }

  /**
   * Publishes the SessionStore, the optional revoke callback and the
   * access requirement that {@link SessionManagementRoute} enforces.
   *
   * @param store       the configured SessionStore; never {@code null}
   * @param revoke      revoke handler; {@code null} → drop-from-store on revoke
   * @param requirement roles and permissions a subject needs to open the
   *                    route and to revoke; {@code null} or empty publishes
   *                    no requirement, and the route then denies every
   *                    subject (JS-SEC-068)
   * @since 00.84.00
   */
  public static void publish(SessionStore store, Consumer<SessionRecord> revoke,
                             Requirement requirement) {
    STORE.set(Objects.requireNonNull(store, "store"));
    REVOKE.set(revoke);
    REQUIREMENT.set(requirement == null || requirement.isEmpty() ? null : requirement);
  }

  /** Test helper: reset the holder. */
  public static void reset() {
    STORE.set(null);
    REVOKE.set(null);
    REQUIREMENT.set(null);
  }

  static Optional<SessionStore> store() {
    return Optional.ofNullable(STORE.get());
  }

  /**
   * @return the published access requirement, or empty when the bootstrap
   *     published none — in which case the route denies everyone
   * @since 00.84.00
   */
  public static Optional<Requirement> requirement() {
    return Optional.ofNullable(REQUIREMENT.get());
  }

  static Consumer<SessionRecord> revoke() {
    Consumer<SessionRecord> registered = REVOKE.get();
    return registered != null ? registered : SessionManagementContext::dropFromStore;
  }

  private static void dropFromStore(SessionRecord record) {
    store().ifPresent(s -> s.delete(record.sessionId()));
  }
}
