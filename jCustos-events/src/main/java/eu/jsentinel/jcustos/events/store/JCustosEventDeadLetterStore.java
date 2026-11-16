package eu.jsentinel.jcustos.events.store;

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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.List;
import java.util.Objects;

/**
 * Dead-letter store (Konzept §736): keeps structured records of envelopes that
 * failed verification, replay, sequence or producer-policy checks, for later
 * inspection and resolution.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public interface JCustosEventDeadLetterStore {

  /**
   * Stores a dead-letter record, unless an open record of the same rejection
   * is already there.
   *
   * <p>A dead-letter store keeps whole rejected envelopes, and a sender needs
   * no key to have one rejected. Implementations therefore have to bound the
   * number of open records they retain (JS-SEC-109, CWE-770) — the shipped
   * in-memory store evicts the oldest open record once its capacity is
   * reached.
   *
   * <p>Implementations may fold the record into an open record of the same
   * rejection exactly as {@link #storeOrMerge} does; the shipped stores do.
   * The id of {@code deadLetter} then never exists in the store, and a later
   * eviction can remove the record before anyone looks. This method cannot
   * tell the caller either way: a caller that needs the record standing for
   * the rejection — to show its id, to {@link #markResolved} it — calls
   * {@link #storeOrMerge} and uses the id of the record it returns.
   *
   * @param deadLetter the record
   */
  void store(JCustosEventDeadLetter deadLetter);

  /**
   * Stores a dead-letter record unless an <em>open</em> record for the same
   * rejection already exists — same envelope content and same reason — and
   * returns the record that now stands for the rejection (JS-SEC-109). This is
   * the entry point of the consume path: a captured, validly signed but
   * expired envelope can be submitted any number of times without a key, and
   * each submission would otherwise retain one more copy of it.
   *
   * <p>Equality is decided on the whole envelope, not on its id: an envelope
   * id is chosen by the sender, so a forged envelope with the id of a genuine
   * one must not be able to displace or hide it.
   *
   * <p>The {@code default} implementation scans {@link #findOpen(int)} and is
   * neither atomic nor cheap — it exists so that every implementation
   * deduplicates. Stores should override it with an indexed, atomic lookup;
   * the shipped in-memory store does.
   *
   * @param deadLetter the candidate record
   * @return {@code deadLetter} itself if it was stored, otherwise the open
   *     record it duplicates
   * @since 00.84.00
   */
  default JCustosEventDeadLetter storeOrMerge(JCustosEventDeadLetter deadLetter) {
    Objects.requireNonNull(deadLetter, "deadLetter");
    for (JCustosEventDeadLetter open : findOpen(Integer.MAX_VALUE)) {
      if (open.reason() == deadLetter.reason()
          && open.envelope().equals(deadLetter.envelope())) {
        return open;
      }
    }
    store(deadLetter);
    return deadLetter;
  }

  /**
   * @param limit the maximum number of records to return
   * @return up to {@code limit} unresolved dead letters, oldest first
   */
  List<JCustosEventDeadLetter> findOpen(int limit);

  /**
   * Marks a dead letter resolved so it no longer appears in {@link
   * #findOpen(int)}.
   *
   * @param id the dead-letter identity
   */
  void markResolved(DeadLetterId id);
}
