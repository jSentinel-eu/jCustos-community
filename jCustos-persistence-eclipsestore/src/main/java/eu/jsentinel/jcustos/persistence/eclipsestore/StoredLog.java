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
package eu.jsentinel.jcustos.persistence.eclipsestore;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * A persistent append-only sequence whose appends write the last chunk only
 * (JS-SEC-125, CWE-770, CWE-400) — the shape of the audit store, which is
 * appended to, read in order and trimmed at the old end, but never looked up
 * by key.
 *
 * <p>The elements live in chunks of {@value #CHUNK_SIZE}. An append stores
 * the last chunk; every {@value #CHUNK_SIZE}th append also stores the list of
 * chunks. Until 00.84.00 every append rewrote one map over all elements.</p>
 *
 * <p>A stored type: its name and its non-transient field are part of the
 * stored format.</p>
 *
 * <p>Like {@link StoredTable} the log does not write itself: it reports what
 * has to be stored to the sink handed to {@link #attach}. Readers hold the
 * storage's read lock, writers the write lock.</p>
 *
 * @param <E> element type
 */
final class StoredLog<E> {

  /** Elements per chunk; an append writes at most this many references. */
  static final int CHUNK_SIZE = 256;

  private final ArrayList<ArrayList<E>> chunks = new ArrayList<>();

  private transient Consumer<Object> changed;
  private transient int size;

  StoredLog() {
  }

  /** Builds the working state; called once per opened storage before the log is used. */
  void attach(Consumer<Object> changedSink) {
    this.changed = changedSink;
    int count = 0;
    for (ArrayList<E> chunk : chunks) {
      count += chunk.size();
    }
    this.size = count;
  }

  int size() {
    return size;
  }

  void append(E element) {
    ArrayList<E> last = chunks.isEmpty() ? null : chunks.get(chunks.size() - 1);
    if (last == null || last.size() >= CHUNK_SIZE) {
      last = new ArrayList<>(CHUNK_SIZE);
      chunks.add(last);
      changed.accept(chunks);
    }
    last.add(element);
    changed.accept(last);
    size++;
  }

  /** @return the elements in append order; a live view for the holder of a lock */
  Iterable<E> elements() {
    return () -> new Iterator<>() {
      private int chunk;
      private int position;

      @Override
      public boolean hasNext() {
        while (chunk < chunks.size() && position >= chunks.get(chunk).size()) {
          chunk++;
          position = 0;
        }
        return chunk < chunks.size();
      }

      @Override
      public E next() {
        if (!hasNext()) {
          throw new NoSuchElementException();
        }
        return chunks.get(chunk).get(position++);
      }
    };
  }

  /** @return number of elements removed because {@code filter} accepted them */
  int removeIf(Predicate<E> filter) {
    int removed = 0;
    boolean chunkDropped = false;
    Iterator<ArrayList<E>> all = chunks.iterator();
    while (all.hasNext()) {
      ArrayList<E> chunk = all.next();
      int before = chunk.size();
      if (chunk.removeIf(filter)) {
        removed += before - chunk.size();
        if (chunk.isEmpty()) {
          all.remove();
          chunkDropped = true;
        } else {
          changed.accept(chunk);
        }
      }
    }
    if (chunkDropped) {
      changed.accept(chunks);
    }
    size -= removed;
    return removed;
  }
}
