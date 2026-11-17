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
package eu.jsentinel.jcustos.authorization.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.NoopLoginAttemptPolicy;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.jwt.api.JwtValidator;
import eu.jsentinel.jcustos.session.NoopSessionPolicy;
import eu.jsentinel.jcustos.session.SessionPolicy;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * ER29 (CWE-459): structural guard for {@link JCustosContext#resetAll()} and
 * {@link JCustosServiceResolver#resetAll()}.
 * <p>
 * {@code resetAll()} used to clear every slot but the JWT validator, so a validator installed by
 * one test stayed active in the next and tests depended on their execution order. A hand-kept list
 * of {@code set(null)} calls drifts whenever a slot is added, so this guard reads the slots by
 * reflection instead:
 * <ul>
 *   <li>every instance slot of {@link JCustosContext} is filled, the context is reset, and it must
 *       then be indistinguishable from a freshly constructed one — for an isolated context and for
 *       the default context behind the static facade;</li>
 *   <li>every static slot of the classes {@link JCustosServiceResolver#resetAll()} is documented to
 *       clear ({@link #RESET_SCOPE}) is filled and must be empty after the reset;</li>
 *   <li>every process-wide mutable static of jCustos-core lives in one of those classes or is a
 *       documented exception ({@link #DELIBERATE_EXCEPTIONS}), so a new holder class cannot
 *       escape the reset unnoticed.</li>
 * </ul>
 * A slot of a kind the guard does not understand fails the test with instructions rather than
 * being skipped. No mocks: plain reference slots are filled with real framework types.
 */
class JCustosResetAllGuardTest {

  /** The classes whose static state {@link JCustosServiceResolver#resetAll()} clears. */
  private static final List<Class<?>> RESET_SCOPE =
      List.of(JCustosServiceResolver.class, JCustosContext.class, SubjectStores.class);

  private static final String WARN_ONCE_AUDIT = "JS-SEC-080 warn-once flag of the Noop audit "
      + "fallback and its counter: JVM-wide by design, not state of a context, re-armed only by "
      + "JCustosContext.resetNoopAuditFallbackWarning()";
  private static final String WARN_ONCE_LOGIN = "JS-SEC-124 warn-once flag of a registered "
      + "NoopLoginAttemptPolicy and its counter: JVM-wide by design, re-armed only by "
      + "JCustosContext.resetNoopLoginAttemptPolicyWarning()";
  private static final String WARN_ONCE_LOGOUT = "JS-SEC-124 warn-once flag of the Noop logout "
      + "fallback and its counter: JVM-wide by design, re-armed only by "
      + "JCustosContext.resetNoopLogoutFallbackWarning()";
  private static final String SINK_FAILURE_THROTTLE = "JS-SEC-123 count and log throttle of failed "
      + "audit-sink writes: a JVM-wide diagnostic, not configuration, so a reset must not hide "
      + "earlier failures";
  private static final String CONSTANT = "constant set or lookup table, initialised once and "
      + "never mutated";
  private static final String WARN_ONCE_CORRELATION = "R5 warn-once flag of a failing "
      + "correlation-id resolver: JVM-wide by design, like the Noop fallback warnings, so a reset "
      + "does not repeat the warning";

  /**
   * Static slots that deliberately survive {@link JCustosServiceResolver#resetAll()}, keyed by
   * {@code <binary class name>#<field>}, with the reason. A new entry needs a reason a reviewer
   * can check; {@link #everyDeliberateExceptionNamesAnExistingStaticSlot()} keeps the list from
   * going stale.
   */
  private static final Map<String, String> DELIBERATE_EXCEPTIONS = Map.ofEntries(
      Map.entry(JCustosContext.class.getName() + "#NOOP_AUDIT_WARNED", WARN_ONCE_AUDIT),
      Map.entry(JCustosContext.class.getName() + "#NOOP_AUDIT_WARNINGS", WARN_ONCE_AUDIT),
      Map.entry(JCustosContext.class.getName() + "#NOOP_LOGIN_ATTEMPT_WARNED", WARN_ONCE_LOGIN),
      Map.entry(JCustosContext.class.getName() + "#NOOP_LOGIN_ATTEMPT_WARNINGS", WARN_ONCE_LOGIN),
      Map.entry(JCustosContext.class.getName() + "#NOOP_LOGOUT_WARNED", WARN_ONCE_LOGOUT),
      Map.entry(JCustosContext.class.getName() + "#NOOP_LOGOUT_WARNINGS", WARN_ONCE_LOGOUT),
      Map.entry("eu.jsentinel.jcustos.bruteforce.LoginFailureAudit#SINK_FAILURES",
          SINK_FAILURE_THROTTLE),
      Map.entry("eu.jsentinel.jcustos.bruteforce.LoginFailureAudit#NEXT_WARNING_AT",
          SINK_FAILURE_THROTTLE),
      Map.entry("eu.jsentinel.jcustos.bruteforce.LoginFailureAudit#WARNINGS_LOGGED",
          SINK_FAILURE_THROTTLE),
      Map.entry("eu.jsentinel.jcustos.bootstrap.FileBootstrapTokenStore#OWNER_RW", CONSTANT),
      Map.entry("eu.jsentinel.jcustos.bootstrap.FileBootstrapTokenStore#GROUP_OR_OTHERS", CONSTANT),
      Map.entry("eu.jsentinel.jcustos.credential.lifecycle.CredentialLifecycleService#ALLOWED",
          CONSTANT),
      Map.entry("eu.jsentinel.jcustos.credential.abuse.InMemoryAbuseDetectionService"
          + "#VOLUME_DIMENSIONS", CONSTANT),
      Map.entry("eu.jsentinel.jcustos.audit.AuditCorrelation#RESOLVER_FAILURE_WARNED",
          WARN_ONCE_CORRELATION));

  /** Real instances for plain reference slots, keyed by the declared type of the slot. */
  private static final Map<Class<?>, Supplier<Object>> SAMPLES = Map.of(
      LoginAttemptPolicy.class, NoopLoginAttemptPolicy::new,
      SessionPolicy.class, NoopSessionPolicy::new,
      PasswordHashingService.class, PasswordHashingServices::defaults);

  /** Fill value of holder slots; type erasure lets it into any {@code AtomicReference}. */
  private static final Object SENTINEL = new Object();
  private static final String SENTINEL_KEY = "er29-reset-guard";

  /** How the guard fills and inspects a slot. */
  private enum Kind {
    REFERENCE_HOLDER, BOOLEAN_HOLDER, INT_HOLDER, LONG_HOLDER, MAP, COLLECTION,
    PLAIN_REFERENCE, PLAIN_PRIMITIVE, CONSTANT, CONTEXT, UNKNOWN
  }

  /** Reference state compared by identity, so a sentinel never equals {@code null}. */
  private record Identity(Object value) {
    @Override
    public boolean equals(Object other) {
      return other instanceof Identity that && that.value == value;
    }

    @Override
    public int hashCode() {
      return System.identityHashCode(value);
    }
  }

  @BeforeEach
  @AfterEach
  void resetDefault() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("ER29: resetAll() forgets an installed JwtValidator, on the facade and on an isolated context")
  void resetAllForgetsTheJwtValidator() {
    JwtValidator validator = compactJwt -> {
      throw new AssertionError("this validator is never called");
    };
    JCustosServiceResolver.setJwtValidator(validator);
    assertSame(validator, JCustosServiceResolver.findJwtValidator().orElseThrow());

    JCustosServiceResolver.resetAll();

    assertTrue(JCustosServiceResolver.findJwtValidator().isEmpty(),
        "a validator installed before the reset must not validate tokens after it");

    JCustosContext isolated = JCustosContext.createIsolated();
    isolated.setJwtValidator(validator);
    isolated.resetAll();
    assertTrue(isolated.findJwtValidator().isEmpty());
  }

  @Test
  @DisplayName("ER29: JCustosContext.resetAll() returns every instance slot to the fresh state")
  void contextResetAllClearsEveryInstanceSlot() throws ReflectiveOperationException {
    JCustosContext context = JCustosContext.createIsolated();
    fillResetAndCompare(context, context::resetAll);
  }

  @Test
  @DisplayName("ER29: JCustosServiceResolver.resetAll() returns the default context to the fresh state")
  void resolverResetAllClearsTheDefaultContext() throws ReflectiveOperationException {
    JCustosContext context = JCustosServiceResolver.current();
    try {
      fillResetAndCompare(context, JCustosServiceResolver::resetAll);
    } finally {
      // Never leave a sentinel in the process-wide context, even when the guard fails.
      JCustosContext fresh = new JCustosContext();
      for (Field slot : instanceSlots()) {
        restore(slot, context, snapshot(slot, fresh));
      }
    }
  }

  @Test
  @DisplayName("ER29: JCustosServiceResolver.resetAll() empties every static slot of the reset scope")
  void resolverResetAllClearsEveryStaticSlot() throws ReflectiveOperationException {
    Map<Field, Object> saved = new LinkedHashMap<>();
    try {
      for (Class<?> owner : RESET_SCOPE) {
        for (Field slot : owner.getDeclaredFields()) {
          if (!Modifier.isStatic(slot.getModifiers()) || slot.isSynthetic()
              || DELIBERATE_EXCEPTIONS.containsKey(key(slot))) {
            continue;
          }
          slot.setAccessible(true);
          switch (kindOf(slot)) {
            case CONSTANT -> {
              // a primitive, String or enum constant holds no state
            }
            case CONTEXT -> assertSame(JCustosServiceResolver.current(), slot.get(null),
                "a static JCustosContext other than the default context is not reset: " + key(slot));
            case UNKNOWN -> fail(unknownKind(slot));
            default -> {
              Object before = snapshot(slot, null);
              try {
                fill(slot, null);
              } catch (UnsupportedOperationException immutable) {
                continue; // an unmodifiable collection constant holds no state
              }
              saved.put(slot, before);
              assertFalse(isEmpty(slot), "the guard could not fill " + key(slot));
            }
          }
        }
      }
      assertTrue(saved.containsKey(SubjectStores.class.getDeclaredField("SUBJECT_STORE_REF")),
          "the guard must at least see the SubjectStores slot");

      JCustosServiceResolver.resetAll();

      List<String> leftOver = new ArrayList<>();
      for (Field slot : saved.keySet()) {
        if (!isEmpty(slot)) {
          leftOver.add(key(slot));
        }
      }
      assertEquals(List.of(), leftOver,
          "JCustosServiceResolver.resetAll() leaves these static slots populated; clear them "
              + "there, or list them in DELIBERATE_EXCEPTIONS with the reason");
    } finally {
      for (Map.Entry<Field, Object> entry : saved.entrySet()) {
        restore(entry.getKey(), null, entry.getValue());
      }
    }
  }

  @Test
  @DisplayName("ER29: every process-wide mutable slot of jCustos-core is reset or a documented exception")
  void everyMutableStaticOfCoreIsResetOrDocumented() throws Exception {
    List<Class<?>> classes = coreClasses();
    assertTrue(classes.containsAll(RESET_SCOPE), "the class scan must see the reset scope");

    List<String> uncovered = new ArrayList<>();
    for (Class<?> type : classes) {
      if (RESET_SCOPE.contains(type)) {
        continue; // filled and checked by resolverResetAllClearsEveryStaticSlot()
      }
      for (Field slot : type.getDeclaredFields()) {
        if (isProcessWideMutable(slot) && !DELIBERATE_EXCEPTIONS.containsKey(key(slot))) {
          uncovered.add(key(slot));
        }
      }
    }
    assertEquals(List.of(), uncovered,
        "process-wide mutable state outside the reset scope; clear it from "
            + "JCustosServiceResolver.resetAll() and add the class to RESET_SCOPE, or list the "
            + "slot in DELIBERATE_EXCEPTIONS with the reason");
  }

  @Test
  @DisplayName("ER29: every deliberate exception names an existing static slot")
  void everyDeliberateExceptionNamesAnExistingStaticSlot() throws ReflectiveOperationException {
    for (String key : DELIBERATE_EXCEPTIONS.keySet()) {
      String[] parts = key.split("#", 2);
      Field slot = Class.forName(parts[0], false, JCustosContext.class.getClassLoader())
          .getDeclaredField(parts[1]);
      assertTrue(Modifier.isStatic(slot.getModifiers()), key + " is not static");
      assertFalse(DELIBERATE_EXCEPTIONS.get(key).isBlank(), key + " has no reason");
    }
  }

  // ── guard mechanics ─────────────────────────────────────────────

  private static void fillResetAndCompare(JCustosContext context, Runnable reset)
      throws ReflectiveOperationException {
    JCustosContext fresh = new JCustosContext();
    List<Field> slots = instanceSlots();
    assertTrue(slots.size() > 20, "the guard must see the slots of JCustosContext, saw " + slots);
    for (Field slot : slots) {
      fill(slot, context);
      assertFalse(snapshot(slot, fresh).equals(snapshot(slot, context)),
          "the guard could not fill " + slot.getName());
    }

    reset.run();

    List<String> leftOver = new ArrayList<>();
    for (Field slot : slots) {
      if (!snapshot(slot, fresh).equals(snapshot(slot, context))) {
        leftOver.add(slot.getName());
      }
    }
    assertEquals(List.of(), leftOver,
        "resetAll() leaves these JCustosContext slots populated; clear them in "
            + "JCustosContext.resetAll()");
  }

  /** The stateful instance fields of {@link JCustosContext}. */
  private static List<Field> instanceSlots() {
    List<Field> slots = new ArrayList<>();
    for (Field slot : JCustosContext.class.getDeclaredFields()) {
      if (Modifier.isStatic(slot.getModifiers()) || slot.isSynthetic()) {
        continue;
      }
      Kind kind = kindOf(slot);
      if (kind == Kind.CONSTANT) {
        continue;
      }
      if (kind == Kind.UNKNOWN || kind == Kind.CONTEXT) {
        fail(unknownKind(slot));
      }
      slot.setAccessible(true);
      slots.add(slot);
    }
    return slots;
  }

  private static Kind kindOf(Field slot) {
    Class<?> type = slot.getType();
    if (AtomicReference.class.isAssignableFrom(type)) {
      return Kind.REFERENCE_HOLDER;
    }
    if (type == AtomicBoolean.class) {
      return Kind.BOOLEAN_HOLDER;
    }
    if (type == AtomicInteger.class) {
      return Kind.INT_HOLDER;
    }
    if (type == AtomicLong.class) {
      return Kind.LONG_HOLDER;
    }
    if (!Modifier.isFinal(slot.getModifiers())) {
      return type.isPrimitive() ? Kind.PLAIN_PRIMITIVE : Kind.PLAIN_REFERENCE;
    }
    if (Map.class.isAssignableFrom(type)) {
      return Kind.MAP;
    }
    if (Collection.class.isAssignableFrom(type)) {
      return Kind.COLLECTION;
    }
    if (type.isPrimitive() || type == String.class || type.isEnum()) {
      return Kind.CONSTANT;
    }
    if (type == JCustosContext.class) {
      return Kind.CONTEXT;
    }
    return Kind.UNKNOWN;
  }

  private static boolean isProcessWideMutable(Field slot) {
    if (!Modifier.isStatic(slot.getModifiers()) || slot.isSynthetic()) {
      return false;
    }
    Class<?> type = slot.getType();
    return !Modifier.isFinal(slot.getModifiers())
        || type.getPackageName().equals(AtomicReference.class.getPackageName())
        || Map.class.isAssignableFrom(type)
        || Collection.class.isAssignableFrom(type);
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private static void fill(Field slot, Object owner) throws IllegalAccessException {
    Object value = slot.get(owner);
    switch (kindOf(slot)) {
      case REFERENCE_HOLDER -> ((AtomicReference<Object>) value).set(SENTINEL);
      case BOOLEAN_HOLDER -> ((AtomicBoolean) value).set(!((AtomicBoolean) value).get());
      case INT_HOLDER -> ((AtomicInteger) value).incrementAndGet();
      case LONG_HOLDER -> ((AtomicLong) value).incrementAndGet();
      case MAP -> ((Map) value).put(SENTINEL_KEY, SENTINEL);
      case COLLECTION -> ((Collection) value).add(SENTINEL);
      case PLAIN_REFERENCE -> slot.set(owner, sample(slot));
      case PLAIN_PRIMITIVE -> slot.set(owner, otherPrimitive(slot, value));
      default -> fail(unknownKind(slot));
    }
  }

  /** A comparable picture of the slot's state; {@code owner} is {@code null} for statics. */
  private static Object snapshot(Field slot, Object owner) throws IllegalAccessException {
    Object value = slot.get(owner);
    return switch (kindOf(slot)) {
      case REFERENCE_HOLDER -> new Identity(((AtomicReference<?>) value).get());
      case BOOLEAN_HOLDER -> ((AtomicBoolean) value).get();
      case INT_HOLDER -> ((AtomicInteger) value).get();
      case LONG_HOLDER -> ((AtomicLong) value).get();
      case MAP -> new HashMap<>((Map<?, ?>) value);
      case COLLECTION -> new ArrayList<>((Collection<?>) value);
      case PLAIN_REFERENCE -> new Identity(value);
      case PLAIN_PRIMITIVE -> value;
      default -> throw new AssertionError(unknownKind(slot));
    };
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private static void restore(Field slot, Object owner, Object snapshot)
      throws IllegalAccessException {
    Object value = slot.get(owner);
    switch (kindOf(slot)) {
      case REFERENCE_HOLDER -> ((AtomicReference<Object>) value).set(((Identity) snapshot).value());
      case BOOLEAN_HOLDER -> ((AtomicBoolean) value).set((Boolean) snapshot);
      case INT_HOLDER -> ((AtomicInteger) value).set((Integer) snapshot);
      case LONG_HOLDER -> ((AtomicLong) value).set((Long) snapshot);
      case MAP -> {
        ((Map) value).clear();
        ((Map) value).putAll((Map) snapshot);
      }
      case COLLECTION -> {
        ((Collection) value).clear();
        ((Collection) value).addAll((Collection) snapshot);
      }
      case PLAIN_REFERENCE -> slot.set(owner, ((Identity) snapshot).value());
      case PLAIN_PRIMITIVE -> slot.set(owner, snapshot);
      default -> throw new AssertionError(unknownKind(slot));
    }
  }

  /** Whether a static slot is in its zero state: {@code null}, {@code false}, 0 or empty. */
  private static boolean isEmpty(Field slot) throws IllegalAccessException {
    Object value = slot.get(null);
    return switch (kindOf(slot)) {
      case REFERENCE_HOLDER -> ((AtomicReference<?>) value).get() == null;
      case BOOLEAN_HOLDER -> !((AtomicBoolean) value).get();
      case INT_HOLDER -> ((AtomicInteger) value).get() == 0;
      case LONG_HOLDER -> ((AtomicLong) value).get() == 0L;
      case MAP -> ((Map<?, ?>) value).isEmpty();
      case COLLECTION -> ((Collection<?>) value).isEmpty();
      case PLAIN_REFERENCE -> value == null;
      case PLAIN_PRIMITIVE -> isZero(value);
      default -> throw new AssertionError(unknownKind(slot));
    };
  }

  private static boolean isZero(Object primitive) {
    return primitive instanceof Boolean b ? !b
        : primitive instanceof Number n && n.doubleValue() == 0d;
  }

  private static Object sample(Field slot) {
    Supplier<Object> sample = SAMPLES.get(slot.getType());
    if (sample == null) {
      fail("no sample value for " + key(slot) + " of type " + slot.getType().getName()
          + "; add a real instance of that type to SAMPLES");
    }
    return sample.get();
  }

  private static Object otherPrimitive(Field slot, Object value) {
    return switch (value) {
      case Boolean b -> !b;
      case Integer i -> i + 1;
      case Long l -> l + 1L;
      default -> throw new AssertionError("the guard cannot fill " + key(slot) + " of type "
          + slot.getType().getName() + "; teach fill() or use an Atomic* holder");
    };
  }

  private static String unknownKind(Field slot) {
    return key(slot) + " (" + slot.getType().getName() + ") is a slot kind the reset guard does "
        + "not understand: teach JCustosResetAllGuardTest how to fill and inspect it and clear it "
        + "in resetAll(), or list it in DELIBERATE_EXCEPTIONS with the reason";
  }

  private static String key(Field slot) {
    return slot.getDeclaringClass().getName() + "#" + slot.getName();
  }

  /** Every class compiled into jCustos-core, loaded without running static initialisers. */
  private static List<Class<?>> coreClasses() throws Exception {
    Path root = Path.of(JCustosContext.class.getProtectionDomain().getCodeSource().getLocation()
        .toURI());
    assertTrue(Files.isDirectory(root), "expected the jCustos-core classes in a directory: " + root);
    List<String> names;
    try (Stream<Path> files = Files.walk(root)) {
      names = files
          .map(file -> root.relativize(file).toString())
          .filter(name -> name.endsWith(".class"))
          .filter(name -> !name.endsWith("module-info.class") && !name.endsWith("package-info.class"))
          .map(name -> name.substring(0, name.length() - ".class".length())
              .replace(File.separatorChar, '.'))
          .sorted()
          .toList();
    }
    List<Class<?>> classes = new ArrayList<>();
    for (String name : names) {
      classes.add(Class.forName(name, false, JCustosContext.class.getClassLoader()));
    }
    return classes;
  }
}
