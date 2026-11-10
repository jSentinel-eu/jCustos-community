/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
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
package eu.jsentinel.jcustos.credential;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.credential.input.PasswordInputPolicy;
import eu.jsentinel.jcustos.credential.input.PasswordInputValidator;
import eu.jsentinel.jcustos.credential.lifecycle.CredentialLifecycleService;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.password.limiter.NoLimitKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.reset.InMemoryResetTokenStore;
import eu.jsentinel.jcustos.credential.store.CredentialRecord;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.store.CredentialStore;
import eu.jsentinel.jcustos.credential.store.InMemoryCredentialStore;
import eu.jsentinel.jcustos.credential.token.TokenDigestService;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Shared wiring for the credential regression tests of V00.84.00: real stores,
 * the real hashing pipeline with a cheap PBKDF2 policy, a clock the test moves
 * by hand and an audit sink that keeps what it receives. No test double replaces
 * a framework class.
 */
public final class CredentialTestKit {

  /** Start instant of {@link #clock}. */
  public static final Instant T0 = Instant.parse("2026-11-10T10:00:00Z");

  public final InMemoryCredentialStore credentials = new InMemoryCredentialStore();
  public final InMemoryResetTokenStore resetTokens = new InMemoryResetTokenStore();
  public final PasswordHashingService hashing = PasswordHashingServices.defaults(
      fastPolicy(), NoLimitKdfExecutionLimiter.INSTANCE);
  public final PasswordInputValidator validator = new PasswordInputValidator();
  public final PasswordInputPolicy inputPolicy = PasswordInputPolicy.defaults();
  public final RecordingAudit audit = new RecordingAudit();
  public final MutableClock clock = new MutableClock(T0);
  public final TokenDigestService digests = new TokenDigestService();

  /** Lifecycle service over {@link #credentials}. */
  public CredentialLifecycleService lifecycle() {
    return lifecycle(credentials);
  }

  /** Lifecycle service over {@code store} — for tests that wrap the real store. */
  public CredentialLifecycleService lifecycle(CredentialStore store) {
    return new CredentialLifecycleService(store, audit, clock);
  }

  /** Registers a credential and returns its encoded hash. */
  public String register(String username, String password, CredentialStatus status) {
    String encoded = hashing.hash(password.toCharArray()).encodedHash();
    credentials.register(new CredentialRecord(username, encoded, status, 1L, T0, T0));
    return encoded;
  }

  public CredentialStatus status(String username) {
    return credentials.findByUsername(username).orElseThrow().status();
  }

  /** Whether {@code password} verifies against the stored hash of {@code username}. */
  public boolean passwordIs(String username, String password) {
    String stored = credentials.findByUsername(username).orElseThrow().encodedHash();
    return hashing.verify(password.toCharArray(), stored)
        instanceof CredentialVerificationResult.Verified;
  }

  private static PasswordHashPolicy fastPolicy() {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
    defaults.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    Map<String, String> min = new LinkedHashMap<>(defaults);
    min.put(Pbkdf2ParameterNames.SALT_LENGTH, "16");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(Pbkdf2ParameterNames.ITERATIONS, "2000");
    max.put(Pbkdf2ParameterNames.KEY_LENGTH, "64");
    max.put(Pbkdf2ParameterNames.SALT_LENGTH, "64");
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, defaults)
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, min)
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, max)
        .build();
  }

  /** Audit sink that keeps every event. */
  public static final class RecordingAudit implements JCustosAuditService {
    public final List<AuditEvent> events = new CopyOnWriteArrayList<>();

    @Override
    public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.copyOf(events);
    }
  }

  /** Clock that only moves when the test says so. */
  public static final class MutableClock extends Clock {
    private final AtomicReference<Instant> now;

    public MutableClock(Instant initial) {
      this.now = new AtomicReference<>(initial);
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now.get();
    }

    public void advance(Duration step) {
      now.updateAndGet(current -> current.plus(step));
    }
  }
}
