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
package eu.jsentinel.jcustos.demo.rest.server;

import eu.jsentinel.jcustos.bootstrap.BootstrapStateService;
import eu.jsentinel.jcustos.bootstrap.BootstrapStatus;
import eu.jsentinel.jcustos.bootstrap.CreateInitialAdminCommand;
import eu.jsentinel.jcustos.bootstrap.InitialAdminBootstrapService;
import eu.jsentinel.jcustos.bootstrap.InitialAdminCreationResult;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.NoopLoginAttemptPolicy;
import eu.jsentinel.jcustos.demo.rest.shared.DemoJson;
import eu.jsentinel.jcustos.rest.BodyRestRequest;
import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.rest.BootstrapRestStatusMapper;
import eu.jsentinel.jcustos.rest.RestClientAddress;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestResponse;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * REST handlers for {@code /api/bootstrap/*}.
 * <p>
 * The handlers never log the bootstrap token, never echo it in responses,
 * and never put it in error messages. The security decision lives in
 * {@link InitialAdminBootstrapService}; the handlers translate the result
 * to an HTTP status via {@link BootstrapRestStatusMapper}.
 */
public final class DemoBootstrapHandlers {

  private static final BootstrapRestStatusMapper STATUS_MAPPER = new BootstrapRestStatusMapper();

  /**
   * Pseudo-username used as the throttling key for the bootstrap endpoint.
   * The bootstrap flow does not have a real authenticating subject yet;
   * the throttler is keyed on the requester's address only, but the
   * username field of {@link LoginAttemptContext} must be non-null so
   * the existing {@link eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicy}
   * counter normalisation works.
   */
  static final String BOOTSTRAP_THROTTLE_KEY = "__bootstrap__";

  private final BootstrapStateService stateService;
  private final InitialAdminBootstrapService bootstrapService;
  private final LoginAttemptPolicy bootstrapAttemptPolicy;

  public DemoBootstrapHandlers(
      BootstrapStateService stateService,
      InitialAdminBootstrapService bootstrapService) {
    this(stateService, bootstrapService, NoopLoginAttemptPolicy.INSTANCE);
  }

  public DemoBootstrapHandlers(
      BootstrapStateService stateService,
      InitialAdminBootstrapService bootstrapService,
      LoginAttemptPolicy bootstrapAttemptPolicy) {
    this.stateService = stateService;
    this.bootstrapService = bootstrapService;
    this.bootstrapAttemptPolicy = Objects.requireNonNull(
        bootstrapAttemptPolicy, "bootstrapAttemptPolicy");
  }

  public void status(RestRequest request, RestResponse response) {
    BootstrapStatus snapshot = BootstrapStatus.from(stateService);
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("bootstrapRequired", snapshot.bootstrapRequired());
    payload.put("mode", snapshot.mode().name());
    response.status(HttpStatus.OK.code());
    response.body(DemoJson.encode(payload));
  }

  public void createInitialAdmin(RestRequest request, RestResponse response) {
    // JS-SEC-061 (CWE-348): resolved through the registered ClientAddressResolver.
    String clientAddress = RestClientAddress.resolve(request).orElse(null);
    LoginAttemptContext attempt = LoginAttemptContext.now(
        BOOTSTRAP_THROTTLE_KEY, clientAddress, null);

    LoginAttemptDecision throttleDecision = bootstrapAttemptPolicy.beforeAttempt(attempt);
    if (throttleDecision instanceof LoginAttemptDecision.LockedOut lockout) {
      response.header("Retry-After",
          Long.toString(Math.max(1L, lockout.remaining().toSeconds())));
      writeJson(response, HttpStatus.TOO_MANY_REQUESTS.code(), Map.of("error", "too_many_requests"));
      return;
    }

    if (!(request instanceof BodyRestRequest bodyRequest)) {
      writeJson(response, HttpStatus.BAD_REQUEST.code(), Map.of("error", "bad_request"));
      return;
    }
    Map<String, Object> body;
    try {
      body = DemoJson.decodeObject(bodyRequest.bodyAsUtf8());
    } catch (RuntimeException e) {
      writeJson(response, HttpStatus.BAD_REQUEST.code(), Map.of("error", "bad_request"));
      return;
    }
    String token = string(body, "bootstrapToken");
    String username = string(body, "username");
    String password = string(body, "password");
    String displayName = string(body, "displayName");
    String email = string(body, "email");
    if (token == null || username == null || password == null) {
      writeJson(response, HttpStatus.BAD_REQUEST.code(), Map.of("error", "bad_request"));
      return;
    }
    char[] pwd = password.toCharArray();
    InitialAdminCreationResult result = bootstrapService.createInitialAdmin(
        new CreateInitialAdminCommand(token, username, pwd, displayName, email));

    if (result instanceof InitialAdminCreationResult.Created) {
      bootstrapAttemptPolicy.recordSuccess(attempt);
    } else if (result instanceof InitialAdminCreationResult.InvalidBootstrapToken) {
      // only token-rejection counts toward brute-force throttling.
      // policy violations / bad usernames are operator errors, not attacks.
      bootstrapAttemptPolicy.recordFailure(attempt);
    }

    int status = STATUS_MAPPER.statusFor(result);
    String code = STATUS_MAPPER.errorCodeFor(result);
    Map<String, Object> payload = new LinkedHashMap<>();
    if (result instanceof InitialAdminCreationResult.Created) {
      payload.put("status", code);
    } else {
      payload.put("error", code);
      if (result instanceof InitialAdminCreationResult.PasswordPolicyViolation policy) {
        payload.put("reason", policy.reason() == null ? "" : policy.reason());
      } else if (result instanceof InitialAdminCreationResult.InvalidUsername invalid) {
        payload.put("reason", invalid.reason() == null ? "" : invalid.reason());
      }
    }
    writeJson(response, status, payload);
  }

  private static String string(Map<String, Object> body, String key) {
    Object value = body.get(key);
    return value instanceof String s ? s : null;
  }

  private static void writeJson(RestResponse response, int status, Map<String, Object> payload) {
    response.status(status);
    response.body(DemoJson.encode(payload));
  }
}
