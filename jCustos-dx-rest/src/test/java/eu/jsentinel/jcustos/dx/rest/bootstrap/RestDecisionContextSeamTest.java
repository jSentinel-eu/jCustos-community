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
package eu.jsentinel.jcustos.dx.rest.bootstrap;

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.logout.SubjectClearingLogoutService;
import eu.jsentinel.jcustos.rest.HttpStatusDecisionMapper;
import eu.jsentinel.jcustos.rest.RestDecisionContext;
import eu.jsentinel.jcustos.rest.RestHeaders;
import eu.jsentinel.jcustos.rest.RestResponse;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import eu.jsentinel.jcustos.test.InMemorySubjectStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * JS-SEC-086 follow-up: {@link RestDecisionContext#mapperOrDefault()} is public, so code
 * outside {@code eu.jsentinel.jcustos.rest} - a login handler, an adapter of its own, the
 * enterprise bridge - renders a refusal through the same seam as the REST filters instead of
 * repeating {@code mapper().orElseGet(HttpStatusDecisionMapper::new)}. This test lives in
 * another package on purpose: it compiles only against the public method.
 */
@DisplayName("RestDecisionContext.mapperOrDefault() - the public rendering seam")
class RestDecisionContextSeamTest {

  @BeforeEach
  @AfterEach
  void reset() {
    RestDecisionContext.reset();
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("without a bootstrap: the HttpStatusDecisionMapper default, 401 with the Bearer challenge")
  void withoutBootstrap_defaultMapper() {
    assertEquals(Optional.empty(), RestDecisionContext.mapper());
    assertInstanceOf(HttpStatusDecisionMapper.class, RestDecisionContext.mapperOrDefault());

    Recording response = new Recording();
    RestDecisionContext.mapperOrDefault()
        .apply(AuthorizationDecision.unauthenticated("invalid-credentials"), response);

    assertEquals(HttpStatus.UNAUTHORIZED.code(), response.status);
    assertEquals(HttpStatusDecisionMapper.BEARER_CHALLENGE,
        response.headers.get(RestHeaders.WWW_AUTHENTICATE));
  }

  @Test
  @DisplayName("after the bootstrap: the published mapper, with the configured problem+json body")
  void afterBootstrap_publishedMapper() {
    RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(request -> Optional.empty())
        .errorBodies(ProblemJsonErrorBodyStrategy.INSTANCE)
        .audit(a -> a.logging())
        .logout(new SubjectClearingLogoutService<>(new InMemorySubjectStore(), String.class))
        .install();

    assertSame(RestDecisionContext.mapper().orElseThrow(), RestDecisionContext.mapperOrDefault());
    Recording response = new Recording();
    RestDecisionContext.mapperOrDefault()
        .apply(AuthorizationDecision.unauthenticated("invalid-credentials"), response);

    assertEquals(HttpStatus.UNAUTHORIZED.code(), response.status);
    assertEquals("{\"type\":\"about:blank\",\"title\":\"Unauthorized\",\"status\":401}", response.body);
    assertEquals(HttpStatusDecisionMapper.BEARER_CHALLENGE,
        response.headers.get(RestHeaders.WWW_AUTHENTICATE));
  }

  private static final class Recording implements RestResponse {
    int status = HttpStatus.OK.code();
    String body;
    final Map<String, String> headers = new LinkedHashMap<>();

    @Override
    public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override
    public void body(String body) {
      this.body = body;
    }

    @Override
    public void header(String name, String value) {
      headers.put(name, value);
    }
  }
}
