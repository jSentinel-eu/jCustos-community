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
package eu.jsentinel.jcustos.net.vaadin;

import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinRequestInterceptor;
import com.vaadin.flow.server.VaadinResponse;
import com.vaadin.flow.server.VaadinServiceInitListener;
import com.vaadin.flow.server.VaadinSession;

import java.io.Serial;
import java.util.Enumeration;

/**
 * Exit review RF01, test support: an application's request interceptor that refuses a request
 * by throwing - a maintenance switch, a tenant check, a rate limiter. Registered through the
 * test resource {@code META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener}; the
 * test classes come first on the class path, so it is registered before jCustos-vaadin's
 * listeners and, as Vaadin reverses the order, runs after {@link VaadinAuditCorrelation}.
 * It refuses only requests that carry {@link #REFUSE_HEADER}; every other test of the module
 * passes it untouched.
 */
public final class RefusingInterceptorServiceInitListener implements VaadinServiceInitListener {

  @Serial
  private static final long serialVersionUID = 1L;

  /** A request with this header is refused. */
  public static final String REFUSE_HEADER = "X-Jcustos-Test-Refuse";

  @Override
  public void serviceInit(ServiceInitEvent event) {
    event.addVaadinRequestInterceptor(new Refusing());
  }

  /** The refusing interceptor. */
  public static final class Refusing implements VaadinRequestInterceptor {

    @Serial
    private static final long serialVersionUID = 1L;

    @Override
    public void requestStart(VaadinRequest request, VaadinResponse response) {
      if (request == null) {
        return;
      }
      Enumeration<String> values = request.getHeaders(REFUSE_HEADER);
      if (values != null && values.hasMoreElements()) {
        throw new IllegalStateException("the application refuses the request");
      }
    }

    @Override
    public void handleException(VaadinRequest request, VaadinResponse response,
                                VaadinSession session, Exception exception) {
      // nothing to add
    }

    @Override
    public void requestEnd(VaadinRequest request, VaadinResponse response, VaadinSession session) {
      // nothing to release
    }
  }
}
