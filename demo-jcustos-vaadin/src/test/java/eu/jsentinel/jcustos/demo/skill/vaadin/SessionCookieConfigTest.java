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
package eu.jsentinel.jcustos.demo.skill.vaadin;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-137 (CWE-1004, CWE-614, CWE-1275): the deployment descriptor gives the session
 * cookie an application-specific name instead of the shared container default
 * {@code JSESSIONID}, and marks it HttpOnly, Secure and SameSite=Lax. The browserless
 * harness does not read {@code web.xml}, so the descriptor itself is checked - the file
 * the servlet container deploys.
 */
@DisplayName("JS-SEC-137 — the session cookie is application-specific, HttpOnly, Secure and SameSite=Lax")
class SessionCookieConfigTest {

  static final String COOKIE_NAME = "JCUSTOS_SKILL_VAADIN_SESSION";

  @Test
  @DisplayName("web.xml configures the session cookie")
  void cookieConfig() throws Exception {
    Path descriptor = Path.of("src/main/webapp/WEB-INF/web.xml");
    assertTrue(Files.isRegularFile(descriptor), "missing " + descriptor.toAbsolutePath());
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setNamespaceAware(true);
    Document document = factory.newDocumentBuilder().parse(descriptor.toFile());

    NodeList configs = document.getElementsByTagNameNS("*", "cookie-config");
    assertEquals(1, configs.getLength(), "exactly one <cookie-config>");
    Element cookie = (Element) configs.item(0);
    assertEquals(COOKIE_NAME, text(cookie, "name"));
    assertEquals("true", text(cookie, "http-only"));
    assertEquals("true", text(cookie, "secure"));
    assertEquals("SameSite", text(cookie, "attribute-name"));
    assertEquals("Lax", text(cookie, "attribute-value"));
  }

  private static String text(Element parent, String child) {
    NodeList nodes = parent.getElementsByTagNameNS("*", child);
    return nodes.getLength() == 0 ? null : nodes.item(0).getTextContent().trim();
  }
}
