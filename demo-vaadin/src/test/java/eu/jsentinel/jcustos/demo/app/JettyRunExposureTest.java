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
package eu.jsentinel.jcustos.demo.app;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-137 (CWE-1188, CWE-319): {@code jetty:run} listens on the loopback interface
 * unless {@value #HOST_PROPERTY} names another address. Starting the Jetty Maven plugin
 * is not practical in a unit test, so the build file it reads is checked: the plugin's
 * single connector takes its host from that property, the property defaults to a
 * loopback literal, and the connector has an explicit port - a connector configured
 * without one listens on a random port. A {@code -D} value on the command line
 * overrides the property.
 */
@DisplayName("JS-SEC-137 — jetty:run listens on the loopback interface by default")
class JettyRunExposureTest {

  static final String HOST_PROPERTY = "jcustos.demo.http.host";

  private static final String JETTY_PLUGIN = "jetty-ee11-maven-plugin";
  private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{([^}]+)}");

  @Test
  @DisplayName("the Jetty connector binds to a loopback address unless jcustos.demo.http.host says otherwise")
  void connectorBindsToLoopback() throws Exception {
    Path pomFile = Path.of("pom.xml");
    assertTrue(Files.isRegularFile(pomFile), "missing " + pomFile.toAbsolutePath());
    Document pom = parse(pomFile);

    List<Element> plugins = descendants(pom.getDocumentElement(), "plugin").stream()
        .filter(plugin -> JETTY_PLUGIN.equals(text(plugin, "artifactId")))
        .toList();
    assertEquals(1, plugins.size(), "exactly one " + JETTY_PLUGIN + " declaration");
    Element configuration = child(plugins.getFirst(), "configuration");
    assertNotNull(configuration, JETTY_PLUGIN + " must be configured");
    assertTrue(children(configuration, "jettyXml").isEmpty()
            && children(configuration, "jettyXmls").isEmpty(),
        "a Jetty XML file could add a connector on every interface");
    List<Element> connectors = children(configuration, "httpConnector");
    assertEquals(1, connectors.size(), "exactly one <httpConnector>");
    Element connector = connectors.getFirst();

    assertEquals("${" + HOST_PROPERTY + "}", text(connector, "host"),
        "the host must come from the documented property");
    String host = property(pom, HOST_PROPERTY);
    assertNotNull(host, "the POM must define " + HOST_PROPERTY);
    assertTrue(InetAddress.ofLiteral(host).isLoopbackAddress(),
        HOST_PROPERTY + " must default to a loopback literal, not " + host);

    String port = resolve(pom, text(connector, "port"));
    assertNotNull(port, "the connector needs an explicit port");
    assertTrue(Integer.parseInt(port) > 0, "port " + port);
  }

  private static Document parse(Path file) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setNamespaceAware(true);
    return factory.newDocumentBuilder().parse(file.toFile());
  }

  /** A {@code ${name}} value is looked up among the POM's own properties. */
  private static String resolve(Document pom, String value) {
    if (value == null) {
      return null;
    }
    Matcher placeholder = PLACEHOLDER.matcher(value);
    return placeholder.matches() ? property(pom, placeholder.group(1)) : value;
  }

  private static String property(Document pom, String name) {
    Element properties = child(pom.getDocumentElement(), "properties");
    return properties == null ? null : text(properties, name);
  }

  private static String text(Element parent, String name) {
    Element element = child(parent, name);
    return element == null ? null : element.getTextContent().trim();
  }

  private static Element child(Element parent, String name) {
    List<Element> matches = children(parent, name);
    return matches.isEmpty() ? null : matches.getFirst();
  }

  private static List<Element> children(Element parent, String name) {
    List<Element> matches = new ArrayList<>();
    NodeList nodes = parent.getChildNodes();
    for (int i = 0; i < nodes.getLength(); i++) {
      Node node = nodes.item(i);
      if (node instanceof Element element && name.equals(element.getLocalName())) {
        matches.add(element);
      }
    }
    return matches;
  }

  private static List<Element> descendants(Element root, String name) {
    List<Element> matches = new ArrayList<>();
    NodeList nodes = root.getElementsByTagNameNS("*", name);
    for (int i = 0; i < nodes.getLength(); i++) {
      matches.add((Element) nodes.item(i));
    }
    return matches;
  }
}
