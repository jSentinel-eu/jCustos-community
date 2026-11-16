package eu.jsentinel.jcustos.demo.skill.vaadin.security.services;

import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordChecker;
import eu.jsentinel.jcustos.credential.compromised.CompromisedPasswordResult;
import eu.jsentinel.jcustos.credential.compromised.LocalBlocklistCompromisedPasswordChecker;
import eu.jsentinel.jcustos.credential.secret.SecretValue;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.function.Function;

/**
 * Password-acceptance check called before any new / changed password
 * is committed.
 *
 * <p>Two layers:
 *
 * <ol>
 *   <li>A local blocklist for the top-N most-common passwords —
 *       fast, offline, always on.</li>
 *   <li>(if true=true) an online k-anonymity range
 *       query against the HaveIBeenPwned API — the plain candidate
 *       never leaves the JVM, only the first 5 SHA-1 hex chars.</li>
 * </ol>
 *
 * <p>Both layers return {@link CompromisedPasswordResult} variants.
 * The caller treats {@link CompromisedPasswordResult.Pwned} as
 * reject (generic message, never name the dictionary — CWE-209) and
 * everything else as accept.
 *
 * <p>Network failures on the HIBP path return
 * {@link CompromisedPasswordResult.Indeterminate} — fail-open by
 * design (CWE-359): a corporate firewall blocking the HIBP API
 * should not block legitimate password changes.
 *
 * <p>Every password the application accepts passes here: new users in
 * {@code AdminRolesView} and the first administrator, whose setup runs
 * the preflight through {@link PreflightPasswordPolicy} (JS-SEC-134).
 *
 * <p>The range query goes to the public HIBP endpoint
 * unless {@value #HIBP_ENDPOINT_PROPERTY} names another endpoint (HTTPS,
 * or HTTP on loopback) - a mirror inside the company network, or the
 * loopback server of a test.
 */
public final class PasswordPreflight {

  private static final CompromisedPasswordChecker LOCAL =
      new LocalBlocklistCompromisedPasswordChecker(List.of(
          "password", "password1", "password123",
          "qwerty", "qwerty123", "letmein",
          "admin", "admin123", "administrator",
          "welcome", "welcome1",
          "12345678", "123456789", "abc12345",
          "iloveyou", "monkey", "dragon",
          "hunter2", "trustno1"));

  /** System property naming another HIBP range endpoint. */
  public static final String HIBP_ENDPOINT_PROPERTY = "jcustos.demo.hibpEndpoint";

  // true=true → activate; false → leave null (lambda skip)
  private static final Function<URI, CompromisedPasswordChecker> HIBP =
      endpoint -> eu.jsentinel.jcustos.credential.compromised.hibp.HaveIBeenPwnedCompromisedPasswordChecker
          .usingJdkHttpClient(endpoint != null ? endpoint
                  : eu.jsentinel.jcustos.credential.compromised.hibp.HaveIBeenPwnedCompromisedPasswordChecker.DEFAULT_ENDPOINT,
              Duration.ofSeconds(5));

  private PasswordPreflight() {
  }

  /**
   * Returns {@code true} if the candidate is acceptable. {@code false}
   * means a Pwned result from one of the layers — caller shows a
   * generic rejection message.
   */
  public static boolean isAcceptable(String candidate) {
    if (candidate == null || candidate.isEmpty()) {
      return false;
    }
    SecretValue secret = SecretValue.ofString(candidate);
    if (LOCAL.check(secret) instanceof CompromisedPasswordResult.Pwned) {
      return false;
    }
    if (HIBP != null
        && HIBP.apply(hibpEndpoint()).check(secret) instanceof CompromisedPasswordResult.Pwned) {
      return false;
    }
    return true;
  }

  /** @return the configured endpoint, or {@code null} for the public one */
  private static URI hibpEndpoint() {
    String configured = System.getProperty(HIBP_ENDPOINT_PROPERTY);
    return configured == null || configured.isBlank() ? null : URI.create(configured);
  }
}
