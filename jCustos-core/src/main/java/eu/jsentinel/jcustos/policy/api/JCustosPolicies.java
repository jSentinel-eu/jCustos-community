/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.policy.api;

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;

import java.time.Clock;
import java.time.LocalTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

/**
 * Pre-built policies for the most common access-control patterns.
 *
 * <p>Every factory method returns a fully-constructed {@link Policy}
 * ready to register with a {@code PolicyRegistry} or to pass into
 * {@code .policies(p -> p.register(...))} on the fluent bootstrap.
 *
 * <p>The patterns covered here are deliberately conservative — they
 * cover the 80 % of common cases without inventing new semantics.
 * Anything more sophisticated should be assembled directly via the
 * {@link Policy#named(String)} DSL.
 *
 * @since 00.74.00
 */
public final class JCustosPolicies {

  private JCustosPolicies() {
    throw new AssertionError("no instances");
  }

  /**
   * The classic "owner-or-admin" pattern: an admin role passes,
   * otherwise the subject must own the resource (the resource
   * resolver's owner attribute equals the subject id).
   *
   * @param resourceType   resource-type name as registered with the
   *                       {@code ResourceResolverRegistry}
   * @param ownerAttribute attribute key returned by the
   *                       {@code ResourceResolver} that holds the
   *                       owner id
   * @param adminRoles     one or more admin role names that always pass
   * @return ready-to-register policy named
   *         {@code "<resourceType>.owner-or-admin"}
   */
  public static Policy ownerOrAdmin(String resourceType,
                                    String ownerAttribute,
                                    String... adminRoles) {
    Objects.requireNonNull(resourceType, "resourceType");
    Objects.requireNonNull(ownerAttribute, "ownerAttribute");
    String[] roles = adminRoles == null || adminRoles.length == 0
        ? new String[]{"ROLE_ADMIN"}
        : adminRoles;
    return Policy.named(resourceType + ".owner-or-admin")
        .allowIf(SubjectPredicates.hasAnyRole(roles))
        .orIf(ResourcePredicates.ownerMatchesSubject(resourceType, ownerAttribute))
        .deny("must be " + String.join("/", roles) + " or own the " + resourceType)
        .build();
  }

  /**
   * Time-of-day gate: access permitted only inside the
   * {@code [start, end)} window in the JVM-default timezone.
   * Useful for "business hours only" patterns.
   *
   * @param policyName non-blank policy name
   * @param start      inclusive lower bound (e.g. {@code 09:00})
   * @param end        exclusive upper bound (e.g. {@code 17:00})
   */
  public static Policy timeWindow(String policyName, LocalTime start, LocalTime end) {
    return timeWindow(policyName, start, end, ZoneId.systemDefault(), Clock.systemDefaultZone());
  }

  /**
   * Time-of-day gate with explicit timezone and clock.
   * Test-friendly: pass a fixed {@link Clock} to make the policy
   * deterministic.
   */
  public static Policy timeWindow(String policyName,
                                  LocalTime start,
                                  LocalTime end,
                                  ZoneId zone,
                                  Clock clock) {
    Objects.requireNonNull(policyName, "policyName");
    Objects.requireNonNull(start, "start");
    Objects.requireNonNull(end, "end");
    Objects.requireNonNull(zone, "zone");
    Objects.requireNonNull(clock, "clock");
    Predicate<PolicyContext> inWindow = ctx -> {
      LocalTime now = LocalTime.now(clock.withZone(zone));
      return !now.isBefore(start) && now.isBefore(end);
    };
    return Policy.named(policyName)
        .allowIf(inWindow)
        .deny("outside business hours [" + start + ", " + end + ") in " + zone)
        .build();
  }

  /** Default attribute key for the subject's tenant (see {@link #sameTenant(String)}). */
  public static final String SUBJECT_TENANT_KEY = "subjectTenantId";
  /** Default attribute key for the resource's tenant when no {@link ResourceRef} is present. */
  public static final String RESOURCE_TENANT_KEY = "resourceTenantId";

  /**
   * Tenant-isolation pattern: the subject's tenant and the resource's
   * tenant must be equal; the policy denies when either side is unknown.
   *
   * <p><strong>Where the two tenants come from (JS-SEC-069, CWE-863).</strong>
   * Until 00.84.00 both sides were read from the same attribute map of the
   * {@code AccessContext}, so a request only had to carry <em>some</em>
   * value under the key — and the one-argument variant compared the key
   * {@code tenantId} with itself, admitting everything. Now:
   * <ul>
   *   <li><em>Resource side:</em> {@link ResourceRef#tenant()} when the
   *   context carries a {@link ResourceRef}; otherwise the
   *   {@code resourceTenantKey} attribute, first among the resolved
   *   {@link PolicyContext#resourceAttributes()}, then among the access
   *   attributes.</li>
   *   <li><em>Subject side:</em> the {@code subjectTenantKey} access
   *   attribute when the adapter or application set one; otherwise the
   *   tenant of the current subject through the registered
   *   {@link SubjectIdResolver#tenantFor(Object)}.</li>
   * </ul>
   * Attribute values may be {@link TenantId} or {@code String}. The two
   * keys must differ — equal keys would compare an attribute with itself.
   *
   * @param policyName        non-blank policy name
   * @param subjectTenantKey  access-attribute key for the subject's tenant
   * @param resourceTenantKey attribute key for the resource's tenant when no
   *                          {@link ResourceRef} is present
   * @throws IllegalArgumentException when both keys are equal
   */
  public static Policy sameTenant(String policyName,
                                  String subjectTenantKey,
                                  String resourceTenantKey) {
    Objects.requireNonNull(policyName, "policyName");
    Objects.requireNonNull(subjectTenantKey, "subjectTenantKey");
    Objects.requireNonNull(resourceTenantKey, "resourceTenantKey");
    if (subjectTenantKey.equals(resourceTenantKey)) {
      // JS-SEC-069 (CWE-863): the same key on both sides is a tautology, never a check.
      throw new IllegalArgumentException(
          "sameTenant: subjectTenantKey and resourceTenantKey must differ — comparing the "
              + "attribute '" + subjectTenantKey + "' with itself would admit every request");
    }
    Predicate<PolicyContext> sameTenant = ctx -> {
      Optional<TenantId> subjectTenant = subjectTenantOf(ctx, subjectTenantKey);
      Optional<TenantId> resourceTenant = resourceTenantOf(ctx, resourceTenantKey);
      return subjectTenant.isPresent() && subjectTenant.equals(resourceTenant);
    };
    return Policy.named(policyName)
        .allowIf(sameTenant)
        .deny("subject and resource must share the same tenant")
        .build();
  }

  /**
   * Convenience variant of {@link #sameTenant(String, String, String)}
   * with the keys {@link #SUBJECT_TENANT_KEY} and
   * {@link #RESOURCE_TENANT_KEY}: the resource tenant comes from the
   * {@link ResourceRef}, the subject tenant from the registered
   * {@link SubjectIdResolver} unless an explicit attribute overrides it.
   */
  public static Policy sameTenant(String policyName) {
    return sameTenant(policyName, SUBJECT_TENANT_KEY, RESOURCE_TENANT_KEY);
  }

  static Optional<TenantId> subjectTenantOf(PolicyContext ctx, String subjectTenantKey) {
    Optional<TenantId> explicit = tenantAttribute(ctx.accessContext().attributes().get(subjectTenantKey));
    return explicit.isPresent() ? explicit : currentSubjectTenant();
  }

  static Optional<TenantId> resourceTenantOf(PolicyContext ctx, String resourceTenantKey) {
    if (ctx.resourceRef().isPresent()) {
      return Optional.of(ctx.resourceRef().get().tenant());
    }
    Optional<TenantId> resolved = tenantAttribute(ctx.resourceAttributes().get(resourceTenantKey));
    return resolved.isPresent()
        ? resolved
        : tenantAttribute(ctx.accessContext().attributes().get(resourceTenantKey));
  }

  private static Optional<TenantId> tenantAttribute(Object value) {
    if (value instanceof TenantId tenant) {
      return Optional.of(tenant);
    }
    if (value instanceof String s && !s.isBlank()) {
      return Optional.of(TenantId.of(s));
    }
    return Optional.empty();
  }

  /**
   * Tenant of the subject currently bound in the {@code SubjectStore}, via the
   * registered {@link SubjectIdResolver}; empty when any link is missing, so the
   * policy denies rather than guesses.
   */
  @SuppressWarnings({"rawtypes", "unchecked"})
  private static Optional<TenantId> currentSubjectTenant() {
    try {
      Optional<AuthenticationService<Object, Object>> authn =
          JCustosServiceResolver.findAuthenticationService();
      Optional<SubjectIdResolver<Object>> resolver = JCustosServiceResolver.findSubjectIdResolver();
      if (authn.isEmpty() || resolver.isEmpty()) {
        return Optional.empty();
      }
      Class subjectType = authn.get().subjectType();
      return SubjectStores.findSubjectStore()
          .flatMap(store -> store.currentSubject(subjectType))
          .map(subject -> resolver.get().tenantFor(subject));
    } catch (RuntimeException unresolvable) {
      return Optional.empty();
    }
  }

  /**
   * Step-up gate: every access request is approved only after the
   * caller satisfies a step-up authentication (typically MFA).
   * The policy returns {@code StepUpRequired} unconditionally — the
   * adapter then triggers the configured step-up route.
   *
   * @param policyName non-blank policy name
   * @param method     requested step-up mechanism
   * @param reason     adapter-neutral diagnostic shown to the caller
   */
  public static Policy requireStepUp(String policyName,
                                     PolicyDecision.StepUpMethod method,
                                     String reason) {
    Objects.requireNonNull(policyName, "policyName");
    Objects.requireNonNull(method, "method");
    Objects.requireNonNull(reason, "reason");
    return Policy.named(policyName)
        .stepUpRequiredIf(ctx -> true, method, reason)
        .build();
  }

  /**
   * Convenience: step-up required with MFA, default reason
   * "Multi-factor authentication required".
   */
  public static Policy requireMfa(String policyName) {
    return requireStepUp(policyName,
        PolicyDecision.StepUpMethod.MFA,
        "Multi-factor authentication required");
  }

  /**
   * Any-of: subject passes if it holds any of the given roles
   * or any of the given permissions. Useful when the policy
   * represents "anybody in this group".
   *
   * @param policyName  non-blank policy name
   * @param roles       roles that pass the gate (any-of)
   * @param permissions permissions that pass the gate (any-of)
   */
  public static Policy anyRoleOrPermission(String policyName,
                                           Set<String> roles,
                                           Set<String> permissions) {
    Objects.requireNonNull(policyName, "policyName");
    Set<String> r = roles == null ? Set.of() : Set.copyOf(roles);
    Set<String> p = permissions == null ? Set.of() : Set.copyOf(permissions);
    if (r.isEmpty() && p.isEmpty()) {
      throw new IllegalArgumentException(
          "anyRoleOrPermission needs at least one role or permission");
    }
    PolicyBuilder b = Policy.named(policyName);
    boolean first = true;
    if (!r.isEmpty()) {
      b = b.allowIf(SubjectPredicates.hasAnyRole(r.toArray(new String[0])));
      first = false;
    }
    for (String perm : p) {
      b = first
          ? b.allowIf(SubjectPredicates.hasPermission(perm))
          : b.orIf(SubjectPredicates.hasPermission(perm));
      first = false;
    }
    return b.deny("must hold one of roles=" + r + " or permissions=" + p).build();
  }

  /**
   * IP allow-list pattern: subject's request must come from an
   * address in {@code allowedCidrs} (CIDR notation, e.g.
   * {@code "10.0.0.0/8"}). The request IP is read from the access
   * context attribute keyed by {@code ipAttributeKey} (typically
   * {@code "clientAddress"} in REST setups).
   *
   * <p>The CIDR check is rudimentary on purpose — it supports IPv4
   * prefixes only; for IPv6 / proxy-chain scenarios use a custom
   * predicate.
   *
   * @param policyName     non-blank policy name
   * @param ipAttributeKey context attribute key holding the request IP
   * @param allowedCidrs   IPv4 CIDR ranges (e.g. {@code "10.0.0.0/8"})
   */
  public static Policy ipAllowList(String policyName,
                                   String ipAttributeKey,
                                   String... allowedCidrs) {
    Objects.requireNonNull(policyName, "policyName");
    Objects.requireNonNull(ipAttributeKey, "ipAttributeKey");
    if (allowedCidrs == null || allowedCidrs.length == 0) {
      throw new IllegalArgumentException("ipAllowList needs at least one CIDR");
    }
    Set<String> cidrs = new LinkedHashSet<>(Arrays.asList(allowedCidrs));
    Predicate<PolicyContext> allowed = ctx -> {
      Object ip = ctx.accessContext().attributes().get(ipAttributeKey);
      if (!(ip instanceof String ipStr)) {
        return false;
      }
      return cidrs.stream().anyMatch(c -> ipv4InCidr(ipStr, c));
    };
    return Policy.named(policyName)
        .allowIf(allowed)
        .deny("request IP not in allow-list " + cidrs)
        .build();
  }

  /**
   * Combinator: all sub-policies must pass.
   * Each child policy is evaluated; the first child that does not
   * return {@code Allowed} wins (deny or step-up).
   *
   * @param policyName  non-blank policy name for the combined policy
   * @param children    at least one child policy
   */
  public static Policy allOf(String policyName, Policy... children) {
    Objects.requireNonNull(policyName, "policyName");
    if (children == null || children.length == 0) {
      throw new IllegalArgumentException("allOf needs at least one child");
    }
    Policy[] copy = children.clone();
    Predicate<PolicyContext> allAllowed = ctx -> {
      for (Policy child : copy) {
        if (!(child.evaluate(ctx) instanceof PolicyDecision.Allowed)) {
          return false;
        }
      }
      return true;
    };
    return Policy.named(policyName)
        .allowIf(allAllowed)
        .deny("not all child policies passed")
        .build();
  }

  /**
   * Combinator: any sub-policy passing is enough.
   * Children are tried in order; the first {@code Allowed} wins.
   */
  public static Policy anyOf(String policyName, Policy... children) {
    Objects.requireNonNull(policyName, "policyName");
    if (children == null || children.length == 0) {
      throw new IllegalArgumentException("anyOf needs at least one child");
    }
    Policy[] copy = children.clone();
    Predicate<PolicyContext> anyAllowed = ctx -> {
      for (Policy child : copy) {
        if (child.evaluate(ctx) instanceof PolicyDecision.Allowed) {
          return true;
        }
      }
      return false;
    };
    return Policy.named(policyName)
        .allowIf(anyAllowed)
        .deny("no child policy passed")
        .build();
  }

  // ── IPv4-CIDR matching, deliberately minimal ───────────────────

  private static boolean ipv4InCidr(String ip, String cidr) {
    try {
      int slash = cidr.indexOf('/');
      if (slash < 0) {
        return false;
      }
      int prefix = Integer.parseInt(cidr.substring(slash + 1));
      if (prefix < 0 || prefix > 32) {
        return false;
      }
      long ipBits = ipv4ToLong(ip);
      long cidrBits = ipv4ToLong(cidr.substring(0, slash));
      if (ipBits < 0 || cidrBits < 0) {
        return false;
      }
      long mask = prefix == 0 ? 0L : (~0L << (32 - prefix)) & 0xFFFFFFFFL;
      return (ipBits & mask) == (cidrBits & mask);
    } catch (NumberFormatException e) {
      return false;
    }
  }

  private static long ipv4ToLong(String ip) {
    String[] parts = ip.split("\\.");
    if (parts.length != 4) {
      return -1;
    }
    long out = 0;
    for (String p : parts) {
      int n = Integer.parseInt(p);
      if (n < 0 || n > 255) {
        return -1;
      }
      out = (out << 8) | n;
    }
    return out & 0xFFFFFFFFL;
  }
}
