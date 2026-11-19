# jCustos V00.82.00 — hardening the residuals

**Theme:** the security findings that earlier releases documented as accepted
residuals rather than fixed. Four of them are closed here, each with a test that
fails when the fix is removed. Additive throughout — no API was broken, and
nothing changes behaviour until you opt in.

## What was closed

### Unprotected REST handlers are now reported at startup (CWE-862)

Deny-by-default already refused a handler carrying no security annotation, but a
REST application only found out when a request arrived. Vaadin reports it at
startup because its router can enumerate routes; REST has no such registry, so
the diagnostic was Vaadin-only.

`RestHandlerDiscovery` closes it — the application names its handler classes,
since it is the only party that knows them:

```java
RestSecurity.bootstrap()
    .discoverHandlers(new ClassScanningRestHandlerDiscovery(DocumentHandlers.class))
    .mode(JCustosBootstrapMode.STRICT)
    .install();
```

The shipped implementation applies the same three rules the filter uses at
runtime — own annotation, class annotation, or `@PublicRoute` — so the startup
verdict matches what a request would meet. Three findings, and the difference
between them is the point: `deny-by-default/unannotated-handler` means a handler
is unreachable, `…/discovery-unavailable` means the check could not run, and
`…/discovery-disabled` means no enumeration is configured. "Could not check" is
never reported as "checked and clean".

### The relying party can vet the logout redirect (CWE-601)

`post_logout_redirect_uri` was forwarded to the provider unchecked. Defensible
on paper — the provider matches it against its registered set — but that check
happens where this code cannot see it, and when the URI comes from the request
an attacker picks where the user lands.

```java
new RpInitiatedLogoutInitiator(
    PostLogoutRedirectValidator.allowOnly(URI.create("https://app.example.com/bye")));
```

`allowOnly` compares scheme, host, port and path **exactly**. A prefix check on
`https://app.example.com` also accepts `https://app.example.com.attacker.test`,
which is how allowlists end up permitting what they were written to stop. A
rejected URI throws rather than being dropped: silently logging the user out to
the provider's default page would hide both an attack and a misconfiguration.

The no-arg constructor is unchanged, so upgrading changes nothing until you pass
a validator.

### HTTP body reads are bounded in time, not just in size (CWE-400)

Every HTTP client used `ofInputStream()` and then `readNBytes(MAX + 1)`. The
size cap worked; the time bound did not. `HttpRequest.timeout` covers the
exchange up to the response headers, and with `ofInputStream` `send()` returns
right there — the body was read afterwards, outside any deadline. A server that
answers the headers promptly and then trickles one byte at a time held the
calling thread for as long as it liked.

`BoundedHttpBody` hands `send()` a materialising, limiting subscriber, so the
call returns only once the body is complete and the request timeout covers the
whole exchange. Seven clients carried the pattern — three more than the finding
listed: JWKS, token endpoint, OAuth2 form post, OIDC discovery, userinfo, the
propagation token client and the HIBP checker.

### Every password verification costs the same (CWE-208)

The dummy KDF runs the preferred algorithm, so a stored hash on a different one
verified at a different cost. During a lazy migration that gap is measurable
from outside and separates "existing but unmigrated" from "no such user" — the
one distinction the dummy path exists to hide.

A verification against a non-preferred envelope now runs an additional
preferred-cost dummy KDF. The cost is one extra KDF per unmigrated account, and
it disappears as the migration completes. Hashes already on the preferred
algorithm are untouched.

## Also in this release

- **Full-backup export** — `EclipseStoreJCustosStorage.issueFullBackup(Path)`
  writes a bootable copy of the live storage while it keeps serving. This was
  written in August, never left a working copy, and was recovered for this
  release along with the tests its original commit promised.
- **Javadoc references** repaired: two `@link`s pointed at packages that do not
  exist on their module's classpath and failed javadoc generation during the
  00.81.20 release build.

## Deferred

**CSRF / web-adapter hardening** stays open. Login-CSRF is covered
(`CallbackStateBinding`, V00.81.00), but general CSRF protection needs a concept
rather than a patch: it only affects cookie-based authentication, while the
documented jCustos REST path uses bearer tokens, where a CSRF token would be
ceremony without effect. Half a CSRF defence is worse than none, because it
suggests protection that does not apply.

## Verification

Community 6600+ tests, enterprise 474 — no failures. Every security fix has a
test that was confirmed to fail when the fix is disabled; a test that never goes
red proves nothing.

> **Correction (00.84.00):** these totals counted every test twice; they summed every
> `Tests run:` line of the Maven log, class lines and module summaries alike. Measured again
> from the tag: 3305 community tests and 237 enterprise tests, no failures.
