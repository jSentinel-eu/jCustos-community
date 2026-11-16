---
name: jcustos-standalone-hardening
description: Layer-3 follow-up to the `jcustos-standalone` skill — Argon2id hashing + optional HIBP + Phase-4c drift detection wired into the CLI's bootstrap chain. Drift detection in standalone is best-effort because the CLI's lifetime is usually one session; the bumper still runs on role mutations and the version store keeps state for the session. Prerequisite: a project that already ran `jcustos-standalone`. Adds 2 deps (`jCustos-crypto-bc`, `jCustos-credentials-hibp`), 4 new templates (`SubjectIdResolverImpl`, `VersionBumper`, `PasswordPreflight`, `Main` delta) + 2 META-INF/services.
---

# jCustos Standalone hardening — layer 3

Argon2id + HIBP + drift for the CLI. Drift detection in standalone
is mostly latent — single-session CLIs rarely trigger it — but
wiring it consistently across all three adapters keeps the surface
uniform.

Argon2id is really used (JS-SEC-134): the user directory and the
first-admin bootstrap hash through
`JCustosServiceResolver.credentialHashingService()`. `PasswordPreflight`
applies to the first administrator through
`HardeningBootstrapExtension.initialAdminPasswordPolicy(...)`.

## Templates

| Template | Source |
|---|---|
| `pom-snippet.xml.tmpl` | shared |
| `SubjectIdResolverImpl.java.tmpl` | shared |
| `VersionBumper.java.tmpl` | shared |
| `PasswordPreflight.java.tmpl` | shared |
| `HardeningBootstrapExtension.java.tmpl` | NEW — `BouncyCastleHashingServices.modern()` + sessions.securityVersion(...) + preflight for the first admin |
| `services-JCustosVersionStore.tmpl` | shared |
| `services-SubjectIdResolver.tmpl` | shared |
