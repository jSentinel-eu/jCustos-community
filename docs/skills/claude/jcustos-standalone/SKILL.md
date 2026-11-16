---
name: jcustos-standalone
description: Battle-tested integration of jCustos (V00.73+) into a CLI / desktop / plain-Java app — V00.73 fluent `StandaloneSecurity.bootstrap()` + `@JCustosAutoService`-registered `AuthenticationService` / `AuthorizationService` + opt-in development seed admin/admin + user/user (`-Djcustos.demo.insecure-seed-accounts=true`, `DEVELOPMENT` only) + `SecuredProxy.wrap(...)` for runtime enforcement (interface) OR `@Secured` annotation processor for compile-time enforcement (concrete class) + interactive CLI loop. Use PROACTIVELY when the user mentions standalone, CLI, desktop, plain Java, `ThreadLocalSubjectStore`, `StandaloneLoginFlow`, `SecuredProxy`, `@Secured` annotation processor, `JCustosEnforcer`, "secure my command-line app", "secure my desktop app", "annotation-driven enforcement on a regular Java class". Provides POM patch (`jCustos-standalone`, `jCustos-dx-standalone`, `jCustos-processor`), 9 templates (User, Credentials, UserDirectory, InMemoryUserDirectory, UserDirectoryProvider, AuthenticationService, AuthorizationService, SecuredService interface + impl, Main). The `SecuredService` interface carries `@RequiresPermission` annotations; `SecuredProxy.wrap(...)` produces a runtime proxy that consults the framework on every call. Does NOT cover the `@Secured` annotation processor for concrete classes (that's a 1-line opt-in: add `@Secured` to a class + wire `jCustos-processor` as `<annotationProcessorPath>` — the `Main` template shows the pattern). Does NOT cover persistence or hardening — those are the `jcustos-standalone-persistence` / `jcustos-standalone-hardening` skills.
---

# jCustos ↦ Standalone (CLI / Desktop / plain Java) — full integration

Drops jCustos into a plain-Java app with no servlet container and
no UI framework. End state: a CLI that prompts for credentials,
binds the subject to a thread-local, and runs a command loop where
each command is gated by `SecuredProxy.wrap(...)`.

## Demo users + permissions

The directory starts empty. With the development switch
`-Djcustos.demo.insecure-seed-accounts=true` (refused outside
`DEVELOPMENT`, JS-SEC-137) it holds:

- `admin / admin` — ADMIN: doc:list, doc:create, doc:delete, audit:read
- `user / user` — USER: doc:list only

Passwords are hashed through `JCustosServiceResolver.credentialHashingService()`;
an unknown name costs one KDF run. `Main` answers a verification shed
under load (`CredentialVerificationUnavailableException`, JS-SEC-126)
with "try again later", and a `LockedOut` result — also returned when
the account was locked while the password was checked (JS-SEC-123) —
with the remaining wait. Deny-by-default is on.

## Commands

```
> login          (initial prompt)
> list           — doc:list   — both users see it
> create <title> — doc:create — admin only
> delete <title> — doc:delete — admin only
> audit          — audit:read — admin only
> whoami         — (always allowed)
> quit
```

`USER` runs `create` → `DENIED — missing permission doc:create`.

## Templates

| Template | Target |
|---|---|
| `pom-snippet.xml.tmpl` | merge |
| `Subject.java.tmpl` | `security/model/{{SUBJECT_TYPE}}.java` |
| `Credentials.java.tmpl` | `security/model/Credentials.java` |
| `UserDirectory.java.tmpl` | `security/model/UserDirectory.java` |
| `InMemoryUserDirectory.java.tmpl` | `security/model/InMemoryUserDirectory.java` |
| `UserDirectoryProvider.java.tmpl` | `security/model/UserDirectoryProvider.java` |
| `AuthorizationRole.java.tmpl` | `security/roles/AuthorizationRole.java` |
| `AppPermission.java.tmpl` | `security/permissions/AppPermission.java` |
| `AuthenticationService.java.tmpl` | `security/services/{{SUBJECT_PREFIX}}AuthenticationService.java` |
| `AuthorizationService.java.tmpl` | `security/services/{{SUBJECT_PREFIX}}AuthorizationService.java` |
| `DocumentService.java.tmpl` | `services/DocumentService.java` (interface with `@RequiresPermission`) |
| `InMemoryDocumentService.java.tmpl` | `services/InMemoryDocumentService.java` |
| `Main.java.tmpl` | `Main.java` |

## Slots

| Slot | Default |
|---|---|
| `{{BASE_PACKAGE}}` | — |
| `{{SUBJECT_TYPE}}` | `User` |
| `{{SUBJECT_PREFIX}}` | `My` |
| `{{BOOTSTRAP_PROFILE}}` | `DEVELOPMENT` |
