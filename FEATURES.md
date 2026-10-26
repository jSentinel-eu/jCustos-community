# jCustos — Feature Catalogue

Vollständige Auflistung aller Funktionen und Erweiterungspunkte
in jCustos 00.70.00 (Stand 2026-05-31, **V00.70.00
feature-complete** — alle acht Phasen aus `Konzept-V00.70.00.md` sind
gemerged: Tenant/Resource-Modell, 11 Persistence-Store-SPIs, Contract-
Testkit + Eclipse-Store-Referenz-Impl, `JCustosVersion`-Drift-
Detection inkl. automatischem Capture im `LoginView`, Policy-API +
`jCustos-processor`, RoleHierarchy + Any/All-Permission-Annotationen,
Account-Lifecycle / API-Keys / RefreshTokens / Rate-Limit, Phase-8
Secured-Komponenten + `SessionManagementView` + OpenAPI-Metadaten).
Geordnet nach Reaktor-Modul und Funktionsbereich. Jeder Eintrag nennt
das Modul, den vollqualifizierten Java-Namen und — wo sinnvoll — die
SPI-Datei unter `META-INF/services/`.

> Konventionen: ✅ = ausgeliefert, voll abgedeckt; ⚠️ = experimentell
> (`@ExperimentalJCustosApi`); ❌ = bewusst nicht im Scope (siehe
> § "Was nicht im Scope ist" am Ende).
>
> ⚠️ bedeutet zweierlei: entweder *noch in der Reifezeit* (wird stabil,
> sobald drei Minor-Releases und eine echte Integration hinter dem Typ
> liegen) oder *bewusste Design-Aussage* — bei der Permission-API etwa
> steht der Marker dafür, dass rollenbasierter Zugriff der empfohlene
> Weg ist. Der `value()`-Text am Marker unterscheidet die beiden Fälle.
> Was pro Release promotet und was bewusst behalten wurde, steht in den
> Release-Notes (zuletzt `RELEASE-NOTES-00.83.00.md`).

---

## 1. Module (13)

| Modul | Artefakt | Zweck |
|---|---|---|
| `jCustos-core` | `jCustos-core` | Framework-neutrale Kern-Typen, alle SPIs, alle 11 Persistence-Store-Interfaces (Phase 2), `JCustosVersion`-Stack (Phase 4), Audit-Pipeline (27 Variants), Bootstrap, `JCustosEnforcer`, Account-Lifecycle- / Token- / RateLimit-Services (Phase 7) |
| `jCustos-vaadin` | `jCustos-vaadin` | Vaadin-Flow-Adapter: Navigation, Login, Session, Logout — plus Phase-8 `SecuredButton` / `SecuredRouterLink` / `SecuredMenuItem` / `SessionManagementView` und Phase-4c `JCustosVersionEnforcerListener` |
| `jCustos-rest` | `jCustos-rest` | Framework-light REST-Adapter (Filter, BearerToken, HTTP-Status-Mapping, Step-Up `WWW-Authenticate`) — plus Phase-4c `RestJCustosVersionFilter` und Phase-8d `OpenApiJCustosMetadataGenerator` |
| `jCustos-standalone` | `jCustos-standalone` | Plain-Java / Desktop / CLI Adapter (ThreadLocal-Subject, `SecuredProxy` Dynamic-Proxy) |
| `jCustos-test` | `jCustos-test` | Wiederverwendbare Test-Fixtures: `FakeAuthenticationService`, `FakeAuthorizationService`, `InMemorySubjectStore`, `RecordingAuditSink`, JUnit-5-`JCustosTestExtension`. Test-Scope-Dependency. |
| `jCustos-processor` | `jCustos-processor` | Compile-Time-Annotation-Processor: erzeugt `<Type>Secured`-Subklassen für `@Secured`-annotierte konkrete Klassen. Wird als `<annotationProcessorPath>` eingebunden. Basiert auf `com.svenruppert:proxybuilder:00.11.00` + `proxybuilder-annotations:00.11.00`. |
| `jCustos-persistence-testkit` | `jCustos-persistence-testkit` | ⚠️ Contract-Test-Suites für jede Persistence-Store-SPI: `@Test default`-Methoden-Interfaces, die ein eigener Store-Adapter implementiert, um automatisch gegen den Library-Persistence-Kontrakt verifiziert zu werden. Persistence-Tech-agnostisch. |
| `jCustos-persistence-eclipsestore` | `jCustos-persistence-eclipsestore` | ⚠️ Eclipse-Store (`org.eclipse.store:storage-embedded:4.1.0`) Referenz-Impl jeder Persistence-Store-SPI; besteht dieselbe 95+ Contract-Suite wie die In-Memory-Defaults. Drop-in für durable Persistence. |
| `demo-rest-shared` | `demo-rest-shared` | Transport-Konstanten + JSON-Helper für REST-Demos |
| `demo-vaadin` | `demo-vaadin` | Vollständige Vaadin-Demo mit lokaler User-Verwaltung |
| `demo-rest` | `demo-rest` | JDK-`HttpServer` + interaktive CLI |
| `demo-vaadin-rest-client` | `demo-vaadin-rest-client` | Vaadin-UI gegen demo-rest-Backend, plus Step-Up- / Resource-Policy-Demo-Views |
| `demo-standalone` | `demo-standalone` | CLI Library-Borrowing-Demo + Member-Directory-Demo — zeigt beide Method-Security-Pfade nebeneinander |

---

## 2. SPI-Contracts (ServiceLoader-basiert)

Alle SPIs werden über `META-INF/services/<FQN>` registriert und über
`eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver`
aufgelöst (cached AtomicReference + lazy ServiceLoader-Resolution).

### Authentifizierung & Autorisierung

| SPI | Modul | Default | Zweck |
|---|---|---|---|
| `AuthenticationService<T, U>` | core | — (anwendungsdefiniert) | Credential-Validation + Subject-Loading |
| `AuthorizationService<U>` | core | — (anwendungsdefiniert) | Subject → Rollen + (optional) Permissions |
| `PermissionAuthorizationService<U>` ⚠️ | core | — | Optionale Permission-API mit `HasPermissions` |
| `AccessEvaluator<A>` | core | siehe § Evaluatoren | Annotation-basierte Vaadin-Access-Entscheidung |
| `AuthorizationEvaluator<A>` | core | siehe § Evaluatoren | Adapter-neutrale Authorization-Entscheidung |
| `ActionAuthorizationService<U>` | core | `StaticActionAuthorizationService` (seit **V00.84**, JS-SEC-083: optionaler dritter Konstruktorparameter `SubjectIdResolver<U>`; `ActionDenied.subjectId` kommt aus dem expliziten oder registrierten Resolver, nie aus Identity-Hash oder `toString()`) | Methoden-/Action-Level-Berechtigungen |
| `SubjectStore` | core | siehe § Subject-Stores | Storage für das aktuelle Subject |
| `LoginListener<U>` | vaadin | — | Vaadin-Login-Lifecycle-Hooks |

### Audit

| SPI | Modul | Default | Zweck |
|---|---|---|---|
| `JCustosAuditService` | core | `DefaultCompositeAuditService` | Audit-Service mit `publish(AuditEvent)` + `query(AuditQuery)` |
| `AuditSink` | core | `RingBufferAuditSink` + `LoggingAuditSink` | Write-only-Sink für Audit-Pipeline |

### Brute-Force & Sessions

| SPI | Modul | Default | Zweck |
|---|---|---|---|
| `LoginAttemptPolicy` | core | `InMemoryLoginAttemptPolicy` | Login-Throttling + Lockout-Entscheidungen |
| `ClientAddressResolver` | core | `DefaultClientAddressResolver` (Verbindungs-Peer, kein Header) | **V00.84** (JS-SEC-061, CWE-348): entscheidet, welche Adresse Throttling, Abuse-Erkennung und Audit-Zeilen schlüsselt. `TrustedProxyClientAddressResolver` wertet `X-Forwarded-For` nur von konfigurierten Proxys (Adressen/CIDR) aus, liest von rechts, ignoriert `Forwarded`/`X-Real-IP`. Adapter: `VaadinClientAddress`, `RestClientAddress`, `RestRequest.remoteAddress()`, DX `.clientAddress(...)`. Doku: `docs/security/deployment/reverse-proxy.md` |
| `SessionPolicy<U>` | core | `TimeoutSessionPolicy` (seit **V00.84 auch Resolver-Default**: 30 min Leerlauf, 12 h Gesamtlebensdauer, Rotation nach Login, Login-Route aus dem Resolver — JS-SEC-065; `NoopSessionPolicy` ist der ausdrückliche Opt-out) | Lifecycle-Hooks + Idle/Absolute-Timeout |

### Logout

| SPI | Modul | Default | Zweck |
|---|---|---|---|
| `LogoutService` | core | `NoopLogoutService` / `SubjectClearingLogoutService` | Zentraler Logout-Treiber mit Fan-out |
| `LogoutListener` | core | — (Anwender-Erweiterung) | Post-logout Side-Effects (Token-Revoke etc.) |
| `SubjectSessionRegistry` | core | `InMemorySubjectSessionRegistry` | Multi-Session-Tracking pro Subject (für `AllSessionsOfSubject`-Scope) |

### Passwort & Bootstrap

| SPI | Modul | Default | Zweck |
|---|---|---|---|
| `PasswordHasher` | core | `Pbkdf2PasswordHasher` (seit **V00.84** 600 000 Iterationen aus `Pbkdf2Defaults`, JS-SEC-072; `verify` prüft Iterationszahl und Salt-Länge gegen die Grenzwerte, bevor abgeleitet wird) | Hashing + Drift-Detection (`needsRehash`); Legacy-Drahtformat `pbkdf2$…`, neue Anwendungen nutzen `PasswordHashingServices.defaults()` |
| `PasswordPolicy` | core | `MinimumLengthPasswordPolicy(8)` | Passwort-Mindestlängen-Validierung |
| `AdministratorAccountStore` | core | anwendungsdefiniert | Persistierung des Bootstrap-Admins |
| `BootstrapTokenStore` | core | `InMemoryBootstrapTokenStore` / `FileBootstrapTokenStore` | Token-Persistenz für First-Run-Bootstrap |
| `BootstrapTokenOutput` | core | `ConsoleBootstrapTokenOutput` / `FileBootstrapTokenOutput` | Token-Ausgabe an Operator |

### Rollenmodell (optional)

| SPI | Modul | Default | Zweck |
|---|---|---|---|
| `RolePermissionMapping` | core | `StaticRolePermissionMapping` | Role → Permissions-Mapping |
| `PermissionCatalog` ⚠️ | core | — | Permission-Inventory für Discovery-UIs |
| `RoleHierarchy` | core | `NoopRoleHierarchy` / `StaticRoleHierarchy` | Role-Inheritance; honoured von `RequiresRoleEvaluator` + `RolePermissionResolver` |
| `SubjectIdResolver<U>` ⚠️ | core | — (anwendungsdefiniert) | Phase 4c-Followup: Typed-User → `SubjectId` (+ optional `TenantId`) — Vaadin-Auto-Capture aktiviert sich erst mit registrierter Impl |

### REST-Adapter

| SPI | Modul | Zweck |
|---|---|---|
| `RestSubjectResolver` | rest | Request → `Optional<JCustosSubject>` + `SessionMetadata` + (Phase 4c) optionaler `RestJCustosVersionContext` |

### Persistence-Stores (Phase 2 — alle 11 ⚠️ `@ExperimentalJCustosApi`)

Jeder Store hat ein `InMemory*Store`-Default in `jCustos-core` und
eine Eclipse-Store-Referenz-Impl in `jCustos-persistence-eclipsestore`,
beide verifiziert über `jCustos-persistence-testkit`-Contract-Tests.

| Store | Modul / Package | Record / Key | Zweck |
|---|---|---|---|
| `AuditEventStore` | core/audit | `AuditEnvelope` | Persistente Audit-Events; Query-API |
| `SessionStore` | core/session | `SessionRecord` keyed on `SessionId` | Persistente Sessions + `findAll()` für Admin-Views |
| `LoginAttemptStore` | core/bruteforce | `LoginAttemptKey(username, clientAddress)` | Brute-Force-Versuche, store-backed flacher Lockout |
| `RoleAssignmentStore` | core/authorization/api/roles | `RoleAssignmentKey(tenant, subjectId)` → `Set<RoleName>` | Persistente Rollen-Zuordnungen |
| `BootstrapStateStore` | core/bootstrap | `BootstrapState` per Tenant | "Ist das System bootstrapped?" — idempotent |
| `RememberMeTokenStore` | core/authentication | `RememberMeTokenRecord` (hash-only) | Persistent-Login-Tokens |
| `PasswordResetTokenStore` | core/accountlifecycle | `PasswordResetTokenRecord` (hash-only, single-use); `InMemoryPasswordResetTokenStore` seit **V00.84** kapazitätsbegrenzt (`CapacityBound`, Subjekt-Index, JS-SEC-074) | Passwort-Reset-Flow |
| `EmailVerificationTokenStore` | core/accountlifecycle | `EmailVerificationTokenRecord` (hash-only, single-use); `InMemoryEmailVerificationTokenStore` seit **V00.84** kapazitätsbegrenzt (JS-SEC-074) | Email-Verifikations-Flow |
| `ApiKeyStore` | core/authentication | `ApiKeyRecord` (hash-only, mit Scopes) | Long-Lived API-Keys |
| `RefreshTokenStore` | core/authentication | `RefreshTokenRecord` (hash-only, rotating mit `markReplaced`) | Rotating Refresh-Tokens mit Replay-Defense |
| `RateLimitStore` | core/ratelimiting | Events unter `RateLimitKey(tenant, scope)` | Event-basierter Sliding-Window-Counter; seit **V00.84** `tryAdmit(key, at, since, limit)` als atomare Zulassung (CWE-367), In-Memory-Store kapazitätsbegrenzt mit Verdrängung des ältesten Schlüssels und Fensterbeschnitt (JS-SEC-078) |

### JCustosVersion / Drift Detection (Phase 4 — ⚠️)

| SPI / Klasse | Modul | Default | Zweck |
|---|---|---|---|
| `JCustosVersionStore` | core/session | `InMemoryJCustosVersionStore` + Eclipse-Store-Impl | Monotonic counter pro `(TenantId, SubjectId)`; `current` / `increment` / `reset` |
| `JCustosVersionCheck` | core/session | — (pure helper) | Vergleicht Session-Snapshot vs. Store-Current → `JCustosVersionStatus(Current \| Drifted)` |
| `JCustosVersionEnforcer` | core/session | — (pure helper) | Adapter-neutral; emittiert `SessionStale`-Audit; `EnforcementOutcome(Continue \| SessionStale)` |

### Account Lifecycle / Notifications (Phase 7 — ⚠️)

| SPI / Klasse | Modul | Default | Zweck |
|---|---|---|---|
| `JCustosNotificationSender` | core/accountlifecycle | `LoggingNotificationSender` | Dispatcher für Reset/Verify-Benachrichtigungen; Apps verdrahten Mail/SMS-Transports |
| `JCustosNotification` (record) + `Kind` (enum, 4 Werte) | core/accountlifecycle | — | `PASSWORD_RESET_REQUESTED` / `PASSWORD_RESET_COMPLETED` / `EMAIL_VERIFICATION_REQUESTED` / `EMAIL_VERIFIED` |
| `PasswordResetService` | core/accountlifecycle | — | `request(SubjectId, ttl)` / `validate(plain)` / `consume(plain)` (single-use, hash-only); seit **V00.84** entwertet `request` alle Vorgänger und `consume` alle Geschwister des Subjekts — nur der neueste Link gilt (JS-SEC-074, CWE-640) |
| `EmailVerificationService` | core/accountlifecycle | — | Wie PasswordReset, plus Email-Adresse am Record; Geschwister-Entwertung seit **V00.84** (JS-SEC-074) |

### API-Keys / Tokens (Phase 7b — ⚠️)

| Klasse | Modul | Zweck |
|---|---|---|
| `ApiKeyAuthenticationService` | core/authentication | Hash-only Lookup, Lifecycle-Verdict (`Unknown` / `ForeignTenant` / `Revoked` / `Expired`); markiert `lastUsedAt`; emittiert `ApiKeyUsed`/`ApiKeyDenied` |
| `TokenService` | core/authentication | `issue(subject)` / `rotate(refresh)` / `revoke(refresh)` über `RefreshTokenStore`; chain-link via `markReplaced` mit Replay-Defense; emittiert `TokenRotated` auf erfolgreicher Rotation; seit **V00.84** (JS-SEC-071, CWE-367/CWE-294) atomarer Claim über `markReplaced` **vor** dem Ausstellen (zwei nebenläufige Rotationen → genau ein Paar), Replay eines verbrauchten Tokens sperrt die Token-Familie und auditiert `CredentialVerificationFailed(REFRESH_TOKEN_REPLAY)` |

### Rate-Limiting (Phase 7c — ⚠️)

| SPI / Klasse | Modul | Default | Zweck |
|---|---|---|---|
| `RateLimitPolicy` | core/ratelimiting | `InMemoryRateLimitPolicy` (Sliding-Window) | Per-Scope Rate-Limit (getrennt von `LoginAttemptPolicy`); `tryAcquire(RateLimitKey)` → `RateLimitDecision(Allowed \| Throttled)`; `tryAcquire` nutzt seit **V00.84** `RateLimitStore.tryAdmit` — N parallele Anfragen bei limit-1 lassen höchstens `limit` durch (JS-SEC-078) |

### Store-backed Services (Phase 4b — ⚠️)

Alle nutzen die Phase-2 Stores als Backing-Store, sind tenant-scoped
und schlucken Persistence-Fehler im Audit/Notification-Pfad, damit
sie die Security-Flow-Auswertung nie blockieren.

| Service | Modul | Backing-Store |
|---|---|---|
| `StoreBackedJCustosAuditService` | core/audit | `AuditEventStore` |
| `StoreBackedLoginAttemptPolicy` | core/bruteforce | `LoginAttemptStore` (flacher Lockout) |
| `StoreBackedSubjectSessionRegistry` | core/logout | `SessionStore` + optionaler `JCustosVersionStore` (Phase-4c-Snapshot beim Register); seit **V00.84** bindet `register` eine wiederverwendete Session-ID bei fremdem Subjekt oder nicht-aktivem Status neu statt aufzufrischen (JS-SEC-075) |
| `StoreBackedRoleAuthorizationService<U>` | core/authorization/api/roles | `RoleAssignmentStore` (generic über Subject-Type) |
| `StoreBackedRememberMeService` | core/authentication | `RememberMeTokenStore` + `PasswordHasher` |
| `StoreBackedBootstrapStateService` | core/bootstrap | `BootstrapStateStore` (idempotentes `markCompleted`) |

---

## 3. Annotations

| Annotation | Modul | Evaluator | Zweck |
|---|---|---|---|
| `@RequiresRole({"ROLE_…"})` | core | `RequiresRoleEvaluator` | Subject muss mindestens eine der genannten Rollen haben (Role-Hierarchy-aware) |
| `@RequiresPermission({"foo:bar"})` | core | `RequiresPermissionEvaluator` | Subject muss alle genannten Permissions haben (AND) |
| `@RequiresAllPermissions({"a", "b"})` | core | `RequiresAllPermissionsEvaluator` | Explizite AND-Semantik (Klarheit über `@RequiresPermission`) |
| `@RequiresAnyPermission({"a", "b"})` | core | `RequiresAnyPermissionEvaluator` | OR-Semantik — mindestens eine Permission reicht |
| `@RequiresPolicy("doc.owner-or-admin")` ⚠️ | core | `RequiresPolicyEvaluator` | Benannte Policy aus `PolicyRegistry`, mit Step-Up-Support |
| `@ProtectedBy(class.class)` | core | `ProtectedByEvaluator` | Eigene Logik via `AccessEvaluator`-Klasse |
| `@JCustosAnnotation(MyEvaluator.class)` | core | — (Meta-Annotation) | Bindet eine projekt-eigene Annotation an einen Evaluator |
| `@Secured` | core | — (Compile-Time-Trigger) | Markiert eine konkrete Klasse, damit `jCustos-processor` einen `<Type>Secured`-Wrapper generiert (RetentionPolicy.SOURCE) |
| `@ExperimentalJCustosApi(reason)` | core | — | Markiert API als experimentell |

Projekt-eigene Annotationen (Beispiele aus den Demos): `@VisibleFor`
(demo-vaadin), `@CustomCheck` (jCustos-vaadin Tests).

---

## 4. Built-in Evaluatoren

| Evaluator | Modul | Annotation | Output |
|---|---|---|---|
| `RequiresRoleEvaluator` | core | `@RequiresRole` | `AuthorizationDecision.Granted/Unauthenticated/Forbidden` |
| `RequiresPermissionEvaluator` | core | `@RequiresPermission` | dito |
| `ProtectedByEvaluator` | core | `@ProtectedBy` | `AccessDecision` (legacy) |
| `RoleBasedAccessEvaluator<A, U>` | core | abstrakt (Basis) | Anwendungs-Basis für rollen-basierte Evaluatoren |
| `PermissionBasedAccessEvaluator<A, U>` ⚠️ | core | abstrakt | Anwendungs-Basis für permission-basierte Evaluatoren |

---

## 5. Decision-Hierarchien (sealed)

### `AuthorizationDecision` (adapter-neutral)

| Variant | Felder | Bedeutung |
|---|---|---|
| `Granted` | — | Zugriff erlaubt |
| `Unauthenticated` | `reason` | Kein Subject gesetzt |
| `Forbidden` | `reason` | Subject hat keine ausreichenden Rechte |
| `StepUpRequired` | `reason`, `method` | Step-Up-Auth erforderlich; Vaadin reroutet zur Step-Up-Route, REST antwortet `401 + WWW-Authenticate: StepUp method="…"` |

### `AccessDecision` (Vaadin-orientiert, legacy)

| Variant | Felder | Bedeutung |
|---|---|---|
| `Granted` | — | Navigation erlaubt |
| `Reroute` | `target`, `asForward` | Umleitung auf andere Route |
| `RerouteToError` | `type`, `message` | Umleitung auf Error-View |
| `RerouteWithParameter<T>` | `target`, `parameter` | Reroute mit einem Route-Parameter |
| `RerouteWithParameters<T>` | `target`, `parameters` | Reroute mit mehreren Parametern |

### `LoginAttemptDecision`

| Variant | Felder | Bedeutung |
|---|---|---|
| `Allowed` | — | Login-Versuch darf laufen |
| `LockedOut` | `remaining (Duration)`, `failedAttempts (int)` | Account momentan gesperrt |

### `SessionDecision`

| Variant | Felder | Bedeutung |
|---|---|---|
| `Continue` | — (singleton) | Session bleibt aktiv |
| `RequireLogin` | — | Anmeldung erforderlich |
| `Invalidate` | `reason`, `loginRoute` | Session abbrechen + Session-ID-Rotation |

### `SessionPolicyDecision` (Pure-Query-Pfad)

| Variant | Bedeutung |
|---|---|
| `Active` | Session ist gültig |
| `IdleTimeout` | Idle-Limit überschritten |
| `AbsoluteLifetimeExceeded` | Absolutes Lifetime-Limit überschritten |

### `NavigationAccessDecision` (LoginListener-Pfad)

| Variant | Bedeutung |
|---|---|
| `Allowed` | Navigation OK |
| `RerouteToLogin` | Subject fehlt, auf Login leiten |
| `RerouteToDefault` | Subject vorhanden, von Login wegleiten |

### `LoginResult<U>` (Standalone)

| Variant | Felder | Bedeutung |
|---|---|---|
| `Success<U>` | `subject` | Login erfolgreich |
| `Rejected<U>` | — | Credentials abgelehnt |
| `LockedOut<U>` | `decision (LoginAttemptDecision.LockedOut)` | Account gesperrt |

### `InitialAdminCreationResult` (Bootstrap)

| Variant | Felder |
|---|---|
| `Created` | `username` |
| `AlreadyInitialized` | — |
| `InvalidBootstrapToken` | — |
| `PasswordPolicyViolation` | `reason` |
| `InvalidUsername` | `reason` |
| `InternalError` | `reason` |

### `JCustosVersionStatus` (Phase 4c)

| Variant | Felder | Bedeutung |
|---|---|---|
| `Current` | `at` | Session-Snapshot == Store-Current |
| `Drifted` | `snapshot`, `current` | Snapshot != Current; Session muss re-validiert werden |

### `JCustosVersionEnforcer.EnforcementOutcome` (Phase 4c)

| Variant | Felder | Bedeutung |
|---|---|---|
| `Continue` | — | Request darf weiterlaufen |
| `SessionStale` | `status (Drifted)` | Request muss abgelehnt werden — Audit ist bereits emittiert |

### `RateLimitDecision` (Phase 7c)

| Variant | Felder | Bedeutung |
|---|---|---|
| `Allowed` | `eventsInWindow`, `limit`, `window` | Event wurde gezählt, Request läuft weiter |
| `Throttled` | `eventsInWindow`, `limit`, `window`, `retryAfter` | Limit erreicht; `retryAfter` liefert die Lower-Bound für den `Retry-After`-Header |

---

## 6. Audit Events (27 sealed Records)

Alle implementieren `AuditEvent` (sealed interface) und sind über
`AuditQuery.matches(AuditEvent)` pattern-match-fähig.

### Klassisch (V00.60 + früher)

| Event | Wichtige Felder | Wird emittiert von |
|---|---|---|
| `LoginSucceeded` | `username`, `clientAddress`, `sessionId` | `MyAuthenticationService`, REST `login`-Handler, `StandaloneLoginFlow` |
| `LoginFailed` | `username`, `clientAddress`, `reason` | `InMemoryLoginAttemptPolicy.recordFailure`, `StandaloneLoginFlow` |
| `LogoutPerformed` | `subjectId`, `sessionId`, `scope` | `SubjectClearingLogoutService` |
| `AccessGranted` | `subjectId`, `route` | `AuthorizationListener` (Vaadin), `RestAuthorizationFilter` |
| `AccessDenied` | `subjectId`, `route`, `reason` | dito |
| `ActionDenied` | `subjectId`, `actionName` | `StaticActionAuthorizationService.requireAllowed` |
| `BruteForceLimitReached` | `username`, `clientAddress`, `failedAttempts`, `lockoutDuration` | `InMemoryLoginAttemptPolicy` |
| `SessionCreated` | `subjectId`, `sessionId` | `TimeoutSessionPolicy.onLogin` — seit **V00.84** (JS-SEC-060) mit der **post-Rotations-ID**, da `LoginView` vor `onLogin` rotiert |
| `SessionExpired` | `subjectId`, `sessionId`, `reason` | `TimeoutSessionPolicy`, `SessionLifetimeListener`, REST-Filter |
| `SessionInvalidated` | `subjectId`, `sessionId (alt)`, `reason` | `LoginView.notifyOnLogin` (B3-Rotation; seit V00.84 nach `SessionCreated` mit der neuen ID) |
| `RoleAssigned` | `subjectId`, `role`, `assignedBy` | `InMemoryDemoUserDirectory.assignRole`, `DemoUserStore.setRole` |
| `RoleRevoked` | `subjectId`, `role`, `revokedBy` | dito |
| `UserCreated` | `username`, `role`, `createdBy` | `InMemoryDemoUserDirectory.addUser`, `DemoUserStore.create` |
| `UserDeleted` | `username`, `deletedBy` | dito |
| `BootstrapAdminCreated` | `username` | `InitialAdminBootstrapService` auf `Created`-Returns |
| `BootstrapTokenRejected` | `reason` (Unknown / Mismatch / Expired) | dito |
| `PolicyEvaluated` | `subjectId`, `policyName`, `decision`, `reason` | `PolicyRegistry`-Path |
| `StepUpChallenged` | `subjectId`, `route`, `method`, `reason` | `AuthorizationListener` / `RestAuthorizationFilter` bei `StepUpRequired`-Decision |

### V00.70 (Phase 4c / Phase 7 / Phase 8)

| Event | Wichtige Felder | Wird emittiert von |
|---|---|---|
| `SessionStale` | `subjectId`, `sessionId`, `route`, `snapshotVersion`, `currentVersion` | `JCustosVersionEnforcer` bei Drift (Phase 4c) |
| `PasswordResetRequested` | `subjectId`, `tokenHash` | `PasswordResetService.request` (Phase 7a) |
| `PasswordResetCompleted` | `subjectId`, `tokenHash` | `PasswordResetService.consume` |
| `EmailVerificationRequested` | `subjectId`, `email`, `tokenHash` | `EmailVerificationService.request` |
| `EmailVerified` | `subjectId`, `email`, `tokenHash` | `EmailVerificationService.consume` |
| `ApiKeyUsed` | `subjectId`, `keyName`, `keyHash` | `ApiKeyAuthenticationService.authenticate` (Phase 7b) |
| `ApiKeyDenied` | `subjectId`, `keyHash`, `reason` (Unknown/ForeignTenant/Revoked/Expired) | dito |
| `TokenRotated` | `subjectId`, `oldHash`, `newHash` | `TokenService.rotate` |
| `RateLimitExceeded` | `scope`, `subjectId`, `limit`, `window`, `eventsInWindow` | `InMemoryRateLimitPolicy.tryAcquire` bei Throttle (Phase 7c) |

`AuditQuery(types, subjectId, from, to, limit)` mit Factories
`all()`, `ofType(...)`, `forSubject(...)`. `AuditQuery.subjectIdOf`
und `LoggingAuditSink` decken alle 27 Varianten ab.

---

## 7. Audit-Pipeline-Bausteine

| Klasse | Modul | Rolle |
|---|---|---|
| `JCustosAuditService` (Interface) | core | API: `publish(AuditEvent)` + `query(AuditQuery)` |
| `AuditSink` (Interface) | core | Write-only, single-method, never-throws |
| `NoopJCustosAuditService` | core | Default-Fallback wenn keine SPI registriert — seit **V00.84** (JS-SEC-080, CWE-778) einmalige WARN-Meldung `audit/noop-fallback` beim ersten Rückfall; `findJCustosAuditService()` meldet jeden Noop (auch eine frische Instanz) als „nicht konfiguriert“; der DX-Bootstrap meldet fehlendes Audit als `audit/noop-fallback` (STRICT: ERROR, sonst WARNING) |
| `CompositeAuditService` | core | RingBuffer + zusätzliche Sinks; query gegen den RingBuffer |
| `DefaultCompositeAuditService` | core | No-arg, SPI-registrierbar; RingBuffer + LoggingAuditSink |
| `RingBufferAuditSink` | core | Default-Cap 256 Events, älteste fliegen raus, thread-safe |
| `LoggingAuditSink` | core | JUL-basierter Sink, kompaktes `AUDIT type=… field=value …`-Format; seit **V00.84** `sessionRef=` (16 Hex-Zeichen SHA-256) statt der Live-Session-ID (JS-SEC-079, CWE-532) |

---

## 8. Vaadin-Adapter

### Klassen & Listener

| Klasse | Zweck |
|---|---|
| `LoginView` (abstract) | Login-Form mit username/password/remember-me/Login/Cancel + Custom-Slot |
| `LoginListener<U>` (abstract) | `BeforeEnterListener` mit Rollen-/Subject-Lifecycle-Hooks |
| `LoginListeners` | Statischer Resolver für `LoginListener` (SPI + Cache + `setLoginListener`) |
| `AuthorizationListener` (`@ListenerPriority(MAX_VALUE - 1)`) | Annotation-basierter Routenschutz pro Navigation |
| `SessionLifetimeListener` (`@ListenerPriority(MAX_VALUE)`) | Idle/Absolute-Timeout-Enforcement vor Authorization; seit **V00.84** (JS-SEC-082, CWE-613) zusätzlich `RequestHandler` für jeden UIDL-Request (RPC ohne Navigation: Subjekt löschen, `SessionExpired`, Redirect auf die Login-Route, Session schließen) und `VaadinSession.getLastRequestTimestamp()` als Aktivitätssignal |
| `ApplicationServiceInitListener` | Registriert `LoginListener` als `BeforeEnterListener` pro UI |
| `VaadinSessionSubjectStore` | `SubjectStore`-Default — speichert Subject in `VaadinSession.getAttribute` |
| `VaadinLogoutService<U>` | Vaadin-spezifischer `LogoutService` mit Page-Redirect / Session-Close / HTTP-Invalidate |
| `VaadinLogoutGateway` / `DefaultVaadinLogoutGateway` | Thin Wrapper über `UI.getPage().setLocation`, `VaadinSession.close`, `WrappedSession.invalidate` |
| `VaadinAccessContextFactory` | Baut `AccessContext` aus `BeforeEnterEvent`; `subjectId` und `displayName` des `JCustosSubject` seit **V00.84** (JS-SEC-083) aus dem `SubjectIdResolver`, nie aus `toString()` (ohne Resolver: Identitäts-Handle) |
| `VaadinAccessDecisionMapper` / `VaadinNavigationAccessDecisionMapper` | Mappen `AccessDecision` / `NavigationAccessDecision` auf Vaadin-Navigation |
| `JCustosAnnotationScanner` | Scannt Class/Method/AnnotatedElement nach `@JCustosAnnotation`-Meta-Annotation (cached); erbt entlang der Superklassen-Kette **und seit V00.84 entlang der Interfaces** (JS-SEC-081, CWE-862) — die am stärksten abgeleitete Einschränkung gewinnt |

### Login-View-Features

- Stabile Test-IDs: `loginview-tf-username`, `loginview-pf-password`, `loginview-btn-login`, `loginview-btn-cancel`, `loginview-cb-remember-me`
- Custom-Element-Slot via `setCustomElements(Component)` / `clearCustomElements()`
- LUMO-Theme-Variants vorverdrahtet
- `notifyOnLogin()` rotiert die HTTP-Session-ID zuerst über `HttpServletRequest.changeSessionId()` (seit **V00.84**, JS-SEC-060, CWE-384; Fallback `VaadinService.reinitializeSession` nur für Nicht-Servlet-Requests), ruft dann `SessionPolicy.onLogin` mit der **neuen** ID (`SessionCreated` trägt die überlebende ID), auditiert `SessionInvalidated` für die alte ID und ruft den Hook `onSessionRotated(alt, neu)` — dort legen Anwendungen `SessionStore`-Einträge an oder schlüsseln sie um (`SessionStore.rekey`, `SessionRecord.withSessionId`)
- `captureJCustosVersionSnapshot()` (Phase 4c-Followup): wenn sowohl `JCustosVersionStore` als auch `SubjectIdResolver` als SPI registriert sind, liest die View beim erfolgreichen Login die aktuelle `JCustosVersion` und schreibt sie in den `VaadinJCustosVersionContext`. Strict-no-op + exception-swallowing, blockiert den Login-Flow nie.

### Phase-4c JCustosVersion-Enforcement (⚠️)

| Klasse | Zweck |
|---|---|
| `VaadinJCustosVersionContext` (Package `session/vaadin`) | Per-VaadinSession Snapshot-Carrier (`record(subjectId, tenant, snapshot, sessionId)` / `current()` / `clear()`). Survives Session-Rotation. |
| `JCustosVersionEnforcerListener` (`@ListenerPriority(Integer.MAX_VALUE)`) | BeforeEnter-Listener vor `AuthorizationListener`. On Drift: clear snapshot + reroute zur konfigurierten LoginView-Klasse. Seit **V00.84** (JS-SEC-082) auch `RequestHandler`: dieselbe Instanz über `ServiceInitEvent.addRequestHandler` registrieren, dann wird Drift auf jedem UIDL-Request durchgesetzt (Subjekt löschen, Snapshot leeren, `SessionStale`, Redirect, Session schließen) |

### Phase-8a/b Components (`jCustos-vaadin/components/` — ⚠️)

| Klasse | Zweck |
|---|---|
| `SecuredVisibility` + `SecuredVisibilityMode` (HIDE / DISABLE) | Zentraler Decision-Point. `Requirement(requiredRoles, requiredPermissions)` (AND-composed), `Target`-Interface, `apply()` + `isAllowed()`. SPI-backed `currentJCustosView()` resolved via `AuthenticationService.subjectType()` + `SubjectStore` + `AuthorizationService`. Missing SPI → denial. |
| `SecuredButton` (Default DISABLE) | Vaadin-Button-Subklasse. Checkt auf Konstruktor und onAttach; `refresh()` für manuelle Re-Checks. |
| `SecuredRouterLink` (Default HIDE) | Vaadin-RouterLink-Subklasse. Router-explicit Konstruktor für headless tests. |
| `SecuredMenuItem.bind(MenuItem, Requirement, …)` | Binding-Helper, da MenuItem vom Parent-MenuBar erzeugt wird (kein Subclass-Pattern möglich). |
| `SessionManagementView` | Reusable Composite. Grid über `SessionStore.findAll()` (Tenant/Subject/SessionId/Status/Created/LastActivity/Version/Action). Per-Row Revoke via `Consumer<SessionRecord>`. Apps subclassen mit `@Route` + `@RequiresPermission`. **V00.84 (JS-SEC-068, CWE-306):** Drei-Argument-Konstruktor mit `Requirement`; der Revoke-Handler prüft das aktuelle Subjekt serverseitig gegen die Anforderung, auditiert eine Ablehnung als `AccessDenied` und lässt den Store unberührt. |
| `SessionManagementRoute` + `SessionManagementAccess` (`jCustos-dx-vaadin`) | Vom Bootstrap aktivierte Route `/session-management`. **V00.84 (JS-SEC-068):** trägt `@ProtectedBy(SessionManagementAccess)`; der Evaluator prüft die mit `.sessionManagementView(Requirement)` veröffentlichte Anforderung — ohne Anforderung fail-closed (`Forbidden`), ohne Subjekt `Unauthenticated`. `.sessionManagementView()` ohne Anforderung ist deprecated und meldet `session-management-view-without-requirement` (ERROR in PRODUCTION/STRICT, WARNING sonst). Die frühere Deny-by-Default-Ausnahme in `AuthorizationListener` und die Discovery-Ausnahme sind entfallen. |

---

## 9. REST-Adapter

| Klasse | Zweck |
|---|---|
| `RestRequest` / `RestResponse` / `RestHandler` (Interfaces) | Framework-light Abstractions, kein Spring/Jakarta-Servlet-Lock-in |
| `BodyRestRequest` | `RestRequest`-Variante mit Body |
| `BearerTokenExtractor` | Liest `Authorization: bearer <token>` (case-insensitive Scheme) |
| `RestAuthenticationFilter` | "Authenticated-only" Filter — `401 Unauthorized` ohne Subject oder bei abgelaufener Session |
| `RestAuthorizationFilter` | Annotation-basierter Filter — `200`/Handler, `401 Unauthorized` (no subject), `403 Forbidden` (missing role/permission); emittiert AccessGranted / AccessDenied / SessionExpired |
| `RestAccessContextFactory` | Baut `AccessContext` aus `RestRequest` (resourceType="rest-endpoint") |
| `HttpStatusDecisionMapper` | `AuthorizationDecision` → HTTP-Status |
| `BootstrapRestStatusMapper` | Bootstrap-spezifisches Status-Mapping |
| `RestHeaders` | Helper für Header-Lookup |
| `RestJCustosVersionContext` + `RestJCustosVersionFilter` (Phase 4c, ⚠️) | Drift-Filter; `RestSubjectResolver.resolveJCustosVersionContext` als opt-in Default-Methode. Bei Drift: `401 + WWW-Authenticate: SessionStale` (RFC 7235-Style) und Audit-Event. |

### Phase-8d OpenAPI-Metadaten (`jCustos-rest/openapi/` — ⚠️)

| Klasse | Zweck |
|---|---|
| `OpenApiJCustosMetadataGenerator.generate(Class<?>)` | Extrahiert die fünf framework-supplied `@Requires…`-Annotationen aus Handler-Klassen. Produziert eine JSON-freie `HandlerJCustosMetadata`-Struktur, die Apps in ihren eigenen OpenAPI-Build mergen. Custom `@JCustosAnnotation`-Annotationen werden bewusst nicht exportiert (App-spezifische Semantik). |
| `JCustosRequirement` (Record + sealed `Scheme(PERMISSION \| ROLE \| POLICY)` + `Operator(ALL \| ANY)`) | Ein einzelnes Security-Requirement |
| `HandlerJCustosMetadata` (Record) | Class-level + per-method `JCustosRequirement`-Listen |

---

## 10. Standalone-Adapter

| Klasse | Zweck |
|---|---|
| `ThreadLocalSubjectStore` | `SubjectStore`-Default — per-Thread-Bindings, **nicht** inherited |
| `StandaloneLoginFlow<T, U>` | Login-Treiber: konsultiert `LoginAttemptPolicy` → `AuthenticationService` → bindet Subject → emittiert `LoginSucceeded`/`LoginFailed` |
| `SecuredProxy.wrap(Interface, impl)` | JDK Dynamic Proxy — enforce per Methode oder Klasse via `JCustosEnforcer.enforce(method, declaringClass)`; Einschränkungen auf Super-Interfaces werden vererbt, und unter `setDenyByDefault(true)` wird eine Methode ohne Einschränkung abgelehnt, sofern sie oder ihr Interface nicht `@PublicRoute` trägt (seit V00.84, JS-SEC-081) |
| `SecuredProxy.requireAllowed(Class, methodName)` | Single-shot Enforcement für Lambdas/Callbacks |
| `LoginResult<U>` (sealed) | `Success` / `Rejected` / `LockedOut` |

---

## 10b. Method Security via Annotation Processor (`jCustos-processor`)

| Klasse / Datei | Zweck |
|---|---|
| `@Secured` (in jCustos-core, `…/authorization/annotations`) | Compile-Time-Trigger — markiert eine **konkrete Klasse** für die Wrapper-Erzeugung. `RetentionPolicy.SOURCE`, Target `TYPE`. |
| `SecuredAnnotationProcessor` | `BasicStaticProxyAnnotationProcessor<Secured>` aus `com.svenruppert:proxybuilder:00.11.00`. Generiert `<Type>Secured extends <Type>` und ersetzt jede annotierte Methode durch `JCustosEnforcer.require…(…)` + `super.<method>(…)`. Marker am Wrapper: `@GeneratedByProxyBuilder(processor, sourceClass, proxyBuilderVersion="00.11.00", date, comments)` (RUNTIME-reflectable via `proxybuilder-annotations`) + `@DelegatesTo("Owner#method(params)")` pro generierter Methode. |
| `META-INF/services/javax.annotation.processing.Processor` | Registriert den Processor für `javac` / Maven-Compiler. |
| `JCustosEnforcer` (in jCustos-core) | Zentrale Enforcement-API, geteilt mit `SecuredProxy`. Methoden: `requirePermission`, `requireAllPermissions`, `requireAnyPermission`, `requireRole`, `requireAnyRole`, `requirePolicy`; plus die Generic-`enforce(Method, Class)` für den Dynamic-Proxy-Pfad. Wirft `AccessDeniedException` on deny. |

Konsumenten binden das Modul über `<annotationProcessorPaths>` in
`maven-compiler-plugin` ein — nie als reguläre Compile-Dependency, da
der Processor selbst zur Runtime nicht im Classpath stehen muss. Die
generierte `<Type>Secured`-Klasse hat **keine** Restanforderungen ans
Konsumenten-Projekt (`@GeneratedByProxyBuilder` wird im
`writeDefinedClass`-Override gestrippt, weil
`RetentionPolicy.SOURCE`).

Annotation-Mapping (Method-Level wins über Class-Level):

| Annotation | Generierter Enforcer-Call |
|---|---|
| `@RequiresPermission("a")` | `JCustosEnforcer.requirePermission("a")` |
| `@RequiresPermission({"a","b"})` | `JCustosEnforcer.requireAllPermissions("a","b")` |
| `@RequiresAllPermissions({"a","b"})` | `JCustosEnforcer.requireAllPermissions("a","b")` |
| `@RequiresAnyPermission({"a","b"})` | `JCustosEnforcer.requireAnyPermission("a","b")` |
| `@RequiresRole("ADMIN")` | `JCustosEnforcer.requireRole("ADMIN")` |
| `@RequiresRole({"A","B"})` | `JCustosEnforcer.requireAnyRole("A","B")` |
| `@RequiresPolicy("p")` | `JCustosEnforcer.requirePolicy("p")` |

Diagnostics für `@Secured` auf `final` Klassen oder Method-Security-
Annotationen auf `final`/`private`/`static`-Methoden werden vom
proxybuilder-Base-Processor als `Diagnostic.Kind.ERROR` emittiert —
kein Code in `jCustos-processor` selbst nötig.

---

## 11. Subject-Stores im Vergleich

| Adapter | Implementation | Scope | Inheritance |
|---|---|---|---|
| Vaadin | `VaadinSessionSubjectStore` | Vaadin-Session-Attribute | Folgt der VaadinSession |
| REST | anwendungsdefiniert via `RestSubjectResolver` | Pro Request | — |
| Standalone | `ThreadLocalSubjectStore` | Per-Thread | **Nicht** inherited (by design) |

---

## 12. First-Run-Bootstrap

| Komponente | Zweck |
|---|---|
| `BootstrapMode` (enum) | `TRANSIENT_CONSOLE` / `PERSISTENT_FILE` / `DISABLED` |
| `BootstrapConfigurationLoader` | Lädt aus sysprop `security.bootstrap.*` > env > defaults |
| `BootstrapStateService` | `bootstrapRequired()` / `hasAdministrator()` |
| `BootstrapTokenStore` (SPI) | In-Memory oder File-backed (`./data/bootstrap.token`, POSIX 0600) |
| `BootstrapTokenGenerator` | 25-stelliger XXXX-XXXX-…-XXXX-Token, kryptographisch sicher |
| `BootstrapTokenOutput` (SPI) | Console (TRANSIENT) oder File (PERSISTENT) |
| `BootstrapStartup.initializeIfRequired` | Wird beim Service-Init aufgerufen; throw bei `DISABLED && !hasAdmin` |
| `InitialAdminBootstrapService.createInitialAdmin(...)` | Validiert Token, Username (`[A-Za-z0-9._-]{1,64}`), Passwort-Policy; auditiert `BootstrapAdminCreated` / `BootstrapTokenRejected` |
| `AdministratorAccountStore` (SPI) | Persistierung des Admins; im demo-vaadin ein `VaadinAdministratorAccountStore` |
| Konfigurierbare TTL für Token (Default 60 min) | |
| Single-use: Token wird auf `Created` invalidiert | |

---

## 13. Demos — Feature-Matrix

### `demo-vaadin` (Standalone, lokale Auth)

| Feature | Pfad / Klasse |
|---|---|
| Login-View mit Custom-Select | `/login` (`MyLoginView`) |
| Bootstrap-Setup | `/setup` (`SetupView`) |
| AppLayout mit Drawer-Tabs | `/` (`MainView`) — Home / Admin / User roles / Audit log / Nerd Zone / My Area / Public / Playground |
| Role-Admin-UI mit Create/Delete/Assign/Revoke | `/admin/roles` (`AdminRolesView`) |
| Audit-Grid mit Type-Filter | `/audit` (`AuditView`) |
| Rollen | ADMIN, Q_ADMIN, NERD, USER, NOBODY |
| Permissions | `demo:view`, `demo:edit`, `demo:admin`, `audit:read`, `admin:roles` |
| Lockout-Banner mit `formatDuration` | s / min / min+s / h / h+min |
| B3-Rotation auf Login-Success | via `TimeoutSessionPolicy.Config.rotateSessionAfterLogin=true` |

### `demo-rest` (JDK HttpServer + CLI)

| Endpoint | Methode | Auth | Zweck |
|---|---|---|---|
| `/api/bootstrap/status` | GET | open | Bootstrap-Status |
| `/api/bootstrap/admin` | POST | bootstrap-token | Initial-Admin anlegen |
| `/api/login` | POST | open | Token holen |
| `/api/logout` | POST | bearer-token | Token revoken |
| `/api/me` | GET | bearer-token | Aktuelles Subject |
| `/api/operations` | GET | bearer-token | Erlaubte Operationen für Subject |
| `/api/documents` | GET / POST / PUT / DELETE | bearer + `@RequiresPermission` | Dokument-CRUD |
| `/api/admin/status` | GET | `admin:access` | Admin-Status |
| `/api/admin/users` | GET / POST | `admin:roles` | User listen / anlegen |
| `/api/admin/users/{username}` | PUT / DELETE | `admin:roles` | Rolle setzen / User löschen |
| `/api/audit` | GET | `audit:read` | Audit-Events (Query-Params `type`, `subject`) |

Plus CLI-Client (`DemoClient.main`) mit Login, Operation-Listing,
Document-Operations.

### `demo-vaadin-rest-client` (Vaadin-UI gegen `demo-rest`)

- Bootstrap über `/setup` schickt `POST /api/bootstrap/admin` an Backend
- Login schickt `POST /api/login`, cached `RemoteUser` lokal
- Role-Admin-UI gegen Backend (`PUT /api/admin/users/{username}`)
- Audit-View gegen Backend (`GET /api/audit`)
- `HttpDemoBackendClient` als einzige HTTP-fähige Klasse

### `demo-standalone` (CLI)

Zeigt **beide** Method-Security-Pfade nebeneinander:

| Kommando | Permission/Role | Pfad | Service |
|---|---|---|---|
| `list` | `book:list` (MEMBER) | Runtime / Dynamic-Proxy | `LibraryService` (Interface) |
| `borrow <title>` | `book:borrow` (MEMBER) | Runtime / Dynamic-Proxy | `LibraryService` |
| `return <title>` | `book:return` (MEMBER) | Runtime / Dynamic-Proxy | `LibraryService` |
| `add <title>` | `book:add` (LIBRARIAN) | Runtime / Dynamic-Proxy | `LibraryService` |
| `remove <title>` | `@RequiresRole("ADMIN")` | Runtime / Dynamic-Proxy | `LibraryService` |
| `members` | `member:list` (MEMBER) | Compile-Time / `MemberDirectorySecured` | `MemberDirectory` (konkrete Klasse) |
| `invite <name> <email>` | `member:add` OR `member:invite` (LIBRARIAN) | Compile-Time | `MemberDirectory` |
| `remove-member <name>` | `member:remove` AND `member:audit-log` (ADMIN) | Compile-Time | `MemberDirectory` |
| `reset-members` | `@RequiresRole("ADMIN")` | Compile-Time | `MemberDirectory` |
| `help` / `quit` | — | — | UI |

Seeded Users: `admin/admin`, `librarian/librarian`, `alice/alice`.
Bücher (`LibraryService`) werden via `SecuredProxy.wrap(...)` gesichert
(JDK Dynamic Proxy auf das Interface). Members (`MemberDirectory`)
werden via `new MemberDirectorySecured()` instanziiert — die Klasse
wird zur Compile-Zeit vom `SecuredAnnotationProcessor` generiert.
Beide Pfade landen im selben `JCustosEnforcer`.

---

## 14. Test-Infrastruktur

| Toolchain | Modul | Zweck |
|---|---|---|
| `jCustos-test` (eigenes Modul) | core / vaadin / rest / standalone / demo-vaadin / demo-standalone | Wiederverwendbare Fakes (`FakeAuthenticationService`, `FakeAuthorizationService`), `InMemorySubjectStore`, `RecordingAuditSink`, JUnit-5-`JCustosTestExtension`, `AccessContexts` / `JCustosSubjects` / `SyntheticAnnotations`-Helper. Konsumiert per `<scope>test</scope>`. |
| Vaadin Browserless Testing 1.0.0 (`com.vaadin:browserless-test-junit6`) | vaadin / demo-vaadin | UI-Adapter-Tests ohne Browser; `BrowserlessTest`-Basisklasse, `navigate(Class)`, `$view(Class)`, typed Tester (`ButtonTester`, `GridTester`, `ComboBoxTester`, `NotificationTester`, `ConfirmDialogTester`) |
| `com.google.testing.compile:compile-testing` 0.21.0 | jCustos-processor | Annotation-Processor-Tests: `Compiler.javac().withProcessors(...).compile(...)`, `assertThat(compilation).succeeded()`, `generatedSourceFile(...).contentsAsUtf8String().contains(...)`. |
| JUnit Jupiter 6.1.0-M1 | alle | Test-Framework |
| PIT 1.x | alle | Mutation Testing |

### Mutation Coverage (Stand 2026-05-31, V00.70 Refresh)

PIT-Re-Runs für die V00.70-Stacks. Die Library-Module liegen alle
bei ≥ 79 %, drei davon ≥ 95 %. Die nicht voll erreichte
jCustos-vaadin-Marke kommt überwiegend von `VoidMethodCallMutator`-
Mutationen auf Vaadin-Component-Settern in den Phase-8-UI-Klassen
(`SessionManagementView`, `SecuredButton`-Konstruktor-Setup etc.) —
das Entfernen eines `setSizeFull()` / `addClassName(…)` / `add(…)`-
Aufrufs hat keinen testbar-beobachtbaren Effekt im JUnit-Harness.
Das Mutations-Surface ohne UI-Konstruktion liegt deutlich höher.

| Modul | Coverage | Kommentar |
|---|---:|---|
| jCustos-core | **86 %** (1191/1381) | Up from 79 % historisch / 82 % erste V00.70-Messung. `LoggingAuditSinkAllVariantsTest`, `CompositeAuditServiceTest`, `DefaultCompositeAuditServiceTest` ergänzt — Audit-Paket von 39 % auf solid. |
| jCustos-vaadin | **79 %** (242/305) | UI-Konstruktion-Mutationen (`VoidMethodCallMutator` auf Vaadin-Settern in `SessionManagementView` etc.) dominieren die Lücke; Phase-4c `session.vaadin`-Paket bei 91 %, `authorization.impl` bei 91 %. |
| jCustos-rest | **95 %** (86/91) | Unverändert hoch. Phase-4c-Filter + Phase-8d-OpenAPI-Generator vollständig gecovert. |
| jCustos-standalone | **97 %** (33/34) | Unverändert. |
| jCustos-test | (kein PIT-Run; Tests prüfen ihre Fakes direkt) | |
| jCustos-processor | (PIT-Run noch offen — Phase 5c-Followup) | |
| jCustos-persistence-testkit | (kein PIT-Run; Contracts werden über Consumer verifiziert) | |
| jCustos-persistence-eclipsestore | (PIT-Re-Run nach Phase 4a noch offen) | |
| demo-vaadin | 70 % | (alte Messung, vor V00.70-Demo-Glue) |
| demo-rest | 49 % | |
| demo-vaadin-rest-client | 10 % | |
| demo-standalone | 86 % | |

PIT-Property-Fix: Der historische Parent-POM-Typo
`pitest-test-classes=junit.com.svenruppert.*` ließ PIT 0 Tests
finden (sämtliche Mutationen "no coverage"). Bei V00.70 auf
`com.svenruppert.*` korrigiert, sonst zeigt der Re-Run irrführende
0 %-Werte.

### Test-Totals (Stand 2026-05-30, nach Phase-8-Commit)

| Modul | Tests |
|---|---:|
| jCustos-core | 921 |
| jCustos-vaadin | 172 |
| jCustos-rest | 71 |
| jCustos-standalone | 30 |
| jCustos-persistence-eclipsestore | 104 |

Alle Module grün.

---

## 15. Public Helper-Statics

| Static | Modul | Zweck |
|---|---|---|
| `JCustosServiceResolver.<service>()` / `.find<Service>()` / `.set<Service>(...)` / `.resetAll()` | core | Zentrale SPI-Lookup-Fassade |
| `SubjectStores.subjectStore()` / `.findSubjectStore()` / `.setSubjectStore(...)` / `.reset()` | core | SubjectStore-Resolver |
| `LoginListeners.loginListener()` / `.findLoginListener()` / `.setLoginListener(...)` / `.reset()` | vaadin | LoginListener-Resolver |
| `RolePermissionResolver.permissionsForRoles(roles, mapping)` | core | Merge-Helper |
| `RoleMatcher.containsAny(...)` / `.containsAll(...)` | core | Rollen-Matching |
| `PermissionMatcher.matches(...)` / `.containsAll(...)` | core | Permission-Matching (mit Wildcard `resource:*`) |
| `JCustosAnnotationScanner.scan(Class/Method/AnnotatedElement)` | core | Annotation-Resolution mit Cache |
| `Secured.wrap(Class, impl)` / `Secured.requireAllowed(Class, methodName)` | standalone | Dynamic-Proxy-Enforcement |

---

## 16. Was nicht im Scope ist (Roadmap-Negativliste)

- ❌ **Spring Security / Jakarta Security Replacement** — bewusst minimalistisch.
- ❌ **OAuth2 / OIDC / SAML / LDAP / Kerberos** — kann als eigener Adapter
  obendrauf gebaut werden, aber nicht im Kern.
- ❌ **Cluster-Mode out-of-the-box** — Default-Implementations sind
  in-memory + single-node. Die SPIs sind aber so geschnitten, dass
  Redis-/DB-/IAM-Backends als Drop-in laufen würden.
- ❌ **Policy-Composing-DSL** — Annotationen und Code sind die
  Konfigurations-Schicht.
- ❌ **`security-javafx`** — geplant, wartet auf realen JavaFX-Bedarf.
  `jCustos-standalone` deckt funktional Swing / JavaFX / CLI ab.

---

## 17. Versions- & Plattform-Eckdaten

- **Java 26** (Sealed Types, Records, Pattern Matching durchgängig)
- **Vaadin 25.3.3** (vaadin-core, kein Hilla)
- **Jetty 12.1.8 EE11** als Dev-Server für die Vaadin-Demos
- **Maven 4** (pinned via `./mvnw`; Minimum `4.0.0-rc-5`)
- **Eclipse Store 4.1.0** (`org.eclipse.store:storage-embedded`) für
  die durable Persistence-Referenz in `jCustos-persistence-eclipsestore`
- **proxybuilder 00.11.00** (`com.svenruppert:proxybuilder` +
  `proxybuilder-annotations`) für den Compile-Time-Processor
- **Lizenz:** EUPL v1.2
- **Aktuelle Version:** `00.80.00` (Betrieb & Forensik — siehe § 18; §1–§17 dokumentieren den V00.70.00-Kernstand)

---

## 18. V00.80.00 — Betrieb & Forensik (Delta zu §1–§17)

> Die Abschnitte 1–17 beschreiben den V00.70.00-Stand; die Releases
> V00.71–V00.79.41 sind in den jeweiligen `RELEASE-NOTES-*.md` inventarisiert.
> V00.80.00 liefert Konzept-Ziel 9 (Betrieb & Monitoring), Ziel 8
> (Event-Integrationen) und Ziel 7 (Tamper-Evident Audit) — sieben neue
> Module plus Erweiterungen in `jCustos-events`/`jCustos-events-rest`.

### Neue Module (Reaktor: 61)

| Modul | Zweck |
|---|---|
| `jCustos-monitoring` | ⚠️ Ziel 9: `JCustosMetricsPublisher`-SPI (Counter/Gauges, never-throw) + `JCustosMetricNames`-Katalog (9 Konzept-Namen `security.eventbus.*` verbatim + auth/session/audit-Namen) + `MetricsEventBusListener`-Bridge (rejected.total als Umbrella + Drilldowns) + `JCustosHealthIndicator`/`JCustosHealthCheck` (dx-`HealthFinding`-Modell) + `MonitoringDiagnosticContributor` |
| `jCustos-events-webhook` | ⚠️ Ziel 8: `WebhookEventPublisher` — signierte Envelopes per JDK-HttpClient (bounded Queue + Virtual-Thread-Worker, Retry/Backoff+Jitter, Dead-Drop-Counter, Bearer via Supplier nie geloggt, https-Pflicht außer Loopback, bewusst KEIN zweiter HMAC-Layer) |
| `jCustos-events-opentelemetry` | ⚠️ Ziel 8: `OpenTelemetryEventPublisher` — Envelope → OTel-LogRecord via Logs-Bridge-API (api-only, noop-safe); `jcustos.*`-Attribut-Vokabular ohne Payload/Signatur |
| `jCustos-events-siem` | ⚠️ Ziel 8: `SiemEventExporter` (Appendable-basiert — Framework liefert nur Formatting) + `CefEnvelopeFormatter` (CEF:0) / `LeefEnvelopeFormatter` (LEEF 2.0) / `JsonLinesEnvelopeFormatter` (NDJSON, Full-Mode als Opt-in) |
| `jCustos-audit-integrity` | ⚠️ Ziel 7: `AuditChainStore`-SPI (append-only, Linkage-CAS) + `AuditChainEntryHasher` (`jsentinel-audit-chain/v1`, H(prev‖entry)) + `AuditChainAppender` + `InMemoryAuditChainStore` + `AuditIntegrityVerifier` (sealed Result, 5 Break-Reasons, fail-closed) + `SignedAuditBatch`/`AuditBatchSigner`/`AuditBatchVerifier` (events-Key-SPIs, kein zweiter Signing-Stack) + `AuditExportService`/`AuditExportNdjsonCodec` (verifizierbare NDJSON-Exporte) + `AuditIntegrityListener`/`AuditRelevancePolicy`/`HashChainingAuditSink` |
| `jCustos-audit-integrity-testkit` | ⚠️ `AuditChainStoreContract` (`@Test default`-Suite) + `TestkitChainEntries` (korrekt gehashte Ketten-Fixtures inkl. `tampered(...)`) |
| `jCustos-audit-integrity-persistence-eclipsestore` | ⚠️ `EclipseStoreAuditChainStorage.openAt(Path)` — restart-sichere Kette (StorageTreeHardening, RW-Lock); Kette verifiziert über Prozess-Grenzen hinweg |

### Erweiterungen in `jCustos-events` / `jCustos-events-rest`

- ⚠️ **Envelope-Tap**: `SignedEnvelopePublisher`-SPI + `JCustosEventBus.subscribeEnvelope(...)` — EIN Kontrakt für alle Exporter; Fan-out nach Store-Append, Fehler-isoliert (`envelopePublisherFailureCount()`).
- ⚠️ **In-Tree-Publisher**: `LoggingEventPublisher` (named Stream `eu.jsentinel.jcustos.events`), `EventStreamPublisher` (`java.util.concurrent.Flow`), `JCustosAlert`/`JCustosAlertSink`/`LoggingAlertSink`/`JCustosAlertPublisher` (Schwelle default ERROR — kritische Verifikationsfehler erzeugen Alerts).
- ⚠️ **Self-Observability**: Marker `EventBusSelfObservabilityEvent` (die 6 INTEGRITY-Records), `EventBusObservabilityPublisher` (direct-dispatch, nie durch die signierte Pipeline → strukturell rekursionsfrei), `SelfObservabilityEvents.fromVerification(...)` (genau EIN Event pro Fehler; Replay → CRITICAL), `DeadLetterRecorder`.
- ⚠️ **Strict-Mode-Consume-Wiring**: `ConsumeFailureAction`/`ConsumeFailurePolicy` (`strict()` fail-closed / `operationalDefaults()` / Builder) + `ConsumeFailureHandler` (Event + Metrik-Seam + optional Dead-Letter + Operator-Log mit stabilen `events/...`-Codes; Fehlkonfiguration scheitert beim Wiring); `EventPublishService` mit optionalem Handler-Parameter, HTTP-Mapping unverändert.
- ⚠️ **Wire-Codec-Umzug**: `EnvelopeWireCodec`/`EventWireException` jetzt in `eu.jsentinel.jcustos.events.wire` (+ `encodeMetadata(...)`-Projektion ohne Payload/Signatur); events-rest behält einen `@Deprecated(forRemoval)`-Delegator für ein Release. `CanonicalJson` ist public (Export-Codec-Reuse).

### Guides

- `docs/dx/5-minute-setup-monitoring.md`
- `docs/dx/5-minute-setup-event-exporters.md`
- `docs/dx/5-minute-setup-audit-integrity.md`
