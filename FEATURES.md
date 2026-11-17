# jCustos — Feature Catalogue

Vollständige Auflistung aller Funktionen und Erweiterungspunkte
in jCustos 00.84.00 (Stand 2026-11-17). Grundlage ist der
V00.70.00-Kernstand (Tenant/Resource-Modell, 11 Persistence-Store-SPIs,
Contract-Testkit + Eclipse-Store-Referenz-Impl, `JCustosVersion`-Drift-
Detection inkl. automatischem Capture im `LoginView`, Policy-API +
`jCustos-processor`, RoleHierarchy + Any/All-Permission-Annotationen,
Account-Lifecycle / API-Keys / RefreshTokens / Rate-Limit, Phase-8
Secured-Komponenten + `SessionManagementView` + OpenAPI-Metadaten).
§ 18 ergänzt das V00.80.00-Delta, und jede Änderung aus 00.84.00 ist mit
**V00.84** markiert.

00.84.00 behebt die Befunde der Eingangsprüfung und der
Sicherheitsanalyse und bringt außerdem: Login-Throttling als Default mit
Kontoschlüssel im store-backed Pfad, optionalem Adresslimit und
Credential-Check-Gate; Korrelations-IDs in Audit-Datensätzen und
-Zeilen; eine https-Regel und einen begrenzten JSON-Leser für alle
ausgehenden Verbindungen; Pepper aus PKCS12-/PKCS#11-Keystore oder
Schlüsseldateien; Passwort-Blocklisten; ein Sliding-Window mit
korrektem `Retry-After` und optionaler Eskalation (`Blocked`); einen
Origin-Guard gegen CSRF für REST; das sofortige Ende einer Vaadin-Session
bei Versionswechsel; einen Fehlerbehandler, der nur eine Referenz zeigt;
einen Betriebsleitfaden für mehrere Knoten; Vaadin 25.3.3.

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
| `jCustos-core` | `jCustos-core` | Framework-neutrale Kern-Typen, alle SPIs, alle 11 Persistence-Store-Interfaces (Phase 2), `JCustosVersion`-Stack (Phase 4), Audit-Pipeline (27 Variants, seit V00.71 31), Bootstrap, `JCustosEnforcer`, Account-Lifecycle- / Token- / RateLimit-Services (Phase 7) |
| `jCustos-vaadin` | `jCustos-vaadin` | Vaadin-Flow-Adapter: Navigation, Login, Session, Logout — plus Phase-8 `SecuredButton` / `SecuredRouterLink` / `SecuredMenuItem` / `SessionManagementView` und Phase-4c `JCustosVersionEnforcerListener` |
| `jCustos-rest` | `jCustos-rest` | Framework-light REST-Adapter (Filter, BearerToken, HTTP-Status-Mapping, Step-Up `WWW-Authenticate`) — plus Phase-4c `RestJCustosVersionFilter` und Phase-8d `OpenApiJCustosMetadataGenerator` |
| `jCustos-standalone` | `jCustos-standalone` | Plain-Java / Desktop / CLI Adapter (ThreadLocal-Subject, `SecuredProxy` Dynamic-Proxy) |
| `jCustos-test` | `jCustos-test` | Wiederverwendbare Test-Fixtures: `FakeAuthenticationService`, `FakeAuthorizationService`, `InMemorySubjectStore`, `RecordingAuditSink`, JUnit-5-`JCustosTestExtension`. Test-Scope-Dependency. |
| `jCustos-processor` | `jCustos-processor` | Compile-Time-Annotation-Processor: erzeugt `<Type>Secured`-Subklassen für `@Secured`-annotierte konkrete Klassen. Wird als `<annotationProcessorPath>` eingebunden. Basiert auf `com.svenruppert:proxybuilder:00.11.01` + `proxybuilder-annotations:00.11.01` (seit **V00.84**; 00.11.00 der Annotations wurde nie veröffentlicht, JS-SEC-141). |
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
Seit **V00.84** übernehmen auch die DX-Bootstraps
(`RestSecurity`/`StandaloneSecurity`/`VaadinSecurity.bootstrap().install()`)
einen per `META-INF/services` (etwa `@JCustosAutoService`) registrierten
`AuthenticationService`/`AuthorizationService` — der REST-Bootstrap auch den
`RestSubjectResolver` — und listen ihn mit der Quelle `spi-registered`, statt
`missing-authentication-service`/`missing-authorization-service` zu melden;
mehrere registrierte Implementierungen sind der ERROR
`ambiguous-authentication-service`/`ambiguous-authorization-service`
(`ambiguous-rest-subject-resolver`).

### DX-Bootstrap-Befunde (neu oder geändert in V00.84)

`install()` meldet Fehlkonfigurationen als Befunde; ein ERROR lässt den
Start scheitern. Neu oder geändert in 00.84.00 (Auswahl; die übrigen
Befunde dieses Releases stehen bei ihrem Baustein):

| Befund | Schweregrad | Auslöser |
|---|---|---|
| `authorization/allow-by-omission` | ERROR in STRICT, WARNING in PRODUCTION | `.denyByDefault(true)` fehlt (JS-SEC-085); die Starter-Profile `productionDefaults()`/`strictDefaults()` setzen es selbst |
| `bruteforce/in-memory-with-shared-sessions` | WARNING in PRODUCTION und STRICT | Sessions store-backed, Login-Policy aber `InMemoryLoginAttemptPolicy` (auch der Resolver-Default) — jeder Knoten zählt für sich (JS-SEC-166, siehe `docs/security/deployment/cluster.md`) |
| `bruteforce/address-limit-without-resolver` | WARNING | Policy mit Adresslimit, aber kein `ClientAddressResolver` registriert; ohne Proxy bestätigt `.clientAddress(ClientAddressResolver.remoteAddress())` den Verbindungs-Peer (JS-SEC-062) |
| `audit/no-subject-id-resolver` | ERROR in STRICT, sonst WARNING | Vaadin-Bootstrap ohne eindeutig auflösbaren `SubjectIdResolver` (JS-SEC-097) |
| `credentials/pepper-active-key-unresolvable` | ERROR | aktive Key-ID des Peppers löst nicht auf mindestens 32 Byte auf (JS-SEC-162) |
| `rest/credentialed-cors-without-origin-guard` | WARNING in PRODUCTION und STRICT, sonst INFO | CORS mit `allowCredentials(true)` ohne installierten `RestOriginGuard` (JS-SEC-163) |
| `rest/session-revocation-inert` | WARNING | `.storeBacked(...)` am REST-Bootstrap, aber der `RestSubjectResolver` behält den Default von `resolveSessionId` (JS-SEC-131) |
| `jwks/uri-not-https` (seit V00.84 verschärft) | ERROR | JWKS-URI ohne https; `http` zu einem Loopback-Host nur mit `-Djcustos.dev=true` (dann INFO), auch im DEVELOPMENT-Modus (JS-SEC-098) |

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
| `CorrelationIdResolver` ⚠️ | core/audit | `TrustedPeerCorrelationIdResolver` | **V00.84** (JS-SEC-066, CWE-778): entscheidet die Korrelations-ID eines Requests. Der Default übernimmt `X-Request-ID` nur, wenn der Verbindungs-Peer ein Proxy ist, dem der registrierte `ClientAddressResolver` vertraut (`trustsPeer`), nur aus genau einer Headerzeile und nur mit 1–128 Zeichen aus `[A-Za-z0-9._:-]` (`AuditEnvelope.MAX_CORRELATION_ID_LENGTH`, `isValidCorrelationId`); sonst erzeugt der Server eine UUID. Auflösung über `JCustosServiceResolver.correlationIdResolver()` / `findCorrelationIdResolver()` / `setCorrelationIdResolver(...)`, DX `.correlationIds(resolver)` |

### Brute-Force & Sessions

| SPI | Modul | Default | Zweck |
|---|---|---|---|
| `LoginAttemptPolicy` | core | `InMemoryLoginAttemptPolicy` (seit **V00.84 auch Resolver-Default** statt `NoopLoginAttemptPolicy`: fünf Fehlversuche in 15 min sperren 15 min, verdoppelnd bis 4 h; ein ausdrücklich registrierter Noop meldet `bruteforce/noop-policy` — JS-SEC-124) | Login-Throttling + Lockout-Entscheidungen. Seit **V00.84** (JS-SEC-123) reserviert ein erlaubtes `beforeAttempt` den Versuch; danach folgt genau eines von `confirmSuccess`/`recordSuccess`, `recordFailure` oder `abandonAttempt`, `peek` liest ohne Reservierung. `recordFailure(context[, reason])` ist der einzige Audit-Punkt für `LoginFailed`; die Schlüssel laufen über `SubjectKeyCanonicalizer` (`alice` = `ALICE`). Ebenfalls seit **V00.84**: die Default-Methode `credentialCheckGate()` liefert ein `CredentialCheckGate` (Default unbegrenzt, JS-SEC-063), und beide mitgelieferten Policies nehmen ihre Grenzwerte als `LoginAttemptLimits` inklusive optionalem Adresslimit (JS-SEC-062) — siehe den folgenden Abschnitt |
| `ClientAddressResolver` | core | `DefaultClientAddressResolver` (Verbindungs-Peer, kein Header) | **V00.84** (JS-SEC-061, CWE-348): entscheidet, welche Adresse Throttling, Abuse-Erkennung und Audit-Zeilen schlüsselt. `TrustedProxyClientAddressResolver` wertet `X-Forwarded-For` nur von konfigurierten Proxys (Adressen/CIDR) aus, liest von rechts, ignoriert `Forwarded`/`X-Real-IP`. Default-Methode `trustsPeer(request)` (für `TrustedPeerCorrelationIdResolver`, JS-SEC-066); `ClientAddressResolver.remoteAddress()` bestätigt ohne Proxy ausdrücklich den Verbindungs-Peer. Adapter: `VaadinClientAddress`, `RestClientAddress`, `RestRequest.remoteAddress()`, DX `.clientAddress(...)`. Doku: `docs/security/deployment/reverse-proxy.md`, für eingebettetes Jetty `docs/security/deployment/reverse-proxy-embedded-jetty.md` |
| `SessionPolicy<U>` | core | `TimeoutSessionPolicy` (seit **V00.84 auch Resolver-Default**: 30 min Leerlauf, 12 h Gesamtlebensdauer, Rotation nach Login, Login-Route aus dem Resolver — JS-SEC-065; `NoopSessionPolicy` ist der ausdrückliche Opt-out) | Lifecycle-Hooks + Idle/Absolute-Timeout |

### Login-Throttling: Grenzwerte, Schlüssel und Gate (seit V00.84 — ⚠️)

| Klasse | Modul | Zweck |
|---|---|---|
| `LoginAttemptLimits` + `LoginAttemptLimits.AddressLimit` | core/bruteforce | Nachfolger der unveränderten `LoginAttemptConfiguration` (JS-SEC-062, CWE-307): Grenzwerte pro Konto (`perAccount`), optionales Adresslimit (`perAddress`) und das Credential-Check-Gate (`maxConcurrentCredentialChecks`, `gateWait`, `gateRetryAfter`). `defaults()`, `withAddressLimit(...)`, `withMaxConcurrentCredentialChecks(...)`, `withGateWait(...)`, `withGateRetryAfter(...)`; neue Konstruktoren beider Policies. Mit Adresslimit führen beide Policies einen dritten Zähler nur auf der Client-Adresse (eigener Schwellwert, eigenes Fenster, eigene Sperre); eine Adresssperre wird als `BruteForceLimitReached` mit leerem Benutzernamen auditiert. Konfiguration auch über `security.login.attempts.address.threshold` (plus `.window`, `.initial-lockout`, `.max-lockout`) und `LoginAttemptConfigurationLoader.loadLimits()`. Ohne Konfiguration ändert sich nichts; `StandaloneLoginFlow` kennt keine Client-Adresse |
| `CredentialCheckGate` | core/bruteforce | Begrenzt gleichzeitige Credential-Prüfungen (JS-SEC-063, CWE-770). `enter()` liefert `Admission.Entered` (nach der Prüfung schließen) oder `Admission.Deferred(retryAfter)`: findet ein Login innerhalb von `gateWait` (Default 250 ms, höchstens 10 s) keinen freien Platz, wird er zurückgestellt — keine Prüfung, Reservierung zurückgegeben, kein Fehlversuch gezählt, `RateLimitExceeded` mit dem Scope `login:credential-check` (`AUDIT_SCOPE`). `LoginView` und `StandaloneLoginFlow` betreten das Gate nach `beforeAttempt`; Konfiguration über `security.login.attempts.max-concurrent-checks`, `.gate-wait`, `.gate-retry-after` |
| `LoginAttemptKey.forAccount(tenant, name)` / `.forAddress(tenant, ip)` | core/bruteforce | Reservierte Schlüssel des store-backed Pfads: Kontoschlüssel mit User-ID `#account:` + kanonischer Name und Adresse `#any` (`accountScoped()`, JS-SEC-166), Adressschlüssel mit User-ID `#address` (JS-SEC-062). Benutzernamen, die mit `#` beginnen, maskiert `accountUserId(...)`. Ein eigener `LoginAttemptStore` muss diese Schlüssel unverändert speichern |
| `ConstantCostCredentialCheck.verify(storedHash, password, pipeline)` | core/credential/password | Zeitvertrag für `checkCredentials` (JS-SEC-064, CWE-208): prüft gegen den gespeicherten Hash und führt ohne Konto (oder bei leerem Hash) die Dummy-Verifikation der Pipeline unter derselben Policy und demselben KDF-Limiter aus; ein unbekanntes Konto kostet etwa so viel wie ein bekanntes mit falschem Passwort. Ein abgewiesener Dummy-Lauf ergibt `TEMPORARILY_UNAVAILABLE` |
| `CredentialCheckDeferredException` | standalone | Unterklasse von `CredentialVerificationUnavailableException` mit `retryAfter()`; wirft `StandaloneLoginFlow`, wenn das Gate den Login zurückstellt |

### Logout

| SPI | Modul | Default | Zweck |
|---|---|---|---|
| `LogoutService` | core | `NoopLogoutService` / `SubjectClearingLogoutService` (der Noop-Rückfall wird seit **V00.84** einmalig als `logout/noop-fallback` gemeldet; der DX-Bootstrap meldet `logout/missing-service` — WARNING, ERROR in PRODUCTION/STRICT, JS-SEC-124) | Zentraler Logout-Treiber mit Fan-out |
| `LogoutListener` | core | — (Anwender-Erweiterung) | Post-logout Side-Effects (Token-Revoke etc.) |
| `SubjectSessionRegistry` | core | `InMemorySubjectSessionRegistry` | Multi-Session-Tracking pro Subject (für `AllSessionsOfSubject`-Scope) |

### Passwort & Bootstrap

| SPI | Modul | Default | Zweck |
|---|---|---|---|
| `PasswordHasher` | core | `Pbkdf2PasswordHasher` (seit **V00.84** 600 000 Iterationen aus `Pbkdf2Defaults`, JS-SEC-072; `verify` prüft Iterationszahl und Salt-Länge gegen die Grenzwerte, bevor abgeleitet wird) | Hashing + Drift-Detection (`needsRehash`); Legacy-Drahtformat `pbkdf2$…`, neue Anwendungen nutzen `PasswordHashingServices.defaults()` |
| `PasswordHashProvider` | core | `Pbkdf2PasswordHashProvider`; Argon2id/bcrypt/scrypt über `jCustos-crypto-bc` | Algorithmus-Provider der Credential-Pipeline (`PasswordHashingService`). Seit **V00.84** Default-Methode `rehashHint(PasswordHashEnvelope)`: ein Provider meldet Schwächen, die nur er kennt, `needsRehash` wertet den Hinweis nach der Parameterprüfung der Policy aus; `BcryptPasswordHashProvider` meldet jede Hülle ohne `term=1` als `PARAMETERS_OUTDATED` (JS-SEC-133) |
| `PasswordPolicy` | core | `MinimumLengthPasswordPolicy(8)` | Passwort-Mindestlängen-Validierung |
| `AdministratorAccountStore` | core | anwendungsdefiniert | Persistierung des Bootstrap-Admins |
| `BootstrapTokenStore` | core | `InMemoryBootstrapTokenStore` / `FileBootstrapTokenStore` | Token-Persistenz für First-Run-Bootstrap; `FileBootstrapTokenStore` übernimmt seit **V00.84** nur eine Datei, die er selbst geschrieben haben kann (POSIX: reguläre Datei des Prozessnutzers ohne Rechte für Gruppe/andere; Token im Generatorformat), sonst entsteht ein neuer Token (JS-SEC-130) |
| `BootstrapTokenOutput` | core | `ConsoleBootstrapTokenOutput` / `FileBootstrapTokenOutput` | Token-Ausgabe an Operator |

### Credential-Pipeline: Pepper und kompromittierte Passwörter (seit V00.84 — ⚠️)

| Klasse | Modul | Zweck |
|---|---|---|
| `KeyStorePepperService` | core/credential/password/pepper | Pepper-Schlüssel aus einer PKCS12-Datei (`fromPkcs12(path, password)`) oder einem von der Anwendung geladenen Keystore, etwa einem PKCS#11-Token (`fromKeyStore(keyStore, entryPassword)`); `activeAlias(...)`, beliebig viele `retiredAlias(...)`, dann `load()`. Key-ID ist der Alias, zeichengenau verglichen (JS-SEC-162, CWE-916/CWE-522) |
| `FilePepperService` | core/credential/password/pepper | Ein Base64-Schlüssel pro Datei und Key-ID aus einem Verzeichnis wie `/run/secrets` (`fromDirectory(dir)`, `activeKeyId(...)`, `retiredKeyId(...)`, `load()`). Wie der Keystore-Pfad scheitert `load()` geschlossen: fehlende, fremde, für Gruppe oder andere lesbare, verlinkte, zu große oder nicht Base64-kodierte Datei, oder ein Schlüssel unter 32 Byte stoppt den Start; kein Schlüsselmaterial in Meldungen, Logs oder `toString()` |
| `BouncyCastleHashingServices.modern(PepperService)` / `modern(policy, limiter, pepper)` | crypto-bc | Argon2id mit Pepper. Der DX-Bootstrap setzt `.pepper(p)` in die Pipeline von `.modern()` oder `.pbkdf2Defaults()` ein und listet ihn in `JCustosRuntime.services()`; bestehende Hashes ohne Pepper melden `PEPPER_KEY_ROTATED` und werden beim nächsten Login neu kodiert. Neben `.hashing(instance)` bleibt `dx/credential-pepper-recorded-not-wired` |
| `LocalBlocklistCompromisedPasswordChecker.fromFile(path)` / `.fromLines(stream)` | core/credential/compromised | Lokale Blocklist aus einer Datei: strikt UTF-8, ein Passwort pro Zeile, Leerzeilen und `#`-Kommentare übersprungen, Grenzen `MAX_FILE_BYTES` (64 MiB), `MAX_ENTRIES` (2 000 000), `MAX_LINE_LENGTH` (256); eine Liste jenseits einer Grenze wird als Ganzes abgelehnt, die Meldung nennt nie eine Zeile. Verglichen wird in `PasswordNormalizer.comparisonForm` (NFKC, dann Kleinschreibung unter `Locale.ROOT`). jCustos liefert keine Liste mit (JS-SEC-164, CWE-521) |
| `CompositeCompromisedPasswordChecker.of(CheckFailurePolicy, ...)` | core/credential/compromised | Fragt seine Prüfer der Reihe nach (etwa lokale Liste, dann `HaveIBeenPwnedCompromisedPasswordChecker`) und liefert den ersten Treffer; ein ausgefallener Prüfer zählt unter `ALLOW`/`WARN` als unauffällig und wird unter `BLOCK` als `CheckFailed` zurückgegeben |
| `CompromisedPasswordScreen` | core/credential/compromised | Der Prüfschritt, den `PasswordChangeService` und `credential.reset.PasswordResetService` nach `withCompromisedPasswordCheck(checker, policy)` ausführen — nach der Strukturprüfung, vor dem ersten KDF-Lauf; öffentlich für Adapter, die Passwörter an anderer Stelle setzen. Ein gelistetes Passwort ergibt beim Ändern `NewPasswordRejected(PasswordInputViolation.COMPROMISED)`, beim Reset `Failed`, ohne den Token zu verbrauchen; eine nicht durchführbare Prüfung folgt `CompromisedPasswordPolicy.onFailure()` |
| `PasswordInputViolation.COMPROMISED` | core/credential/input | Neue Konstante; ein erschöpfendes `switch` braucht einen weiteren Zweig |

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
| `RestSubjectResolver` | rest | Request → `Optional<JCustosSubject>` + `SessionMetadata` + (Phase 4c) optionaler `RestJCustosVersionContext`; seit **V00.84** Default-Methode `resolveSessionId(request)` — liefert sie eine Session-ID, prüfen die REST-Filter den `SessionStore`-Datensatz auf Widerruf (JS-SEC-131) |

### Persistence-Stores (Phase 2 — alle 11 ⚠️ `@ExperimentalJCustosApi`)

Jeder Store hat ein `InMemory*Store`-Default in `jCustos-core` und
eine Eclipse-Store-Referenz-Impl in `jCustos-persistence-eclipsestore`,
beide verifiziert über `jCustos-persistence-testkit`-Contract-Tests.

| Store | Modul / Package | Record / Key | Zweck |
|---|---|---|---|
| `AuditEventStore` | core/audit | `AuditEnvelope` | Persistente Audit-Events; Query-API. Seit **V00.84** (JS-SEC-066) trägt `AuditEnvelope` die vierte Komponente `correlationId` (der Drei-Argument-Konstruktor bleibt, Record-Patterns mit drei Komponenten kompilieren nicht mehr); neue Methode `append(TenantId, AuditEvent, String correlationId)` — ihr Default verwirft die ID, ein eigener Store muss sie überschreiben (`AuditEventStoreContract` prüft das). In-Memory- und Eclipse-Store-Store speichern die ID; ältere Envelopes laden ohne |
| `SessionStore` | core/session | `SessionRecord` keyed on `SessionId` | Persistente Sessions + `findAll()` für Admin-Views; seit **V00.84** (JS-SEC-131) liest die Widerrufsprüfung (`VaadinSessionRevocation`, `RestSessionRevocation`) den Datensatz pro Request — `REVOKED` oder ein gesehener und danach entfernter Datensatz beendet die Session, `EXPIRED` allein nicht; Datensätze unter `SessionRef.of(id)` statt der Live-ID ablegen (JS-SEC-117) |
| `LoginAttemptStore` | core/bruteforce | `LoginAttemptKey(tenant, userId, ip)` | Brute-Force-Versuche, store-backed flacher Lockout; seit **V00.84** vier atomare Versuchs-Operationen als `default`-Methoden, der In-Memory-Store ist hart begrenzt und verdrängt keinen gesperrten Schlüssel (JS-SEC-122, JS-SEC-123). Neben dem Tupel-Schlüssel (Benutzername, Adresse) speichert der Store seit **V00.84** die reservierten Schlüssel `LoginAttemptKey.forAccount(...)` (Konto über alle Adressen, JS-SEC-166) und `forAddress(...)` (Adresslimit, JS-SEC-062); der In-Memory-Store und der Eclipse-Store-Adapter führen die Grenzwerte von Konto- und Adressschlüsseln getrennt. `LoginAttemptStoreContract` prüft zwei Knoten auf einem Store (`secondNodeStore(store)`) |
| `RoleAssignmentStore` | core/authorization/api/roles | `RoleAssignmentKey(tenant, subjectId)` → `Set<RoleName>` | Persistente Rollen-Zuordnungen |
| `BootstrapStateStore` | core/bootstrap | `BootstrapState` per Tenant | "Ist das System bootstrapped?" — idempotent |
| `RememberMeTokenStore` | core/authentication | `RememberMeTokenRecord` (hash-only) | Persistent-Login-Tokens; seit **V00.84** `markRotated`/`findRotated` als Spur getauschter Tokens für die Replay-Erkennung — beide mitgelieferten Stores führen sie (JS-SEC-128) |
| `PasswordResetTokenStore` | core/accountlifecycle | `PasswordResetTokenRecord` (hash-only, single-use); `InMemoryPasswordResetTokenStore` seit **V00.84** kapazitätsbegrenzt (`CapacityBound`, Subjekt-Index, JS-SEC-074) | Passwort-Reset-Flow |
| `EmailVerificationTokenStore` | core/accountlifecycle | `EmailVerificationTokenRecord` (hash-only, single-use); `InMemoryEmailVerificationTokenStore` seit **V00.84** kapazitätsbegrenzt (JS-SEC-074) | Email-Verifikations-Flow |
| `ApiKeyStore` | core/authentication | `ApiKeyRecord` (hash-only, mit Scopes) | Long-Lived API-Keys |
| `RefreshTokenStore` | core/authentication | `RefreshTokenRecord` (hash-only, rotating mit `markReplaced`) | Rotating Refresh-Tokens mit Replay-Defense; seit **V00.84** atomares `rotate(oldHash, successor, now)` und eine „invalid before“-Marke nach `revokeAll` (JS-SEC-129) |
| `RateLimitStore` | core/ratelimiting | Events unter `RateLimitKey(tenant, scope)` | Event-basierter Sliding-Window-Counter; seit **V00.84** prüft und zählt `tryAdmit(key, at, since, limit)` in einem Schritt (CWE-367) — atomar im In-Memory- und im Eclipse-Store-Store, Events mit gleichem Zeitpunkt zählen einzeln, es werden genau `limit` Anfragen zugelassen (JS-SEC-078, JS-SEC-118). Beide Stores sind begrenzt, verdrängen den am längsten nicht benutzten Schlüssel und halten höchstens 10 000 Events pro Schlüssel (`InMemoryRateLimitStore.DEFAULT_MAX_EVENTS_PER_KEY`; an der Grenze lehnt `tryAdmit` ab); `maxEventsPerKey()` nennt die Grenze, und `InMemoryRateLimitPolicy` lehnt ein höheres Limit beim Bau ab. Ebenfalls seit **V00.84** (JS-SEC-165): `Admission` trägt `oldestInWindow` (`Optional<Instant>`) für ein korrektes `retryAfter`, und die Default-Methoden `blockedUntil(key)` / `block(key, until)` halten die Sperren einer `RateLimitEscalation` — beide mitgelieferten Stores atomar, der Eclipse-Store-Store über einen Neustart hinweg; die Defaults werfen `UnsupportedOperationException`. `RateLimitStoreContract` prüft ältestes Event, Sperren und zwei Knoten auf einem Store (`reportsOldestInWindow()`, `keepsBlocks()` als Opt-out) |

### JCustosVersion / Drift Detection (Phase 4 — ⚠️)

| SPI / Klasse | Modul | Default | Zweck |
|---|---|---|---|
| `JCustosVersionStore` | core/session | `InMemoryJCustosVersionStore` + Eclipse-Store-Impl | Monotonic counter pro `(TenantId, SubjectId)`; `current` / `increment` / `reset` |
| `JCustosVersionCheck` | core/session | — (pure helper) | Vergleicht Session-Snapshot vs. Store-Current → `JCustosVersionStatus(Current \| Drifted)` |
| `JCustosVersionEnforcer` | core/session | — (pure helper) | Adapter-neutral; emittiert `SessionStale`-Audit; `EnforcementOutcome(Continue \| SessionStale)` |
| `JCustosVersionChangeListener` | core/session | — | **V00.84** (R8, JS-SEC-167, CWE-613): `onChange(JCustosVersionKey, JCustosVersion)` — Benachrichtigung über eine Versionsänderung |
| `ObservableJCustosVersionStore` | core/session | — (Opt-in-Dekorator) | **V00.84** (R8, JS-SEC-167): speichert über den umhüllten Store und benachrichtigt danach seine Listener (`addListener`/`removeListener`) auf dem aufrufenden Thread — nach `increment` mit der neuen Version, nach `reset` mit `INITIAL`. Eine vom Store abgelehnte Änderung wird nicht gemeldet; ein werfender Listener wird geloggt, die Änderung bleibt bestehen. Knotenlokal: andere Knoten am selben Store bemerken die Änderung erst bei ihrem nächsten Request. Registrierung: `.sessions(s -> s.securityVersion(new ObservableJCustosVersionStore(store)))`, Versionen nur noch über diese Instanz ändern; Vaadin-Gegenstück `VaadinJCustosVersionChangeBridge` (§ 8) |

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
| `TokenService` | core/authentication | `issue(subject)` / `rotate(refresh)` / `revoke(refresh)` über `RefreshTokenStore`; chain-link via `markReplaced` mit Replay-Defense; emittiert `TokenRotated` auf erfolgreicher Rotation; seit **V00.84** (JS-SEC-071, CWE-367/CWE-294) atomarer Claim **vor** dem Ausstellen (zwei nebenläufige Rotationen → genau ein Paar), Replay eines verbrauchten Tokens sperrt die Token-Familie und auditiert `CredentialVerificationFailed(REFRESH_TOKEN_REPLAY)`; Claim und Nachfolger laufen seit JS-SEC-129 in einem Schritt über `RefreshTokenStore.rotate`, ein Logout oder `revokeAll` während der Rotation geht nicht mehr verloren |

### Rate-Limiting (Phase 7c — ⚠️)

| SPI / Klasse | Modul | Default | Zweck |
|---|---|---|---|
| `RateLimitPolicy` | core/ratelimiting | `InMemoryRateLimitPolicy` (Sliding-Window) | Per-Scope Rate-Limit (getrennt von `LoginAttemptPolicy`); `tryAcquire(RateLimitKey)` → `RateLimitDecision(Allowed \| Throttled \| Blocked)`; `tryAcquire` nutzt seit **V00.84** `RateLimitStore.tryAdmit` und lässt je Fenster genau `limit` Anfragen zu, auch bei parallelen Aufrufen (JS-SEC-078, JS-SEC-118). Seit **V00.84** (JS-SEC-165) ist `Throttled.retryAfter` die Zeit, bis das älteste Event das Fenster verlässt (`oldest + window - now` plus `MIN_RETRY_AFTER`, eine Nanosekunde), statt des ganzen Fensters; ein Store ohne `oldestInWindow` liefert weiter das ganze Fenster. `Blocked` tritt nur mit einer `RateLimitEscalation` auf. Wer nur auf `instanceof Throttled` prüft, lässt ein `Blocked` durch — alles ablehnen, was nicht `Allowed` ist, oder `RestRateLimit.respond` nutzen (§ 9). `.rateLimit(...)` an den DX-Bootstraps bleibt aufgezeichnet, aber nicht verdrahtet (JS-SEC-055) |
| `RateLimitEscalation` | core/ratelimiting | — (Opt-in) | **V00.84** (JS-SEC-165, CWE-799): `new RateLimitEscalation(throttleThreshold, escalationWindow, blockDuration)` im Konstruktor von `InMemoryRateLimitPolicy` sperrt einen Schlüssel, der innerhalb von `escalationWindow` `throttleThreshold`-mal gedrosselt wurde, für `blockDuration`. Während der Sperre antwortet die Policy mit `Blocked`, zählt nichts und publiziert `RateLimitExceeded` für jede Ablehnung; `reset` hebt die Sperre auf. Die Drosselungen zählt derselbe Store unter dem reservierten Scope-Präfix `#throttled:` (`THROTTLE_SCOPE_PREFIX`) über `tryAdmit`; ein Store ohne `blockedUntil`/`block` wird beim Bau abgelehnt |

### Store-backed Services (Phase 4b — ⚠️)

Alle nutzen die Phase-2 Stores als Backing-Store, sind tenant-scoped
und schlucken Persistence-Fehler im Audit/Notification-Pfad, damit
sie die Security-Flow-Auswertung nie blockieren.

| Service | Modul | Backing-Store |
|---|---|---|
| `StoreBackedJCustosAuditService` | core/audit | `AuditEventStore`; speichert seit **V00.84** die Korrelations-ID des Requests mit dem Envelope (`AuditCorrelation`, JS-SEC-066) |
| `StoreBackedLoginAttemptPolicy` | core/bruteforce | `LoginAttemptStore` (flacher Lockout); seit **V00.84** Konstruktor mit Audit-Service, `recordFailure` publiziert `LoginFailed`, ein Zähler verfällt nach einem vollen `window()` ohne Fehlversuch (JS-SEC-122, JS-SEC-123), und eine Sperre, die ein Fehlversuch auslöst, wird als `BruteForceLimitReached` auditiert. Seit **V00.84** (JS-SEC-166, CWE-307) zählt die Policy jeden Versuch zusätzlich auf dem Kontoschlüssel `LoginAttemptKey.forAccount(tenant, name)` — ein Konto wird nach `failureThreshold` Fehlversuchen von beliebigen Adressen für `initialLockout` gesperrt – so sperrt auch die In-Memory-Policy seit jeher; einen Schalter dagegen gibt es nicht. Gefragt werden Tupel, Konto und — mit Adresslimit — Adresse in dieser Reihenfolge; eine Ablehnung gibt die bereits gemachten Reservierungen zurück. Jeder Versuch belegt zwei Store-Schlüssel (drei mit Adresslimit). Knoten, die einen Store teilen, wirken als eine Drossel: `docs/security/deployment/cluster.md` |
| `StoreBackedSubjectSessionRegistry` | core/logout | `SessionStore` + optionaler `JCustosVersionStore` (Phase-4c-Snapshot beim Register); seit **V00.84** bindet `register` eine wiederverwendete Session-ID bei fremdem Subjekt oder nicht-aktivem Status neu statt aufzufrischen (JS-SEC-075) |
| `StoreBackedRoleAuthorizationService<U>` | core/authorization/api/roles | `RoleAssignmentStore` (generic über Subject-Type) |
| `StoreBackedRememberMeService` | core/authentication | `RememberMeTokenStore` + `PasswordHasher`; seit **V00.84** tauscht `rotate` das Token bei jeder Nutzung, ein bereits getauschtes Token widerruft alle Remember-me-Tokens des Subjekts und auditiert `SessionInvalidated` mit Grund `RememberMeTokenReplay` (JS-SEC-128) |
| `StoreBackedBootstrapStateService` | core/bootstrap | `BootstrapStateStore` (idempotentes `markCompleted`) |

### Ausgehende Verbindungen: eine https-Regel, ein JSON-Leser, ein Form-POST (seit V00.84 — ⚠️)

Seit **V00.84** (ER31, JS-SEC-098, CWE-1041/CWE-770) gibt es jede dieser
Regeln genau einmal in `jCustos-core`; die Release-Gate-Stufe
`definitions` (`scripts/single-definitions.py`) schlägt fehl, sobald eine
davon in den Library-Quellen eine zweite Definition bekommt.

| Klasse | Modul / Package | Zweck |
|---|---|---|
| `EndpointSecurity` | core/net | `requireHttps(uri, errorCode)` ist die eine Regel für alle ausgehenden Endpunkte — Token, PAR, Revocation, Introspection, Device, Discovery, UserInfo, JWKS, HIBP-Range-API und die Token-Endpunkte der Propagation: `https` mit Host, oder `http` zu einem Loopback-Host nur mit `-Djcustos.dev=true` (`DEV_MODE_PROPERTY`, `devModeEnabled()`). `isLoopbackHost(host)` erkennt Loopback allein aus der URI, ohne Namensauflösung (`localhost`, `127.0.0.0/8`, `[::1]`); `localhost.example`, `127.0.0.1.example` oder `http://localhost@host` werden abgelehnt. Seit 00.84.00 gilt das auch für `HttpJwksClient` und den HIBP-Prüfer, die Loopback-`http` vorher ohne Schalter annahmen; der Schalter gehört nie in die Produktion. Die Redirect-URI-Prüfung der OAuth2/OIDC-Bootstraps nutzt `isLoopbackHost` ohne Schalter (RFC 8252) |
| `BoundedJson` | core/util/json | Der eine JSON-Leser für jede Antwort (intern, öffentlich nur für die Identity-, OAuth2- und Propagation-Module): höchstens 1 MiB (`MAX_INPUT_CHARS`), Verschachtelung höchstens 64 Ebenen (`MAX_DEPTH`), ein wiederholter Schlüssel verwirft das Dokument, RFC-8259-Grammatik, alle Escapes dekodiert; `parseObject(json)` liefert ein `Result`. `OAuth2Json` bleibt als Fassade, `OidcJson` entfällt |
| `OAuth2FormPost` | core/oauth2/http | Der eine Form-POST an Token-Endpunkte — Client-Authentifizierung, 10 s Zeitlimit (`TIMEOUT`), Antwort höchstens 1 MiB (`MAX_RESPONSE_BYTES`); trägt `HttpTokenEndpointClient`, PAR, Revocation, Introspection, Device-Grant und beide Propagation-Strategien. Liegt seit 00.84.00 in `jCustos-core` (vorher `oauth2.internal.OAuth2FormPost`) |
| `JoseLimits` | core/jwt/api | Gemeinsame Größengrenzen der JOSE-Parser und der eine Segmentzähler `countSegments` |

---

## 3. Annotations

| Annotation | Modul | Evaluator | Zweck |
|---|---|---|---|
| `@RequiresRole({"ROLE_…"})` | core | `RequiresRoleEvaluator` | Subject muss mindestens eine der genannten Rollen haben (Role-Hierarchy-aware) |
| `@RequiresPermission({"foo:bar"})` | core | `RequiresPermissionEvaluator` | Subject muss alle genannten Permissions haben (AND) |
| `@RequiresAllPermissions({"a", "b"})` | core | `RequiresAllPermissionsEvaluator` | Explizite AND-Semantik (Klarheit über `@RequiresPermission`) |
| `@RequiresAnyPermission({"a", "b"})` | core | `RequiresAnyPermissionEvaluator` | OR-Semantik — mindestens eine Permission reicht |
| `@RequiresPolicy("doc.owner-or-admin")` ⚠️ | core | `RequiresPolicyEvaluator` | Benannte Policy aus `PolicyRegistry`, mit Step-Up-Support; seit **V00.84** (JS-SEC-157) ohne Subjekt `Unauthenticated("no-subject")`, bevor die Policy gefragt wird — außer die Policy erlaubt anonyme Anfragen ausdrücklich (`PolicyBuilder.allowAnonymous()`, `JCustosPolicies.anonymous(policy)`) |
| `@ProtectedBy(class.class)` | core | `ProtectedByEvaluator` | Eigene Logik via `AccessEvaluator`-Klasse |
| `@JCustosAnnotation(MyEvaluator.class)` | core | — (Meta-Annotation) | Bindet eine projekt-eigene Annotation an einen Evaluator |
| `@Secured` | core | — (Compile-Time-Trigger) | Markiert eine konkrete Klasse, damit `jCustos-processor` einen `<Type>Secured`-Wrapper generiert (RetentionPolicy.SOURCE) |
| `@ExperimentalJCustosApi(reason)` | core | — | Markiert API als experimentell |

Projekt-eigene Annotationen (Beispiele aus den Demos): `@VisibleFor`
(demo-vaadin), `@CustomCheck` (jCustos-vaadin Tests).

Seit **V00.84** (JS-SEC-154) wirkt eine Einschränkung auch, wenn sie auf
einem Annotationstyp sitzt (`@RequiresRole("ADMIN") @interface AdminOnly`,
eine Ebene tief) — in Vaadin, REST, Standalone und im `@Secured`-Processor;
die Regel „eine Einschränkung pro Element“ bleibt.

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

### `RateLimitDecision` (Phase 7c, ⚠️)

| Variant | Felder | Bedeutung |
|---|---|---|
| `Allowed` | `eventsInWindow`, `limit`, `window` | Event wurde gezählt, Request läuft weiter |
| `Throttled` | `eventsInWindow`, `limit`, `window`, `retryAfter` | Limit erreicht; `retryAfter` ist seit **V00.84** (JS-SEC-165) die Zeit, bis das älteste Event im Fenster dieses verlässt — eine Anfrage zu `now + retryAfter` wird zugelassen. Vorher war es stets das ganze Fenster |
| `Blocked` | `eventsInWindow`, `limit`, `window`, `retryAfter`, `throttledCount` | **V00.84** (JS-SEC-165): Schlüssel gesperrt, weil er innerhalb des Eskalationsfensters `throttledCount`-mal gedrosselt wurde; `retryAfter` ist die Zeit bis zum Ende der Sperre. Nur mit `RateLimitEscalation`; ein erschöpfendes `switch` braucht einen dritten Zweig |

### `CredentialCheckGate.Admission` (seit V00.84, ⚠️)

| Variant | Felder | Bedeutung |
|---|---|---|
| `Entered` | — (`AutoCloseable`) | Platz vergeben; Credential-Prüfung ausführen, danach `close()` |
| `Deferred` | `retryAfter` | Innerhalb von `gateWait` kein Platz frei; Login zurückgestellt, nichts gezählt |

---

## 6. Audit Events (31 sealed Records)

Alle implementieren `AuditEvent` (sealed interface) und sind über
`AuditQuery.matches(AuditEvent)` pattern-match-fähig.

### Klassisch (V00.60 + früher)

| Event | Wichtige Felder | Wird emittiert von |
|---|---|---|
| `LoginSucceeded` | `username`, `clientAddress`, `sessionId` | `MyAuthenticationService`, REST `login`-Handler, `StandaloneLoginFlow` |
| `LoginFailed` | `username`, `clientAddress`, `reason` | `recordFailure` der drei mitgelieferten Policies (`InMemoryLoginAttemptPolicy`, `StoreBackedLoginAttemptPolicy`, `NoopLoginAttemptPolicy`) — seit **V00.84** der einzige Audit-Punkt: genau ein Event pro abgelehntem Login, auch hinter dem Vaadin-`LoginView` und den REST-Handlern (JS-SEC-123, JS-SEC-124). `LoginView` und `StandaloneLoginFlow` publizieren selbst nur für einen Login, den die Policy nach der Credential-Prüfung verweigert (Sperre während der Prüfung) |
| `LogoutPerformed` | `subjectId`, `sessionId`, `scope` | `SubjectClearingLogoutService` |
| `AccessGranted` | `subjectId`, `route` | `AuthorizationListener` (Vaadin), `RestAuthorizationFilter` |
| `AccessDenied` | `subjectId`, `route`, `reason` | dito; seit **V00.84** auch `RestAuthenticationFilter` für eine Anfrage ohne Subjekt (`Unauthenticated:no-subject`, JS-SEC-086) und `RestOriginGuard` für eine fremde Herkunft (`csrf:origin-mismatch`, JS-SEC-163) |
| `ActionDenied` | `subjectId`, `actionName` | `StaticActionAuthorizationService.requireAllowed`; seit **V00.84** auch `SecuredUi.action(...)` für einen Klick, dessen Anforderung nicht mehr erfüllt ist (JS-SEC-168) |
| `BruteForceLimitReached` | `username`, `clientAddress`, `failedAttempts`, `lockoutDuration` | `InMemoryLoginAttemptPolicy`; seit **V00.84** auch `StoreBackedLoginAttemptPolicy` (JS-SEC-122), eine Sperre wird einmal auditiert; eine Adresssperre (Adresslimit, JS-SEC-062) mit leerem `username` |
| `SessionCreated` | `subjectId`, `sessionId` | `TimeoutSessionPolicy.onLogin` — seit **V00.84** (JS-SEC-060) mit der **post-Rotations-ID**, da `LoginView` vor `onLogin` rotiert |
| `SessionExpired` | `subjectId`, `sessionId`, `reason` | `TimeoutSessionPolicy`, `SessionLifetimeListener`, REST-Filter |
| `SessionInvalidated` | `subjectId`, `sessionId (alt)`, `reason` | `LoginSessionRotation.afterLogin` aus `LoginView` und `AbstractOAuth2CallbackView` (B3-Rotation; seit V00.84 nach `SessionCreated` mit der neuen ID); seit **V00.84** zusätzlich mit den Gründen `Revoked` (`VaadinSessionRevocation`, `RestSessionRevocation`, JS-SEC-131), `RotationAfterLoginFailed` (JS-SEC-146), `LoginNotConfirmed` (`LoginView`, JS-SEC-123) und `RememberMeTokenReplay` (JS-SEC-128) |
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
| `SessionStale` | `subjectId`, `sessionId`, `route`, `snapshotVersion`, `currentVersion` | `JCustosVersionEnforcer` bei Drift (Phase 4c); seit **V00.84** auch beim proaktiven Session-Ende durch `VaadinJCustosVersionChangeBridge` (JS-SEC-167) — publiziert vom Thread, der die Version geändert hat, oder vom Request der belegten Session |
| `PasswordResetRequested` | `subjectId`, `tokenHash` | `PasswordResetService.request` (Phase 7a); seit **V00.84** auch `credential.reset.PasswordResetService.issue` (mit dem öffentlichen Selektor, nie dem Verifier — JS-SEC-074) |
| `PasswordResetCompleted` | `subjectId`, `tokenHash` | `PasswordResetService.consume`; seit **V00.84** auch `credential.reset.PasswordResetService.consume` |
| `EmailVerificationRequested` | `subjectId`, `email`, `tokenHash` | `EmailVerificationService.request` |
| `EmailVerified` | `subjectId`, `email`, `tokenHash` | `EmailVerificationService.consume` |
| `ApiKeyUsed` | `subjectId`, `keyName`, `keyHash` | `ApiKeyAuthenticationService.authenticate` (Phase 7b) |
| `ApiKeyDenied` | `subjectId`, `keyHash`, `reason` (Unknown/ForeignTenant/Revoked/Expired) | dito |
| `TokenRotated` | `subjectId`, `oldHash`, `newHash` | `TokenService.rotate` |
| `RateLimitExceeded` | `scope`, `subjectId`, `limit`, `window`, `eventsInWindow` | `InMemoryRateLimitPolicy.tryAcquire` bei Throttle (Phase 7c), seit **V00.84** auch für jede Ablehnung eines gesperrten Schlüssels (`Blocked`, JS-SEC-165) und für einen vom `CredentialCheckGate` zurückgestellten Login (Scope `login:credential-check`, JS-SEC-063) |

### V00.71 (Credential-Pipeline)

| Event | Wird emittiert von |
|---|---|
| `CredentialVerificationSucceeded`, `CredentialVerificationFailed`, `CredentialRehashed` | `CredentialAuditPublisher` der Credential-Pipeline (siehe `RELEASE-NOTES-00.71.00.md`); `CredentialVerificationFailed` mit der Klassifikation `REFRESH_TOKEN_REPLAY` seit **V00.84** auch von `TokenService` bei einem Refresh-Token-Replay (JS-SEC-071) |
| `CredentialStatusChanged` | `CredentialLifecycleService`, `MassCredentialStatusChange` |

Seit **V00.84** (JS-SEC-117) tragen `SessionCreated`, `SessionExpired`,
`SessionInvalidated`, `SessionStale` und `LogoutPerformed` im Feld
`sessionId` die Session-Referenz — `sref-` plus die ersten 16 Hex-Zeichen
des SHA-256 (`SessionRef.of(id)`) —, nie die Live-Session-ID; die
Kern-Produzenten, die REST-Filter und der Vaadin-Adapter reduzieren schon
beim Erzeugen.

Seit **V00.84** (JS-SEC-066) gehört jeder Audit-Datensatz zu dem Request,
der ihn ausgelöst hat: `AuditEnvelope.correlationId` speichert die
Korrelations-ID, die `CorrelationIdResolver` für den Request entschieden
hat, und `LoggingAuditSink` beendet die Zeile mit `corr=<id>`. Außerhalb
eines Requests — Hintergrund-Threads, `UI.access` aus einem anderen
Thread, Standalone-Anwendungen — fehlt das Feld; es wird keine ID
erfunden. Hinter einem Reverse Proxy soll der Proxy `X-Request-ID` setzen
und einen vom Client gesendeten Wert ersetzen (Caddy:
`header_up X-Request-ID {http.request.uuid}`); der Proxy wird mit
`ClientAddressResolver.trustedProxies(...)` registriert.

`AuditQuery(types, subjectId, from, to, limit)` mit Factories
`all()`, `ofType(...)`, `forSubject(...)`. `AuditQuery.subjectIdOf`
und `LoggingAuditSink` decken alle 31 Varianten ab.

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
| `LoggingAuditSink` | core | JUL-basierter Sink, kompaktes `AUDIT type=… field=value …`-Format; seit **V00.84** `sessionRef=` (`sref-` + 16 Hex-Zeichen SHA-256, `SessionRef`) statt der Live-Session-ID (JS-SEC-079, CWE-532) und am Zeilenende `corr=<id>`, bereinigt wie jedes andere Feld (JS-SEC-066) |
| `AuditCorrelation` ⚠️ | core/audit | **V00.84** (JS-SEC-066): trägt die Korrelations-ID für den Thread, der einen Request bedient — `current()`, `open(id)` / `openFor(request)` liefern einen `Scope` (`AutoCloseable`), `newId()` erzeugt eine serverseitige UUID. Geöffnet wird der Scope von `VaadinAuditCorrelation` (§ 8) und `RestAuditCorrelation` (§ 9) |
| `TrustedPeerCorrelationIdResolver` ⚠️ | core/audit | **V00.84**: Default-`CorrelationIdResolver` (§ 2) — `X-Request-ID` (`X_REQUEST_ID`, Headername konfigurierbar) nur von einem vertrauenswürdigen Proxy |
| `SessionRef` ⚠️ | core | **V00.84** (JS-SEC-117, CWE-532): `SessionRef.of(id)` / `ofNullable(id)` bildet die Session-Referenz (`PREFIX` `sref-` + `HEX_LENGTH` 16 Hex-Zeichen SHA-256, 21 Zeichen); ein Wert dieser Form bleibt unverändert, `isReference(value)` erkennt ihn. Gemeinsame Referenz für Log-Zeile, Audit-Events, Session-Datensätze und Dashboards |

---

## 8. Vaadin-Adapter

### Klassen & Listener

| Klasse | Zweck |
|---|---|
| `LoginView` (abstract) | Login-Form mit username/password/remember-me/Login/Cancel + Custom-Slot; seit **V00.84** (JS-SEC-124) fährt die View das Throttling-Protokoll der registrierten `LoginAttemptPolicy` selbst um `checkCredentials()` — `beforeAttempt`, dann genau eines von `confirmSuccess`, `recordFailure`, `abandonAttempt`, geschlüsselt auf Benutzername und die Adresse des `ClientAddressResolver`; Hooks `reactOnLockedOut(lockout)` und `reactOnVerificationUnavailable()`, Opt-out über `throttleLoginAttempts()` für einen `AuthenticationService`, der die Policy selbst aufruft. Seit **V00.84** (JS-SEC-063) betritt die View nach `beforeAttempt` das `CredentialCheckGate` der Policy und verlässt es, sobald `checkCredentials` zurückkehrt; ein zurückgestellter Login ruft `reactOnCredentialCheckDeferred(Duration)` (Default: `reactOnVerificationUnavailable()`). Eine View mit `throttleLoginAttempts() == false` betritt das Gate nicht |
| `LoginListener<U>` (abstract) | `BeforeEnterListener` mit Rollen-/Subject-Lifecycle-Hooks; erkennt seit **V00.84** über `RouteRestrictionResolver` auch eine Route, die nur ihr Layout schützt |
| `LoginListeners` | Statischer Resolver für `LoginListener` (SPI + Cache + `setLoginListener`) |
| `AuthorizationListener` (`@ListenerPriority(MAX_VALUE - 1)`) | Annotation-basierter Routenschutz pro Navigation; seit **V00.84** müssen die Einschränkungen des Ziels **und** jedes Router-Layouts der Kette gewähren (JS-SEC-154, `@PublicRoute` hebt keine Layout-Einschränkung auf), und jede Ablehnung ohne erreichbares Reroute-Ziel — nicht registrierte Route oder die abgelehnte View selbst — endet in der Error-View für `SecurityException` (JS-SEC-152, JS-SEC-158) |
| `SessionLifetimeListener` (`@ListenerPriority(MAX_VALUE)`) | Idle/Absolute-Timeout-Enforcement vor Authorization; seit **V00.84** (JS-SEC-082, JS-SEC-155, CWE-613) zusätzlich `RequestHandler` für jeden UIDL-Request und `VaadinRequestInterceptor` für Nachrichten über einen reinen WebSocket-Push-Kanal. Die Prüfung läuft unter dem Session-Lock; bei Ablauf wird der Request verbraucht (Subjekt gelöscht, `SessionExpired`, Vaadin-Session geschlossen, HTTP-Session invalidiert, der Client erhält Vaadins Session-expired-Meldung). Aktivität führt der Listener in einem eigenen Attribut, automatische Polls (`UI.setPollInterval`) zählen nicht, `getLastRequestTimestamp()` wird nicht mehr herangezogen. Prüft außerdem den `SessionStore`-Datensatz der aktuellen Session auf Widerruf (JS-SEC-131) |
| `ApplicationServiceInitListener` | Registriert `LoginListener` als `BeforeEnterListener` pro UI |
| `VaadinSessionSubjectStore` | `SubjectStore`-Default — speichert Subject in `VaadinSession.getAttribute` |
| `VaadinLogoutService<U>` | Vaadin-spezifischer `LogoutService` mit Page-Redirect / Session-Close / HTTP-Invalidate; seit **V00.84** (JS-SEC-084) Komfort-Konstruktoren mit Ziel `/` + `loginRouteName()` (zur Logout-Zeit aufgelöst, statt fest `/login`) und Session-ID im `SessionContext` für `SessionPolicy.onLogout` |
| `VaadinLogoutGateway` / `DefaultVaadinLogoutGateway` | Thin Wrapper über `UI.getPage().setLocation`, `VaadinSession.close`, `WrappedSession.invalidate`; seit **V00.84** (JS-SEC-084) `currentSessionId()` (Default-Methode, der Default-Gateway liefert die WrappedSession-ID) |
| `VaadinAccessContextFactory` | Baut `AccessContext` aus `BeforeEnterEvent`; `subjectId` und `displayName` des `JCustosSubject` seit **V00.84** (JS-SEC-083) aus dem `SubjectIdResolver`, nie aus `toString()` (ohne Resolver: Identitäts-Handle) |
| `VaadinAccessDecisionMapper` / `VaadinNavigationAccessDecisionMapper` | Mappen `AccessDecision` / `NavigationAccessDecision` auf Vaadin-Navigation |
| `JCustosAnnotationScanner` | Scannt Class/Method/AnnotatedElement nach `@JCustosAnnotation`-Meta-Annotation (cached); erbt entlang der Superklassen-Kette **und seit V00.84 entlang der Interfaces** (JS-SEC-081, CWE-862) — die am stärksten abgeleitete Einschränkung gewinnt. Seit **V00.84** außerdem: eine Methode ohne eigene Einschränkung erbt die ihrer Klasse (JS-SEC-070), `scan(Method, Class)` löst eine geerbte oder überschriebene Methode so auf, wie sie auf der übergebenen Klasse läuft (Methode, dann Klasse, dann überschriebene Deklaration — JS-SEC-114), zusammengesetzte Annotationen wirken eine Ebene tief (JS-SEC-154) |
| `RouteRestrictionResolver` ⚠️ (`authorization/impl`) | **V00.84** (JS-SEC-154): löst die Einschränkungen einer Navigation auf — Ziel plus jedes Router-Layout der Kette, alle müssen gewähren; gemeinsame Quelle für `AuthorizationListener`, `LoginListener` und die Start-up-Discovery |
| `LoginSessionRotation` ⚠️ | **V00.84** (JS-SEC-146, CWE-384): die öffentliche Post-Login-Sequenz `afterLogin(...)` — Session-ID-Rotation, `SessionPolicy.onLogin`, Rotations-Audit, Hook `onSessionRotated`, Security-Version-Snapshot; genutzt von `LoginView` und `AbstractOAuth2CallbackView` (der Callback scheitert geschlossen: ohne Rotation wird der Login zurückgenommen, `SessionInvalidated(RotationAfterLoginFailed)`) |
| `VaadinSessionRevocation` ⚠️ (`session/vaadin`) | **V00.84** (JS-SEC-131, CWE-613): `revoke(record)` / `terminate(sessionId, …)` beenden die Live-Session auf demselben Knoten sofort (Subjekt, Snapshot und Token-Credential gelöscht, `SessionInvalidated(Revoked)`, Vaadin-Session geschlossen, HTTP-Session invalidiert); `useSessionStore(store)` registriert den Store für die Prüfung pro Request — der Bootstrap übernimmt diese Registrierung bei `.sessions(s -> s.storeBacked(...))` (`bootstrap-session-revocation`). Vergleicht über `SessionRef`, findet also Datensätze unter Referenz und unter Live-ID |
| `CurrentSubject` ⚠️ (core, `authorization/api`) | **V00.84** (ER30, JS-SEC-097, CWE-1041/CWE-532): die eine Fassade für Subjekt-Lookup und Subjekt-ID — `subjectType()`, `current()`, `currentPropagatingFailures()`, `subjectIdOf(Object)`, `currentJCustosSubject()`, `clear()`. Regel: der Wert des registrierten `SubjectIdResolver`; ohne Resolver, bei einem Fehler oder leerem Wert das Identitäts-Handle `SimpleClassName@identityHash`; nie `toString()`, nie leer. Lookups werfen nicht und lesen Fehler als „kein Subjekt“; die Lebensdauerprüfung nutzt `currentPropagatingFailures()`, damit ein unlesbarer Subject-Store den Request weiter stoppt. Genutzt von `VaadinAccessContextFactory`, `SecuredVisibility`, `LoginSessionRotation`/`LoginView`, `SessionLifetimeListener`, `JCustosVersionEnforcerListener`, `AuthorizationListener`, `LoginListener`, der OIDC-Logout-View und `JCustosEnforcer` |
| `VaadinAuditCorrelation` ⚠️ (`net/vaadin`) | **V00.84** (JS-SEC-066): Request-Interceptor, den jCustos-vaadin per `META-INF/services` als `VaadinServiceInitListener` registriert; öffnet für jeden Request den `AuditCorrelation`-Scope und schließt ihn am Ende. Ein Request-Interceptor der Anwendung, der aus einem später geladenen Service-Init-Listener stammt, auditiert ohne ID |
| `RouteNameCheck` ⚠️ (`jCustos-dx-vaadin`) | **V00.84** (JS-SEC-152): prüft einen Routennamen gegen die Route-Registry (`REGISTERED` / `UNREGISTERED` / `UNAVAILABLE`); Grundlage der Bootstrap-Befunde `vaadin/login-route-unresolved` und `vaadin/step-up-route-unresolved`. Die Registry ist auch aus `VaadinServiceInitListener.serviceInit` lesbar, nur nicht außerhalb eines Service (`ServletContextListener`, `main`) |

### Login-View-Features

- Stabile Test-IDs: `loginview-tf-username`, `loginview-pf-password`, `loginview-btn-login`, `loginview-btn-cancel`, `loginview-cb-remember-me`
- Custom-Element-Slot via `setCustomElements(Component)` / `clearCustomElements()`
- LUMO-Theme-Variants vorverdrahtet
- Nach erfolgreichem Login (seit **V00.84** über `LoginSessionRotation.afterLogin(...)`, JS-SEC-146) wird die HTTP-Session-ID zuerst über `HttpServletRequest.changeSessionId()` rotiert (seit **V00.84**, JS-SEC-060, CWE-384; Fallback `VaadinService.reinitializeSession` nur für Nicht-Servlet-Requests), dann folgt `SessionPolicy.onLogin` mit der **neuen** ID (`SessionCreated` trägt die Referenz der überlebenden ID, `SessionRef`), `SessionInvalidated` für die alte ID und der Hook `onSessionRotated(alt, neu)` — dort legen Anwendungen `SessionStore`-Einträge an oder schlüsseln sie um (`SessionStore.rekey`, `SessionRecord.withSessionId`)
- `captureJCustosVersionSnapshot()` (Phase 4c-Followup): wenn sowohl `JCustosVersionStore` als auch `SubjectIdResolver` als SPI registriert sind, liest die View beim erfolgreichen Login die aktuelle `JCustosVersion` und schreibt sie in den `VaadinJCustosVersionContext`. Strict-no-op + exception-swallowing, blockiert den Login-Flow nie.

### Phase-4c JCustosVersion-Enforcement (⚠️)

| Klasse | Zweck |
|---|---|
| `VaadinJCustosVersionContext` (Package `session/vaadin`) | Per-VaadinSession Snapshot-Carrier (`record(subjectId, tenant, snapshot, sessionId)` / `current()` / `clear()`). Survives Session-Rotation. |
| `JCustosVersionEnforcerListener` (`@ListenerPriority(Integer.MAX_VALUE)`) | BeforeEnter-Listener vor `AuthorizationListener`. On Drift: clear snapshot + reroute zur konfigurierten LoginView-Klasse. Seit **V00.84** (JS-SEC-082, JS-SEC-155) auch `RequestHandler` und `VaadinRequestInterceptor`: `register(ServiceInitEvent)` verdrahtet alle drei Eintrittspunkte, dann wird Drift auf jeder Client-Nachricht unter dem Session-Lock durchgesetzt (Subjekt löschen, Snapshot leeren, `SessionStale`, Session schließen, Request verbrauchen — der Client erhält Vaadins Session-expired-Meldung) |
| `VaadinJCustosVersionChangeBridge` ⚠️ (Package `session/vaadin`) | **V00.84** (R8, JS-SEC-167, CWE-613): beendet eine offene Session, sobald sich die Security-Version ihres Subjekts ändert — ohne auf den nächsten Request zu warten. Als `JCustosVersionChangeListener` eines `ObservableJCustosVersionStore` registriert (`register(ServiceInitEvent, ObservableJCustosVersionStore)`), merkt sie sich den Subjekt-Schlüssel jeder UI und führt bei einer Änderung `UI.access` aus: eine gedriftete Session wird wie bei der Prüfung pro Request beendet (Subjekt, Snapshot und Token-Credential gelöscht, `SessionStale` mit Session-Referenz und offener Route, jede UI der Session per `Page.setLocation` auf das Reroute-Ziel geschickt und gepusht, Session geschlossen, HTTP-Session invalidiert); eine Session ohne Drift bekommt ihre Secured-Komponenten neu ausgewertet. Mit `@Push` verlässt der Browser die Seite ohne Klick; ohne Push endet die Session serverseitig sofort, der Browser erhält beim nächsten Request Vaadins Session-expired-Antwort. `VaadinJCustosStarter.serviceInit(...)` registriert die Bridge, wenn der registrierte Store beobachtbar ist |

### Phase-8a/b Components (`jCustos-vaadin/components/` — ⚠️)

| Klasse | Zweck |
|---|---|
| `SecuredVisibility` + `SecuredVisibilityMode` (HIDE / DISABLE) | Zentraler Decision-Point. `Requirement(requiredRoles, requiredPermissions)` (AND-composed), `Target`-Interface, `apply()` + `isAllowed()`. SPI-backed `currentJCustosView()` resolved via `AuthenticationService.subjectType()` + `SubjectStore` + `AuthorizationService`. Missing SPI → denial. Seit **V00.84**: ohne gebundenes Subjekt wird jede Anforderung abgelehnt, `SecuredUi.requiresRole()`/`requiresPermission()` lehnen ein leeres Array mit `IllegalArgumentException` ab (JS-SEC-135), und eine abgelehnte Komponente ohne `HasEnabled` (`Composite`, eigene `@Tag`-Komponente, `Icon`) wird im HIDE-Modus tatsächlich verborgen (JS-SEC-153). Ebenfalls seit **V00.84**: das Subjekt kommt über `CurrentSubject`, Rollen und Permissions werden vor der Herausgabe der Sicht aufgelöst — ein fehlschlagender `AuthorizationService` lehnt ab, statt aus `apply(...)` zu werfen (JS-SEC-097); `SecuredVisibility.refreshAll(UI)` wertet alle Secured-Bindings einer UI neu aus (JS-SEC-167), innerhalb von `ui.access(...)` aufrufen, etwa nach einer Rollenänderung ohne Versionssprung. |
| `SecuredBindingRegistry` ⚠️ | **V00.84** (R8, JS-SEC-167): Register pro UI (als Komponentendaten gehalten, Komponenten schwach referenziert) aller Secured-Bindings — `SecuredButton`, `SecuredRouterLink`, `SecuredMenuItem` und die `SecuredUi`-Bindings des Starters inklusive `requiresPolicy(...)`. `refreshAll(UI)` verwirft eingesammelte und inzwischen an eine andere UI gehängte Komponenten und verbirgt eine Komponente, deren Neuauswertung wirft |
| `ComponentTarget` ⚠️ | **V00.84** (ER30, JS-SEC-097): das eine öffentliche `SecuredVisibility.Target` für eine Vaadin-`Component` mit der Semantik von JS-SEC-153; ersetzt die vier bisherigen privaten Adapter |
| `SecuredButton` (Default DISABLE) | Vaadin-Button-Subklasse. Checkt auf Konstruktor und onAttach; `refresh()` für manuelle Re-Checks. |
| `SecuredRouterLink` (Default HIDE) | Vaadin-RouterLink-Subklasse. Router-explicit Konstruktor für headless tests. |
| `SecuredMenuItem.bind(MenuItem, Requirement, …)` | Binding-Helper, da MenuItem vom Parent-MenuBar erzeugt wird (kein Subclass-Pattern möglich). Seit **V00.84** bei jedem Attach neu ausgewertet, wie `SecuredButton` und `SecuredRouterLink` (JS-SEC-167). |
| `SessionManagementView` | Reusable Composite. Grid über `SessionStore.findAll()` (Tenant/Subject/SessionId/Status/Created/LastActivity/Version/Action). Per-Row Revoke via `Consumer<SessionRecord>`. Apps subclassen mit `@Route` + `@RequiresPermission`. **V00.84 (JS-SEC-068, CWE-306):** Drei-Argument-Konstruktor mit `Requirement`; der Revoke-Handler prüft das aktuelle Subjekt serverseitig gegen die Anforderung, auditiert eine Ablehnung als `AccessDenied` und lässt den Store unberührt. **V00.84 (JS-SEC-131):** mit `VaadinSessionRevocation::revoke` als Revoke-Callback beendet „Revoke“ die Session beim Klick; die Spalte „Session id“ zeigt `SessionRef.of(...)` statt der Live-ID. |
| `SessionManagementRoute` + `SessionManagementAccess` (`jCustos-dx-vaadin`) | Vom Bootstrap aktivierte Route `/session-management`. **V00.84 (JS-SEC-068):** trägt `@ProtectedBy(SessionManagementAccess)`; der Evaluator prüft die mit `.sessionManagementView(Requirement)` veröffentlichte Anforderung — ohne Anforderung fail-closed (`Forbidden`), ohne Subjekt `Unauthenticated`. `.sessionManagementView()` ohne Anforderung ist deprecated und meldet `session-management-view-without-requirement` (ERROR in PRODUCTION/STRICT, WARNING sonst). Die frühere Deny-by-Default-Ausnahme in `AuthorizationListener` und die Discovery-Ausnahme sind entfallen. Seit JS-SEC-131 ist das echte Beenden der Session (`VaadinSessionRevocation`) der Standard-Revoke der Route. |

### Vaadin-Starter (`jCustos-vaadin-starter`, seit V00.84 erweitert)

| Klasse | Zweck |
|---|---|
| `VaadinJCustosStarter` (`starter/profile`) | Profile `developmentDefaults()` / `productionDefaults()` / `strictDefaults()`. Seit **V00.84** (JS-SEC-168, CWE-1188) setzen `productionDefaults()` und `strictDefaults()` zusätzlich `.denyByDefault(true)` und, wenn eindeutig, `.loginRoute(...)` — die Route der einen registrierten `LoginView`-Route bzw. der vom registrierten `LoginListener` genannten; `developmentDefaults()` setzt nur den Modus. Ein späteres `.loginRoute(...)` nach `.use(profile)` gewinnt; eine nicht annotierte Route ist unter diesen Profilen erst mit `@PublicRoute` öffentlich |
| `VaadinJCustosStarter.serviceInit(event, rerouteTarget[, options])` (implementiert von `VaadinJCustosServiceInit` ⚠️) | **V00.84** (JS-SEC-168): ein Aufruf aus dem `VaadinServiceInitListener` nach `install()` verdrahtet die Service-Teile (`VaadinJCustosServiceInit.Part`): `JCustosVersionEnforcerListener.register(...)` bei registriertem `JCustosVersionStore`, `VaadinJCustosVersionChangeBridge` bei einem `ObservableJCustosVersionStore`, `JCustosErrorHandler.install(...)` und — mit `Options.withOidcSessionRegistry(...)` — `VaadinSessionRegistryCleanup` des OIDC-Moduls (per Name geladen, ohne Abhängigkeit). `Options.defaults().withoutErrorHandler()` lässt den Fehlerbehandler weg. Liefert und loggt die installierten Teile und meldet jeden übersprungenen; handgeschriebene Init-Listener für dieselben Teile entfallen, sonst werden sie doppelt registriert |
| `SecuredUi.action(component, onClick)` ⚠️ (`starter/ui`) | **V00.84** (JS-SEC-168): wertet die Anforderung beim Binden, beim Attach, aus `refreshAll(UI)` **und beim Eintreffen des Klicks** aus. Der Klick eines Subjekts, das sie nicht mehr erfüllt, führt `onClick` nicht aus, wertet das Steuerelement sofort neu aus (Default deaktiviert, mit `hideWhenDenied()` verborgen), wird als `secured-ui/action-refused` geloggt und als `ActionDenied` auditiert; eine werfende Prüfung lehnt den Klick ab. `SecuredUi.button(...).onClick(...)` führt den Klick weiterhin aus, sobald Vaadin ihn zustellt. `SecuredUi.component(...).bind()` wird seit **V00.84** bei jedem Attach neu ausgewertet |
| `JCustosErrorHandler` ⚠️ (`starter/errors`) | **V00.84** (R7, JS-SEC-067, CWE-209): opt-in `ErrorHandler`, `JCustosErrorHandler.install(ServiceInitEvent)` aus dem `VaadinServiceInitListener`; jede danach erzeugte Session bekommt ihn. Fragt zuerst `ErrorHandlerUtil.handleErrorByRedirectingToErrorView(...)` wie Vaadins Default, sodass etwa eine `AccessDeniedException` die `HasErrorParameter`-View erreicht; sonst zieht er eine 16-stellige Base32-Referenz aus `SecureRandom`, loggt `Unhandled error, reference <ref>` mit Stacktrace auf ERROR und zeigt dem Nutzer nur die Referenz (`jcustos.error.reference`, `{0}` = Referenz, sonst englischer Text). Abgebrochene Verbindungen werden nicht gemeldet, der Handler rekursiert nicht; `showReference(UI, String)` überschreibbar |

---

## 9. REST-Adapter

| Klasse | Zweck |
|---|---|
| `RestRequest` / `RestResponse` / `RestHandler` (Interfaces) | Framework-light Abstractions, kein Spring/Jakarta-Servlet-Lock-in; `RestRequest` seit **V00.84** mit `remoteAddress()` (JS-SEC-061) und `headerValues(String)` — `headers()` fügt wiederholte Listen-Header mit `", "` zusammen, ein wiederholter `Authorization`-, `X-Api-Key`- oder `Cookie`-Header wird mit `400` abgelehnt (JS-SEC-113) |
| `BodyRestRequest` | `RestRequest`-Variante mit Body |
| `BearerTokenExtractor` | Liest `Authorization: bearer <token>` (case-insensitive Scheme); seit **V00.84** kein Token, wenn `Authorization` zweimal ankommt (JS-SEC-113) |
| `RestAuthenticationFilter` | "Authenticated-only" Filter — `401` ohne Subject oder bei abgelaufener Session; rendert über den publizierten Decision-Mapper (Body-Strategie, `WWW-Authenticate: Bearer`) und auditiert `AccessDenied` (`Unauthenticated:no-subject`) bzw. `SessionExpired` (JS-SEC-086); seit **V00.84** auch `401` für eine widerrufene Session (`RestSessionRevocation`, JS-SEC-131) |
| `RestAuthorizationFilter` | Annotation-basierter Filter — `200`/Handler, `401 Unauthorized` (no subject), `403 Forbidden` (missing role/permission); emittiert AccessGranted / AccessDenied / SessionExpired. Rendert über den im Konstruktor übergebenen oder den publizierten Decision-Mapper (`RestDecisionContext.mapperOrDefault()`), jedes `401` mit `WWW-Authenticate: Bearer` (JS-SEC-086). Seit **V00.84**: Überladung `authorizeAndHandle(request, response, handler, method, handlerClass)` löst eine geerbte oder überschriebene Handler-Methode auf der Handler-Klasse auf (JS-SEC-114); `401` für eine widerrufene Session (JS-SEC-131); eine Policy-Route verlangt ein Subjekt (JS-SEC-157) |
| `RestAccessContextFactory` | Baut `AccessContext` aus `RestRequest` (resourceType="rest-endpoint") |
| `HttpStatusDecisionMapper` | `AuthorizationDecision` → HTTP-Status; jedes `Unauthenticated`-401 trägt `WWW-Authenticate: Bearer` (RFC 7235), Step-Up `StepUp method="…"`; Body über die konfigurierte `RestErrorBodies`-Strategie |
| `BootstrapRestStatusMapper` | Bootstrap-spezifisches Status-Mapping |
| `RestHeaders` | Helper für Header-Lookup |
| `RestHeaderLines` ⚠️ | **V00.84** (JS-SEC-113, CWE-348): Helfer für Adapter, die mehrzeilige Header liefern — `joined(...)` baut `headers()` regelkonform, `values(...)` liefert alle Zeilen, `rejectDuplicates(...)` antwortet `400` auf einen wiederholten `Authorization`-, `X-Api-Key`- oder `Cookie`-Header |
| `RestDecisionContext` | Hält den vom Bootstrap publizierten Decision-Mapper; **V00.84** (JS-SEC-086): `mapperOrDefault()` ist öffentlich (publizierter Mapper, sonst `HttpStatusDecisionMapper`) — eigene Ablehnungen eines Handlers laufen über `RestDecisionContext.mapperOrDefault().apply(decision, response)` |
| `RestSessionRevocation` ⚠️ | **V00.84** (JS-SEC-131, CWE-613): Widerrufsprüfung der drei REST-Filter. Mit registriertem `SessionStore` (`.sessions(s -> s.storeBacked(...))` am `RestSecurity.bootstrap()` oder `useSessionStore(...)`) und einem Resolver mit `resolveSessionId` beendet ein `REVOKED`- oder ein gesehener und dann entfernter Datensatz die Session: `401` über den Mapper, `SessionInvalidated(Revoked)`, kein Handler. `EXPIRED` allein beendet nichts, Store-Fehler werden geloggt; Gedächtnis gesehener Datensätze pro Knoten 10 000 (`SEEN_CAPACITY`), für mehrere Knoten `requireRecord(true)` |
| `RestAuditCorrelation` ⚠️ | **V00.84** (JS-SEC-066): `run(request, action)` / `call(request, supplier)` öffnen den `AuditCorrelation`-Scope eines REST-Requests; innerhalb eines bereits geöffneten Scopes gilt dessen ID. `RestAuthenticationFilter`, `RestAuthorizationFilter` und `RestJCustosVersionFilter` entscheiden darin, ebenso `RestSessionRevocation.allow(...)`; eigene Login- oder Token-Handler und eigene Router umhüllen ihren Dispatch damit, wie in `demo-rest` und in den Routern der REST-Skill-Demos |
| `RestOriginGuard` ⚠️ | **V00.84** (JS-SEC-163, CWE-352): Opt-in-Schutz gegen CSRF für REST-Sessions, die auf einem Cookie laufen. Prüft jeden Request mit unsicherer Methode (`GET`, `HEAD`, `OPTIONS`, `TRACE` passieren): `Sec-Fetch-Site: same-origin` oder `none` passiert, sonst muss `Origin` die eigene Herkunft aus `Host` oder einen Eintrag der Allowlist nennen (Schema, Host und Port exakt); `null`, Pfad, User-Info, Query, Fragment und ein wiederholtes `Origin` werden abgelehnt. Ohne beide Header passiert ein Nicht-Browser-Client, außer mit `MissingHeaders.REFUSE`. Ablehnung: `403` über den Decision-Mapper und `AccessDenied` mit `csrf:origin-mismatch`. `RestOriginGuard.sameOrigin()`, `withAllowedOrigins(Set)` (ersetzt den `Host`-Vergleich, hinter einem Proxy nötig), `withMissingHeaders(...)`; `RestSecurity.bootstrap().originGuard(guard)` installiert ihn prozessweit (`install`, `installed`, `reset`, `bootstrap-origin-guard`), der Router ruft `RestOriginGuard.installed()` als ersten Schritt, die drei REST-Filter führen einen installierten Guard vor ihren eigenen Prüfungen aus. Für Bearer-Tokens nicht nötig; `OidcLogoutHandler` nutzt `originAccepted(...)`. Doku: `docs/security/csrf.md` |
| `RestRateLimit` ⚠️ | **V00.84** (JS-SEC-165, CWE-799): `respond(decision, response[, body])` schreibt für `Allowed` nichts und liefert `false`, beantwortet `Throttled` und `Blocked` gleich (429, `Retry-After`, derselbe generische Body) und liefert `true` — `if (RestRateLimit.respond(policy.tryAcquire(key), response)) return;`. Einen REST-Filter für Rate-Limits gibt es nicht |
| `RestThrottleResponses` ⚠️ | **V00.84** (JS-SEC-063): `tooManyRequests(response, retryAfter[, body])` antwortet `429` mit `Retry-After` in ganzen Sekunden, aufgerundet, mindestens 1 (`retryAfterValue`); für das Credential-Check-Gate eines eigenen Login-Handlers und für `RestRateLimit` |
| `RestJCustosVersionContext` + `RestJCustosVersionFilter` (Phase 4c, ⚠️) | Drift-Filter; `RestSubjectResolver.resolveJCustosVersionContext` als opt-in Default-Methode. Bei Drift: `401 + WWW-Authenticate: SessionStale` (RFC 7235-Style) und Audit-Event; Status und Body über den publizierten Decision-Mapper (JS-SEC-086). Seit **V00.84** läuft vor der Drift-Prüfung die Widerrufsprüfung (`RestSessionRevocation`, JS-SEC-131), und das `SessionStale`-Event trägt `sessionReference(sessionId)` statt des Bearer-Tokens (JS-SEC-117). |

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
| `StandaloneLoginFlow<T, U>` | Login-Treiber: konsultiert `LoginAttemptPolicy` → `AuthenticationService` → bindet Subject → emittiert `LoginSucceeded`; `LoginFailed` publiziert seit **V00.84** die Policy in `recordFailure` (Grund `REASON_NO_SUBJECT` bzw. `REASON_CREDENTIALS_REJECTED`), der Flow selbst nur für einen Login, den die Policy nach der Prüfung verweigert (JS-SEC-123). Eine vom KDF-Limiter abgewiesene Prüfung gibt den Versuch zurück, zählt keinen Fehlschlag und reicht `CredentialVerificationUnavailableException` an den Aufrufer weiter (JS-SEC-126). Seit **V00.84** betritt der Flow nach `beforeAttempt` das `CredentialCheckGate` der Policy; ein zurückgestellter Login wirft `CredentialCheckDeferredException` mit `retryAfter()` (JS-SEC-063) |
| `SecuredProxy.wrap(Interface, impl)` | JDK Dynamic Proxy — enforce per Methode oder Klasse via `JCustosEnforcer.enforce(method, declaringClass)`; Einschränkungen auf Super-Interfaces werden vererbt, und unter `setDenyByDefault(true)` wird eine Methode ohne Einschränkung abgelehnt, sofern sie oder ihr Interface nicht `@PublicRoute` trägt (seit V00.84, JS-SEC-081); eine geerbte Methode wird seit V00.84 so geprüft, wie sie auf der übergebenen Klasse läuft (`JCustosAnnotationScanner.scan(Method, Class)`, JS-SEC-114) |
| `SecuredProxy.requireAllowed(Class, methodName)` | Single-shot Enforcement für Lambdas/Callbacks |
| `LoginResult<U>` (sealed) | `Success` / `Rejected` / `LockedOut` |

---

## 10b. Method Security via Annotation Processor (`jCustos-processor`)

| Klasse / Datei | Zweck |
|---|---|
| `@Secured` (in jCustos-core, `…/authorization/annotations`) | Compile-Time-Trigger — markiert eine **konkrete Klasse** für die Wrapper-Erzeugung. `RetentionPolicy.SOURCE`, Target `TYPE`. |
| `SecuredAnnotationProcessor` | `BasicStaticProxyAnnotationProcessor<Secured>` aus `com.svenruppert:proxybuilder:00.11.01`. Generiert `<Type>Secured extends <Type>` und ersetzt jede annotierte Methode durch `JCustosEnforcer.require…(…)` + `super.<method>(…)`. Seit **V00.84** (JS-SEC-156, JS-SEC-159) läuft alles, was das native Mapping nicht abdeckt — `@ProtectedBy`, eigene `@JCustosAnnotation`-Annotationen, zusammengesetzte und von Supertypen geerbte Einschränkungen, Methoden ohne Einschränkung (Deny-by-Default) — über `JCustosEnforcer.enforce(Method, Class)`, wie bei `SecuredProxy`. Marker am Wrapper: `@GeneratedByProxyBuilder(processor, sourceClass, proxyBuilderVersion="00.11.00", date, comments)` (RUNTIME-reflectable via `proxybuilder-annotations`) + `@DelegatesTo("Owner#method(params)")` pro generierter Methode. |
| `META-INF/services/javax.annotation.processing.Processor` | Registriert den Processor für `javac` / Maven-Compiler. |
| `JCustosEnforcer` (in jCustos-core) | Zentrale Enforcement-API, geteilt mit `SecuredProxy`. Methoden: `requirePermission`, `requireAllPermissions`, `requireAnyPermission`, `requireRole`, `requireAnyRole`, `requirePolicy`; plus die Generic-`enforce(Method, Class)` für den Dynamic-Proxy-Pfad. Wirft `AccessDeniedException` on deny. Seit **V00.84**: unter Deny-by-Default wird ein Element ohne Einschränkung abgelehnt, sofern es oder seine Klasse nicht `@PublicRoute` trägt (JS-SEC-081); `requirePolicy` wirft ohne Subjekt, außer die Policy erlaubt anonyme Aufrufe (JS-SEC-157). |

Konsumenten binden das Modul über `<annotationProcessorPaths>` in
`maven-compiler-plugin` ein — nie als reguläre Compile-Dependency, da
der Processor selbst zur Runtime nicht im Classpath stehen muss. Die
generierte `<Type>Secured`-Klasse hat **keine** Restanforderungen ans
Konsumenten-Projekt außer den Markern `@GeneratedByProxyBuilder` /
`@DelegatesTo` aus `proxybuilder-annotations`: Konsumenten deklarieren
`com.svenruppert:proxybuilder-annotations:00.11.01` als Compile-Dependency
und schließen `io.dropwizard.metrics` und `com.squareup:javapoet` davon aus
(seit **V00.84**, JS-SEC-141; `demo-standalone` zeigt die Deklaration).

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
proxybuilder-Base-Processor als `Diagnostic.Kind.ERROR` emittiert.
Seit **V00.84** (JS-SEC-156) meldet `jCustos-processor` zusätzlich selbst:
eine Einschränkung auf einer Methode, die der Wrapper nicht überschreibt
(`final`, `static`, `private`, `protected`, package-private, eine
`Object`-Methode, per `@SkipProxy` oder `excludeMethodNames`
ausgeschlossen), ist der Compile-Fehler
`processing/unenforceable-security-annotation`; eine native und eine
eigene (oder zusammengesetzte) Einschränkung auf einem Element sind
`processing/multiple-security-annotations`. Außerdem seit **V00.84**
(JS-SEC-156, JS-SEC-159): Eine nicht annotierte Überschreibung einer
eingeschränkten Supertyp-Methode, die der Wrapper auslässt, und eine
Klassen-Einschränkung auf einer ausgeschlossenen öffentlichen Methode
ergeben ebenfalls `processing/unenforceable-security-annotation`; eine
ausgeschlossene öffentliche Methode ganz ohne Einschränkung ergibt die
Warnung `processing/deny-by-default-not-applied`; eine Einschränkung, die
über mehr als eine Ebene zusammengesetzt ist, ergibt
`processing/nested-composed-security-annotation`. `@PropagateToken` zählt
nicht als Einschränkung.

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
| `BootstrapTokenStore` (SPI) | In-Memory oder File-backed (`./data/bootstrap.token`, POSIX 0600); eine untergeschobene oder zu weit berechtigte Token-Datei wird seit **V00.84** nicht übernommen, ein Erstellungszeitpunkt mehr als fünf Minuten in der Zukunft gilt als abgelaufen (JS-SEC-130) |
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

Seeded Users: `admin/admin`, `librarian/librarian`, `alice/alice` — seit
**V00.84** (JS-SEC-137) nur mit dem Entwicklungsschalter
`-Djcustos.demo.insecure-seed-accounts=true`, der außerhalb von
`DEVELOPMENT` abgelehnt wird; ohne Schalter startet die Demo ohne
Benutzer. Passwörter laufen durch die Credential-Pipeline statt im
Klartext.
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
| Vaadin Browserless Testing 1.0.0 (`com.vaadin:browserless-test-junit6`; der Kern `browserless-test-shared` kommt seit **V00.84** in 25.3.2 über die Vaadin-BOM) | vaadin / demo-vaadin | UI-Adapter-Tests ohne Browser; `BrowserlessTest`-Basisklasse, `navigate(Class)`, `$view(Class)`, typed Tester (`ButtonTester`, `GridTester`, `ComboBoxTester`, `NotificationTester`, `ConfirmDialogTester`) |
| `com.google.testing.compile:compile-testing` 0.21.0 | jCustos-processor | Annotation-Processor-Tests: `Compiler.javac().withProcessors(...).compile(...)`, `assertThat(compilation).succeeded()`, `generatedSourceFile(...).contentsAsUtf8String().contains(...)`. |
| JUnit Jupiter 6.1.0 | alle | Test-Framework |
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
| `JCustosAnnotationScanner.scan(Class/Method/AnnotatedElement)` / `.scan(Method, Class)` | core | Annotation-Resolution mit Cache; `scan(Method, Class)` seit **V00.84** für Methoden, wie sie auf einer bestimmten Klasse laufen (JS-SEC-114) |
| `SessionRef.of(id)` / `.ofNullable(id)` / `.isReference(value)` | core | **V00.84** (JS-SEC-117): Session-Referenz `sref-…` für Audit, Logs, Session-Datensätze und Dashboards |
| `SubjectKeyCanonicalizer.defaults()` / `.exact()` | core | **V00.84** (JS-SEC-123, CWE-178): ein Schlüssel pro Konto — Default NFKC, Kleinschreibung (`Locale.ROOT`), getrimmt; `exact()` für Verzeichnisse mit Groß-/Kleinschreibung. Dieselbe Instanz an Login-Policies, `InMemoryCredentialStore` und `InMemoryAbuseDetectionService` übergeben |
| `CurrentSubject.current()` / `.subjectIdOf(subject)` / `.clear()` | core | **V00.84** (JS-SEC-097): Subjekt-Lookup und Subjekt-ID nach einer Regel — Resolver-Wert, sonst Identitäts-Handle, nie `toString()` |
| `EndpointSecurity.requireHttps(uri, errorCode)` / `.isLoopbackHost(host)` / `.devModeEnabled()` | core | **V00.84** (JS-SEC-098): die eine https-Regel für ausgehende Endpunkte; `http` zu Loopback nur mit `-Djcustos.dev=true` |
| `BoundedJson.parseObject(json)` | core | **V00.84** (JS-SEC-098): der begrenzte JSON-Leser (intern, ⚠️) |
| `OAuth2FormPost.post(...)` / `.postWithoutClientAuthentication(...)` | core | **V00.84** (JS-SEC-098): der eine Form-POST an Token-Endpunkte |
| `AuditCorrelation.current()` / `.open(id)` / `.openFor(request)` | core | **V00.84** (JS-SEC-066): Korrelations-ID des aktuellen Requests |
| `RestAuditCorrelation.run(request, action)` / `.call(request, supplier)` | rest | **V00.84** (JS-SEC-066): Korrelations-Scope für eigene REST-Handler und Router |
| `RestRateLimit.respond(decision, response)` | rest | **V00.84** (JS-SEC-165): 429 mit `Retry-After` für `Throttled` und `Blocked` |
| `RestOriginGuard.install(guard)` / `.installed()` / `.reset()` | rest | **V00.84** (JS-SEC-163): prozessweiter Origin-Guard |
| `SecuredVisibility.refreshAll(UI)` | vaadin | **V00.84** (JS-SEC-167): alle Secured-Bindings einer UI neu auswerten |
| `VaadinJCustosStarter.serviceInit(event, rerouteTarget)` | vaadin-starter | **V00.84** (JS-SEC-168): Versionsprüfung, Versions-Bridge, Fehlerbehandler und OIDC-Cleanup in einem Aufruf |
| `RestDecisionContext.mapperOrDefault()` | rest | **V00.84** (JS-SEC-086): Decision-Mapper, über den eigene REST-Ablehnungen gerendert werden |
| `RestHeaderLines.joined(...)` / `.rejectDuplicates(...)` | rest | **V00.84** (JS-SEC-113): mehrzeilige Header für `RestRequest`-Adapter |
| `Secured.wrap(Class, impl)` / `Secured.requireAllowed(Class, methodName)` | standalone | Dynamic-Proxy-Enforcement |

---

## 16. Was nicht im Scope ist (Roadmap-Negativliste)

- ❌ **Spring Security / Jakarta Security Replacement** — bewusst minimalistisch.
- ❌ **SAML / LDAP / Kerberos** — kann als eigener Adapter obendrauf gebaut
  werden, aber nicht im Kern. OAuth2, OIDC und JWT sind dagegen
  inzwischen im Scope: die Verträge liegen in `jCustos-core`
  (`oauth2/api`, `oidc/api`, `jwt/api`), die Implementierungen in eigenen
  Modulen (`jCustos-jwt`, `jCustos-oauth2*`, `jCustos-identity-oidc*`,
  sechs Hersteller-Profile `jCustos-identity-vendor-*`).
- ❌ **Eigener Cluster-Store** — jCustos liefert keinen JDBC-, Redis- oder
  Hazelcast-Adapter; die In-Memory-Defaults sind single-node, und Eclipse
  Store ist eine eingebettete Speicherung für einen Prozess, kein
  Cluster-Store. Mehrere Knoten sind seit **V00.84** dennoch ein
  dokumentierter Betriebsfall (JS-SEC-166):
  `docs/security/deployment/cluster.md` nennt die Stores, die alle Knoten
  teilen müssen, die Bausteine, die bewusst pro Knoten bleiben
  (Abuse-Erkennung, KDF-Limiter, Credential-Check-Gate), und was ein Store
  für mehrere Knoten garantieren muss. Die Contract-Suites
  (`LoginAttemptStoreContract`, `RateLimitStoreContract`) prüfen zwei
  Knoten auf einem Store, und `StoreBackedLoginAttemptPolicy` sperrt pro
  Konto über alle Adressen.
- ❌ **Policy-Composing-DSL** — Annotationen und Code sind die
  Konfigurations-Schicht.
- ❌ **`security-javafx`** — geplant, wartet auf realen JavaFX-Bedarf.
  `jCustos-standalone` deckt funktional Swing / JavaFX / CLI ab.

---

## 17. Versions- & Plattform-Eckdaten

- **Java 26** (Sealed Types, Records, Pattern Matching durchgängig)
- **Vaadin 25.3.3** (vaadin-core, kein Hilla)
- **Jetty 12.1.15 EE11** (`jetty-ee11-maven-plugin`) als Dev-Server für die Vaadin-Demos
- **Maven 4** (pinned via `./mvnw`; Minimum `4.0.0-rc-5`)
- **Eclipse Store 4.1.0** (`org.eclipse.store:storage-embedded`) für
  die durable Persistence-Referenz in `jCustos-persistence-eclipsestore`
- **proxybuilder 00.11.01** (`com.svenruppert:proxybuilder` +
  `proxybuilder-annotations`) für den Compile-Time-Processor
- **Bouncy Castle 1.86** (`org.bouncycastle:bcprov-jdk18on`) im optionalen
  `jCustos-crypto-bc`
- **Lizenz:** EUPL v1.2
- **Aktuelle Version:** `00.84.00` (§1–§17 dokumentieren den V00.70.00-Kernstand, ergänzt um die mit **V00.84** markierten Änderungen; § 18 das V00.80.00-Delta Betrieb & Forensik; alles Weitere in den `RELEASE-NOTES-*.md`)
- **Betriebsleitfäden (V00.84):** `docs/security/deployment/reverse-proxy.md`,
  `docs/security/deployment/reverse-proxy-embedded-jetty.md` (eingebettetes
  Jetty 12 hinter einem TLS-Proxy: Connector auf Loopback, Cookie-Attribute,
  kein Server-Banner, `X-Request-ID`, Adresslimit, Origin-Guard),
  `docs/security/deployment/cluster.md`, `docs/security/csrf.md`,
  `docs/security/release-verification.md`

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
- ⚠️ **V00.84 — Schlüsselbindung an den Producer** (JS-SEC-101): `JCustosEventVerificationKeyResolver.mayVerify(keyId, producerId, tenantId)` wird nach der Signaturprüfung gefragt; ein Schlüssel, der nicht an den beanspruchten Producer gebunden ist, ergibt `KeyNotAuthorizedForProducer`. `JdkKeyStoreKeyManagement` bindet über den Alias-Namen oder `withProducerBinding(...)`; ein eigener Resolver erbt „Key-ID = Producer-ID“.
- ⚠️ **V00.84 — Payload-Metadaten-Prüfung** (JS-SEC-107): `ConsumePipeline` dekodiert die kanonische Payload und vergleicht Event-Typ, Event-ID, Tenant, Subjekt und Zeitpunkt mit dem Envelope; Abweichung, nicht dekodierbare Payload oder unbekannter Content-Type ergeben `PayloadMetadataMismatch`. `Valid.payload()` liefert die geprüfte Payload — Konsumenten lesen das Event dort statt `canonicalPayload` selbst zu dekodieren.
- ⚠️ **V00.84 — Sequenzen und Ablehnungen**: ein frischer Scope akzeptiert nur bis `maxInitialSequence` (Default 1), eine begrenzte Lücke ist über `maxTolerableGap` tolerierbar (`new SequenceValidator(maxInitialSequence, maxTolerableGap)`), `resetSequence`/`releaseReservation` am `JCustosEventSequenceStore` (JS-SEC-105, JS-SEC-108); Ablehnungen nicht authentifizierter Envelopes laufen unter dem System-Tenant und sind auf 20 pro Minute gedrosselt (`suppressedUnauthenticatedCount()`, `SelfObservabilityEvents.isUnauthenticatedRejection`, JS-SEC-104); Dead Letters werden über `storeOrMerge` zusammengeführt, `InMemoryDeadLetterStore` hält standardmäßig 1 000 offene Datensätze (JS-SEC-109).

### Guides

- `docs/dx/5-minute-setup-monitoring.md`
- `docs/dx/5-minute-setup-event-exporters.md`
- `docs/dx/5-minute-setup-audit-integrity.md`
