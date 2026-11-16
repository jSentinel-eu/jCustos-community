# Demo: Vaadin UI gegen REST-Backend

`demo-vaadin-rest-client` zeigt das Zielbild für eine reale Architektur:
ein REST-Server (`demo-rest`) hält die Datenhoheit über Benutzer, Rollen,
Permissions; eine Vaadin-Flow-UI ist reiner Client und benutzt einen
gekapselten Java-Backend-Client für jede HTTP-Interaktion.

> **Verwandte Demos**:
> - [`demo-vaadin.md`](demo-vaadin.md) — dieselbe UI-Idee, aber
>   single-JVM (kein Backend, kein HTTP).
> - [`demo-rest.md`](demo-rest.md) — der gleiche REST-Server, aber
>   ohne UI (CLI-Client statt Browser).
> - [`bootstrap.md`](bootstrap.md) — der Initial-Admin-Setup-
>   Mechanismus, den dieses Demo `/setup` über REST aufruft.

## Architektur-Leitlinien

- **Vaadin-Code sieht keine REST-Aufrufe.** Im gesamten `views/`,
  `security/` Code findest du keinen Import von `java.net.http.*`,
  `URI`, `HttpClient`, JSON-Encoding oder Endpoint-Pfaden. Der
  Vertrag ist `DemoBackendClient`; die HTTP-Implementierung
  (`HttpDemoBackendClient`) ist die einzige Klasse mit Transport-Wissen.
- **REST-Server ist authoritativ.** Mutierende Klicks rufen den Server.
  Der Server liefert `200 / 401 / 403` zurück und hat das letzte Wort.
  Lokale `PermissionGuard`-Checks gegen den gecachten `RemoteUser` sind
  reine UX-Hinweise.
- **Bootstrap geht über REST.** Die Vaadin-`/setup`-Seite ruft
  `POST /api/bootstrap/admin` — sie macht keine eigene Admin-Logik im JVM.

## Voraussetzungen

- JDK 26+
- Maven 3.9.9+
- `demo-rest` und `demo-rest-shared` müssen einmal im lokalen `~/.m2/`
  installiert sein (passiert automatisch bei `mvn install` aus dem
  Projekt-Root).

```bash
# Einmalig: alles bauen + installieren
mvn clean install -DskipTests
```

## Demo starten

Zwei Konsolen — Backend und Frontend laufen als zwei separate Prozesse.

### Konsole 1 — Backend (`demo-rest`)

```bash
mvn -pl :demo-rest exec:java
```

Defaults:

- HTTP-Server auf `http://localhost:8080`
- Bootstrap-Modus `TRANSIENT_CONSOLE` — der Token wird **in die Backend-
  Konsole** gedruckt, sobald der Server bootet:

```
============================================================
Initial administrator setup required.

Open the Vaadin setup page or POST to /api/bootstrap/admin
(server on port 8080).

Bootstrap token:
  AAAA-BBBB-CCCC-DDDD-EEEE

This token is single-use and only valid while the system is uninitialized.
============================================================
```

### Konsole 2 — Vaadin-Client (`demo-vaadin-rest-client`)

```bash
mvn -pl :demo-vaadin-rest-client jetty:run
```

- UI auf `http://localhost:9090/`
- Backend-URL default `http://localhost:8080`. Override via:

```bash
mvn -pl :demo-vaadin-rest-client jetty:run -Ddemo.backend.url=http://localhost:9000
```

Oder per Env-Var: `DEMO_BACKEND_URL=http://localhost:9000`.

## Reviewer-Pfad

1. Browser öffnet `http://localhost:9090/`. Da es noch keinen Admin gibt,
   leitet die UI auf `/setup` um.
2. Setup-Form ausfüllen:
   - **Bootstrap token**: aus Backend-Konsole kopieren
   - **Admin username**: `admin`
   - **Password** + Bestätigung
3. Nach „Create administrator" → Erfolg → Forward zu `/login`.
4. Login als `admin` mit dem gerade gesetzten Passwort.
5. Welcome-Screen zeigt die vom Backend gelieferten Rollen + Permissions.
6. Linke Navigation:
   - **Documents** — `BackendOperationCard` mit echten REST-Calls.
     Klick auf „Create document" → 201. Klick auf „Delete document #1"
     → je nach Rolle 204 oder 403.
   - **Permission demo** — Pattern A (UX) vs. Pattern B (lokaler Guard).
     Vergleicht UX-Sichtbarkeit mit der lokalen `PermissionGuard`-Logik
     gegen den gecachten Subject-Snapshot.
   - **Standalone routes** — drei Router-Links zu drei Stilen:
     - `/documents` — `@RequiresPermission("document:read")` (Stil A1)
     - `/admin` — `@RequiresRole("ROLE_ADMIN")` (Stil A2)
     - `/nerd` — `@VisibleForRoles({ADMIN, EDITOR})` (Stil B, projekt-eigen)
7. Logout: Sign-out-Button rechts oben → ruft `POST /api/logout`,
   invalidiert VaadinSession + HTTP-Session, leitet auf `/login`.

## Mit anderen Demo-Usern testen

Demo-User mit festen Passwörtern legt das Backend seit 00.84.00
(JS-SEC-137) nur mit dem Entwicklungsschalter
`-Djcustos.demo.insecure-seed-accounts=true` an — ausschließlich für eine
lokale Wegwerf-Instanz, nie für eine, die andere erreichen. Mit dem
Schalter entstehen `editor/editor` und `viewer/viewer`; startet das Backend
zusätzlich mit `SECURITY_BOOTSTRAP_MODE=DISABLED`, auch `admin/admin`, und
der Setup-Flow entfällt. Ohne den Schalter verweigert der Modus `DISABLED`
den Start, weil dann niemand einen Administrator anlegen könnte.

```bash
# Backend (nur lokal: feste, öffentlich bekannte Passwörter)
mvn -pl :demo-rest exec:java -Dsecurity.bootstrap.mode=DISABLED \
    -Djcustos.demo.insecure-seed-accounts=true

# Frontend (anderes Terminal)
mvn -pl :demo-vaadin-rest-client jetty:run
```

Browser öffnet `/login` direkt, kein `/setup` erforderlich.

## Was die Demo zeigt

| Schicht | Mechanismus | Datei |
|---|---|---|
| Auth (HTTP) | `RestBackedAuthenticationService` ruft `backend.login(...)`, cached Token + RemoteUser | `security/RestBackedAuthenticationService.java` |
| Authorization-Snapshot | `RestBackedAuthorizationService` liefert Rollen + Permissions aus dem RemoteUser | `security/RestBackedAuthorizationService.java` |
| View-Schutz Stil A1 | `@RequiresPermission` auf der Route | `views/standalone/DocumentsView.java` |
| View-Schutz Stil A2 | `@RequiresRole` auf der Route | `views/standalone/AdminStatusView.java` |
| View-Schutz Stil B | Projekt-eigene `@VisibleForRoles` + `ProjectRoleAccessEvaluator` | `views/standalone/NerdView.java`, `security/VisibleForRoles.java`, `security/ProjectRoleAccessEvaluator.java` |
| UX-Adaption | `PermissionGuard.hasPermission` gegen den gecachten Subject | `views/components/PermissionDemoCard.java` |
| Server-authoritativer Klick | echte REST-Calls über den `DemoBackendClient` | `views/components/BackendOperationCard.java` |
| Bootstrap-via-REST | `/setup` ruft `backend.createInitialAdmin(...)` | `views/SetupView.java` |
| Logout | `VaadinLogoutService` + vorgeschalteter `backend.logout(token)` | `views/MainView.java` |

## Konfiguration — vollständig

| Sysprop | Env | Default |
|---|---|---|
| `demo.backend.url` | `DEMO_BACKEND_URL` | `http://localhost:8080` |
| `demo.backend.connect-timeout` | `DEMO_BACKEND_CONNECT_TIMEOUT` | `PT5S` |
| `demo.backend.request-timeout` | `DEMO_BACKEND_REQUEST_TIMEOUT` | `PT10S` |

Backend-seitig (gilt für `demo-rest`, nicht für den Client):

| Sysprop | Env | Default |
|---|---|---|
| `security.bootstrap.mode` | `SECURITY_BOOTSTRAP_MODE` | `TRANSIENT_CONSOLE` |
| `security.bootstrap.token.file` | `SECURITY_BOOTSTRAP_TOKEN_FILE` | `./data/bootstrap.token` |
| `security.bootstrap.token.ttl` | `SECURITY_BOOTSTRAP_TOKEN_TTL` | `PT24H` |
| `jcustos.demo.insecure-seed-accounts` | — | `false` (Demo-User mit festen Passwörtern, nur lokal) |

## Bekannte Limitierungen

- Kein Token-Refresh — bei `401` muss der User neu einloggen.
- Kein Audit-Event für Login/Logout/Access-Denied (siehe Konzept V00.60 § 2).
- Keine UI-Tests (analog zu den anderen Vaadin-Demos).
- `RemoteUser` ist ein Snapshot; Permission-Änderungen am Backend wirken
  erst nach Re-Login.
