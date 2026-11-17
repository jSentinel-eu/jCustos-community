# Running jCustos on several nodes

Status: 00.84.00 · JS-SEC-166, JS-SEC-012, JS-SEC-062 · CWE-307 (Improper Restriction of Excessive
Authentication Attempts)

jCustos ships no cluster store of its own: there is no JDBC, Redis or Hazelcast adapter. What it
ships are the store SPIs that a cluster needs, the policies that use them correctly, and contract
tests that a store for several nodes has to pass. This page says which state the nodes must share,
which building blocks deliberately stay on each node, what a store you write or buy has to
guarantee, and how to test it.

The short version: every counter, every single-use mark and every revocation that protects an
account or a token has to live in a store that all nodes reach. A node that keeps such state in its
own memory turns every limit into "limit × number of nodes" and every single-use token into
"once per node".

## Eclipse Store is not a cluster store

`jCustos-persistence-eclipsestore` opens an **embedded** storage: one `EmbeddedStorageManager` in
one process, on a local directory that the process locks, owns and restricts to its own user, with
reads and writes serialised by a lock inside the JVM (`EclipseStoreJCustosStorage`). A second
process cannot open the same directory, and nothing replicates it. Use it to keep lockouts,
sessions and tokens across a **restart of a single node**. For several nodes, every store listed
below needs an implementation over a service that all nodes share.

## State the nodes must share

| SPI | What it holds | Shipped implementations | Wired through | With one instance per node |
|---|---|---|---|---|
| `LoginAttemptStore` (`eu.jsentinel.jcustos.bruteforce`) | failed-login counters and attempts in flight per tuple, account and address key | `InMemoryLoginAttemptStore`, Eclipse Store | `new StoreBackedLoginAttemptPolicy(store, ...)`, then `.bruteForce(policy)` | each node locks after its own threshold; an attacker spreads the guesses over the nodes |
| `RateLimitStore` (`eu.jsentinel.jcustos.ratelimiting`) | the events of a sliding window, throttle counts and blocks | `InMemoryRateLimitStore`, Eclipse Store | `new InMemoryRateLimitPolicy(store, audit, limit, window, clock[, escalation])`, called by your handler (`.rateLimit(...)` is recorded, not wired) | the limit applies per node |
| `SessionStore` (`eu.jsentinel.jcustos.session`) | the session inventory and its revocations (`REVOKED`) | `InMemorySessionStore`, `SweepingSessionStore` (decorator), Eclipse Store | `.sessions(s -> s.storeBacked(store))` | a session revoked on one node lives on on the others |
| `JCustosVersionStore` (`eu.jsentinel.jcustos.session`) | the security version per subject (drift detection) | `InMemoryJCustosVersionStore`, Eclipse Store | `.sessions(s -> s.securityVersion(store))` | a role change on one node does not end the sessions on another |
| `JtiStore` (`eu.jsentinel.jcustos.replay.api`) | the `jti` of DPoP proofs and of OIDC logout tokens already seen | `InMemoryJtiStore` only ("for a single JVM only") | `new NimbusDpopProofValidator(algorithms, jtiStore, clock)`, `new DefaultLogoutTokenValidator(validator, issuer, clientId, jtiStore)` | a proof or logout token replayed to another node is accepted again |
| `StateStore` (`eu.jsentinel.jcustos.oauth2.api`) | the single-use `state` of an authorisation-code flow | `JdkInMemoryStateStore` (in process), `VaadinSessionStateStore` (in the Vaadin session) | `new HttpAuthorizationCodeFlow(config, tokenEndpoint, stateStore)` | a callback that reaches another node than the one that started the login fails |
| `JCustosEventReplayStore`, `JCustosEventSequenceStore` (`jCustos-events`) | envelopes already consumed; the last accepted sequence per tenant and producer | in-memory only | constructor parameters of `ConsumePipeline` and `PublishPipeline` | each node accepts a replayed envelope once and checks sequences on its own |

The same holds for every store that consumes a token once or rotates it: `RefreshTokenFamilyStore`
(`RefreshTokenRotator`), `RememberMeTokenStore` (`StoreBackedRememberMeService`),
`PasswordResetTokenStore`, `EmailVerificationTokenStore` and `ResetTokenStore`. A single-use token
held per node can be used once on every node.

Two notes on sessions:

- jCustos's `SessionStore` is the session **inventory and revocation list**, not the HTTP session.
  Vaadin keeps the UI state in the HTTP session of the node that serves it; run a Vaadin cluster
  with sticky sessions, as Vaadin requires anyway.
- A revocation is a record with the status `REVOKED`, not a deletion. `VaadinSessionRevocation`
  ends a session whose record is missing only on a node that saw the record on an earlier request,
  and `RestSessionRevocation` remembers the records it has seen per JVM. On several nodes, revoke
  by status (the session-management view and `VaadinSessionRevocation.revoke(...)` do), and for
  REST consider `RestSessionRevocation.requireRecord(true)`: a session id without a record is then
  refused on every node, and the application has to save the record before it hands out the
  token.

## The login throttle on several nodes

The resolver default, `InMemoryLoginAttemptPolicy`, keeps its counters in the memory of one node.
For several nodes, register a `StoreBackedLoginAttemptPolicy` over a shared `LoginAttemptStore`:

```java
LoginAttemptStore shared = yourSharedLoginAttemptStore();          // your adapter
LoginAttemptLimits limits = LoginAttemptLimits.defaults()
    .withAddressLimit(new LoginAttemptLimits.AddressLimit(
        50, Duration.ofHours(1), Duration.ofMinutes(30), Duration.ofHours(2)));
LoginAttemptPolicy policy = new StoreBackedLoginAttemptPolicy(shared, limits,
    TenantId.DEFAULT, Clock.systemUTC(), SubjectKeyCanonicalizer.defaults(), null);

VaadinSecurity.bootstrap()
    .bruteForce(policy)
    .clientAddress(ClientAddressResolver.trustedProxies("10.0.0.0/8"))
    .sessions(s -> s.storeBacked(yourSharedSessionStore()))
    // ...
    .install();
```

Since 00.84.00 the store-backed policy counts every attempt on the same dimensions as the in-memory
policy (JS-SEC-166):

- the **tuple** `(tenant, user name, address)`;
- the **account**, `LoginAttemptKey.forAccount(tenant, user name)`, across all addresses - the
  user-name counter of the in-memory policy. Until 00.84.00 the store-backed policy counted the
  tuple only (JS-SEC-012), so whoever moved to it to run several nodes lost the protection against
  an attacker who changes address after every few guesses;
- the **address**, `LoginAttemptKey.forAddress(tenant, address)`, across all accounts - only with
  `LoginAttemptLimits.perAddress()` (JS-SEC-062, password spraying).

The account counter is always on, as it is in the in-memory policy. The consequence is the same as
there: whoever knows a user name can lock that account for `initialLockout` by failing
`failureThreshold` times, from any addresses. A successful login never lifts a lockout in force.

The policy keeps no state of its own. Every node asks the store, so a lockout earned through one
node refuses the account on every node, and the attempts in flight on all nodes together never
exceed the threshold - provided the store is atomic as described below. An attempt that a node
admitted but never reported, because the node failed, lapses after
`InMemoryLoginAttemptPolicy.ATTEMPT_RESERVATION_TTL` (30 seconds) and frees its slot. The lockout of
the store-backed policy is flat (`initialLockout` from the failure that reached the threshold); the
progressive backoff of the in-memory policy needs per-key history the store contract does not carry.

The tuple, the account and the address are separate store operations, not one atomic step: a
lockout of one of them that sets in between them is caught by the next attempt.

## Building blocks that stay on each node

These are deliberately per node. They protect the node they run on, or they have no store SPI in
this release; their limits therefore add up across the nodes.

- **Abuse detection** (`AbuseDetectionService`, `AbusePatternMonitor`, `eu.jsentinel.jcustos.credential.abuse`).
  The shipped `InMemoryAbuseDetectionService` keeps its counters on the heap of one node, and there
  is no store SPI for it. Its counters (`AbuseDimension`: user name, client address, tenant, the
  global ceiling) are therefore per node: with `n` nodes an attacker gets `n` times the volume. The account and address counters
  of the login policy above are the cluster-wide limit on password guessing. For cluster-wide abuse
  limits, implement `AbuseDetectionService` over a shared store, as its Javadoc asks of
  multi-node deployments.
- **KDF limiter** (`SemaphoreKdfExecutionLimiter`, `KdfResourceBudget`). It bounds how many
  memory-hard hash computations run at the same time **in this JVM** (default: 16, waiting at most
  250 ms) - a protection of this node's CPU and memory. Sharing it would make no sense.
- **Credential-check gate** (`CredentialCheckGate`, R3, JS-SEC-063). The gate of a login policy
  (`LoginAttemptLimits.maxConcurrentCredentialChecks`) holds a fixed number of permits per policy
  instance, so it bounds the concurrent credential checks of one node. The cluster as a whole runs
  up to `permits × nodes` checks; size the permits for one node.
- **Proactive reaction to a version change** (`ObservableJCustosVersionStore`, R8, JS-SEC-167). The
  decorator notifies the listeners of the node that changed the version, so only the sessions on
  that node are ended at once and only their controls refreshed. The other nodes read the new
  version from the shared `JCustosVersionStore` and end a drifted session at its next request (the
  per-request check of `JCustosVersionEnforcerListener`). Proactive delivery to every node would need
  a message bus between the nodes; this release ships none.

## What a store for several nodes has to guarantee

- **Every operation is atomic in the backend, for every caller.** A lock inside the JVM is not
  enough: every node has its own instance. `LoginAttemptStore.tryBeginAttempt`, `completeFailure`,
  `completeSuccess` and `abandonAttempt` each check and change one key in one step (a transaction
  with a row lock, a compare-and-set loop, a server-side script). `RateLimitStore.tryAdmit` checks
  the window and records the event in one step; `block` only ever extends a block, also when two
  nodes block at the same time. `JtiStore.record` is a set-if-absent with a lifetime, and the
  replay store's `markSeen` lets exactly one consumer win. A store that inherits the SPI defaults
  of `LoginAttemptStore` keeps working, but without reservations: parallel guesses on several nodes
  can then all be evaluated.
- **Instants may be coarse.** A store may keep lockout ends in milliseconds or whole seconds (a JDBC
  `TIMESTAMP(3)` or `DATETIME` column). The store-backed login policy decides whether a failure
  caused the lockout it reads back within `StoreBackedLoginAttemptPolicy.STORE_INSTANT_TOLERANCE`
  (one second), so the lockout is still audited; `LoginAttemptStoreContract` checks this at
  sub-millisecond instants.
- **The time comes from the caller.** The policies pass their own clock's instant (`now`,
  `since`) to the store. The store evaluates with those instants and does not mix in a clock of its
  own; it accepts them out of order, because a node whose clock is behind reports an earlier
  instant after a node whose clock is ahead.
- **Keys are stored verbatim.** Login keys use reserved user ids - `#address`, the `#account:`
  prefix with the address `#any` - and rate-limit keys the scope prefix `#throttled:`. A store that
  rewrites, truncates or case-folds keys merges counters that must stay apart.
- **The store is bounded and never evicts a live lockout.** It is keyed on values an attacker
  chooses; see the `LoginAttemptStore` Javadoc for what a bounded store must do when it is full.
- **Lockouts follow from counter, last failure and the caller's limits.** The store keeps a
  counter and a last-failure instant per key, as the SPI defaults do; a lockout restored from them
  survives a restart of the store as well.

## Clock synchronisation

The nodes' clocks decide when a window ends and when a lockout or a block runs out. A skew between
two nodes moves those moments by up to the skew, in either direction: a node whose clock is two
seconds ahead lets an account in two seconds before the others do, and a node two seconds behind
keeps it locked two seconds longer. Nothing is released early beyond the skew, and nothing stays
locked for good. Keep the nodes synchronised (NTP); the contract tests check a skew of two seconds.

## Testing a store for several nodes

`jCustos-persistence-testkit` contains the contracts a store has to pass:
`LoginAttemptStoreContract` and `AtomicLoginAttemptStoreContract` for a `LoginAttemptStore`,
`RateLimitStoreContract` for a `RateLimitStore`. Implement the contract interface in a test class
and return a fresh store from `newStore()`. Since 00.84.00 the tests whose name starts with
`JS-SEC-166` run two policies - two "nodes" - against the store:

- a lockout earned through node A refuses the account on node B, from any address;
- 2 × 24 threads on the two nodes: exactly the threshold (login) or the limit (rate limit) is
  admitted, every round;
- the attempts in flight of a node that fails lapse after the reservation lifetime;
- the throttles of both nodes count towards one block, and the block refuses on both;
- a clock skew of ±2 seconds moves the end of a lockout, a window or a block by at most two
  seconds.

By default node B uses the same store instance as node A, which only proves atomicity within one
instance. Override `secondNodeStore(store)` to return a second client of the same backend - the
way a second node would build it - so that the two nodes meet in the backend.

## Bootstrap findings

`install()` of the Vaadin and REST bootstraps reports two configurations that do not fit several
nodes (the standalone adapter has neither sessions nor client addresses):

| Code | Severity | When |
|---|---|---|
| `bruteforce/in-memory-with-shared-sessions` | WARNING in PRODUCTION and STRICT; not reported in DEVELOPMENT and COMMUNITY_DEFAULTS | sessions are store-backed (`.sessions(s -> s.storeBacked(...))`), but the effective login policy is an `InMemoryLoginAttemptPolicy` - passed to `.bruteForce(...)` or the resolver default |
| `bruteforce/address-limit-without-resolver` | WARNING | the effective login policy has an address limit (`LoginAttemptLimits.perAddress()`), but no `ClientAddressResolver` was passed to `.clientAddress(...)` or registered; behind a reverse proxy every client then shares the proxy's counter. Without a proxy, confirm the connection peer with `.clientAddress(ClientAddressResolver.remoteAddress())` |

See also [Running jCustos behind a reverse proxy](reverse-proxy.md) for the client address that
the tuple and address counters are keyed on.
