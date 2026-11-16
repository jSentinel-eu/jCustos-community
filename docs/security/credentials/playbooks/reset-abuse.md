# Playbook — Password Reset Abuse

Status: draft — V00.71.00
CWE: CWE-307 (Improper Restriction of Repeated Authentication
Attempts), CWE-640 (Weak Password Recovery Mechanism),
CWE-203 (Observable Discrepancy), CWE-799 (Improper Control of
Interaction Frequency), CWE-645 (Overly Restrictive Account Lockout
Mechanism)

Revised for V00.84.00 (JS-SEC-121): the sections "Throttle" and
"What a reset request does to the account" describe the behaviour
from that version on.

## Trigger

- `AbusePatternMonitor` raises a `RESET_ABUSE` signal.
- Audit shows an elevated rate of
  `PasswordResetRequested` events against a single account or a
  set of accounts.
- Operations / support sees an unusual rate of "I didn't request
  this" complaints.

## Pre-conditions

- The deployment uses `PasswordResetService` from
  `jSentinel-core` (V00.71.00 selector/verifier model).
- `AbuseDetectionService` and `AbusePatternMonitor` are wired
  into the reset flow. Either the adapter evaluates the throttle
  before it calls `PasswordResetService.issue`, or the service is
  given the throttle through
  `PasswordResetService.withAbuseDetection(...)` and evaluates it
  itself; in the second case the adapter must not record
  `RESET_REQUEST` outcomes a second time.

## Response

### 1. Confirm the signal

- Query the audit sink for `PasswordResetRequested` and
  `RateLimitExceeded` events.
- Confirm the cardinality and time window. A burst of 5 requests
  for the same account within 60 minutes is the default
  threshold; deployments may have tightened it.

### 2. Throttle

- For `RESET_REQUEST` the per-username and the per-client-address
  counter are *volume* counters: every request counts, whatever
  its outcome, and an accepted request does not reset the window.
  With `AbuseLimitsPolicy.defaults()` the fourth request for one
  account within an hour is answered with `AbuseDecision.Delay`
  and the seventh with `AbuseDecision.Block`; per client address
  the limits are 10 (delay) and 30 (block) per hour.
- The per-username counter is keyed on the account, not on the
  spelling: `InMemoryAbuseDetectionService` applies a
  `SubjectKeyCanonicalizer` (by default NFKC, lower case, trimmed),
  so `alice`, `ALICE` and ` Alice ` share one budget since V00.84.00.
  A deployment with case-sensitive user names passes
  `SubjectKeyCanonicalizer.exact()`, as it does to its credential
  store and login policy.
- Before V00.84.00 the per-username counter was a failure counter.
  A request that was accepted for an existing account is a success,
  so it was never counted and cleared the window; the limit only
  ever applied to unknown usernames. Deployments that relied on it
  were not throttled per account.
- A service built with `withAbuseDetection(...)` refuses a blocked
  request with the same result it gives for a disabled account, for
  known and unknown usernames alike. A refused request issues no
  token and does **not** retire the link that was delivered last —
  repeating the request cannot keep every delivered link dead.
  Refused requests are not counted, so the block ends when the
  window has moved past the accepted ones.
- An accepted request still retires the older open links of the
  account (only the newest link works). An attacker can therefore
  invalidate at most as many links per hour as the per-username
  limit lets through; the link of the last accepted request stays
  usable until it expires.
- The block is timed (`retryAfter`). The framework does not
  surface this to end users beyond a generic message — that is
  the consuming application's responsibility. **Do not** add a
  detail field that confirms "your account is rate-limited" —
  it would be a user-enumeration channel (CWE-203).

### 3. What a reset request does to the account

- Nothing the owner would notice. A reset request is
  unauthenticated, so since V00.84.00 it leaves the status of a
  usable credential untouched: the password login keeps working
  while a link is open, and the password is only replaced when a
  link is consumed. Before, the request moved the credential to
  `RESET_PENDING`, which closed the password login until a link was
  consumed — anyone who knew a username could lock its owner out.
- Accounts that an earlier version left in `RESET_PENDING` stay
  there until a reset is completed for them; request a link for the
  affected user and have it consumed, or move the credential back
  with the lifecycle service after checking the account.
- The exception is a credential marked `COMPROMISED`: a reset
  request moves it to `RESET_PENDING` and it stays blocked until
  the link is consumed. When the last open link lapses unused it
  returns to `COMPROMISED`; adapters trigger that check with
  `PasswordResetService.releaseLapsedReset(username)`.

### 4. Invalidate outstanding tokens

If the abuse pattern suggests credential-stuffing of reset
tokens themselves:

- The reset token table uses the selector / verifier split. The
  selector is the only part visible to the client; the verifier
  is a SHA-256 digest stored at rest.
- Operators can retire the open links of one user with
  `ResetTokenStore.retireOpenTokens(username)` through the
  consuming application's admin path. A successful password change
  does the same when `PasswordChangeService` was given the reset
  store (`withResetTokenStore(...)`). The framework does not expose
  an invalidation across all users — it is intentional scope
  reduction.

### 5. Decide on credential rotation

- A high-confidence reset-abuse signal does **not** imply the
  account is compromised. Do not auto-rotate.
- If account-level compromise is suspected, run the per-account
  `MUST_CHANGE` transition via the lifecycle service. For
  service-wide concerns, see `pepper-compromise.md` or
  `algorithm-compromise.md`.

## Rollback boundary

- A throttle decision is automatically reversible — the next
  window expiry restores normal behaviour.
- A `MUST_CHANGE` transition is **not** automatically reversible.

## Operator checklist

- [ ] Confirm the `AbusePatternMonitor` signal from audit.
- [ ] Confirm throttling is active for the affected scope.
- [ ] Decide whether token bulk-invalidation is warranted.
- [ ] Avoid distinct user-facing messages that reveal throttle
      state (CWE-203, CWE-209).
- [ ] Post-incident review.

## What the framework does not do

- It does **not** notify end users that they were targeted.
- It does **not** silently extend the throttle window.
- It does **not** close the password login of an account because a
  reset was requested for it.
- It does **not** auto-rotate credentials.
- It does **not** publish or persist client IP addresses in
  abuse-pattern signals — those carry aggregates only.
