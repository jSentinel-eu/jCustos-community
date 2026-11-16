# Rollback Boundaries

Status: draft — V00.71.00
CWE: CWE-693 (Protection Mechanism Failure), CWE-1391 (Use of
Weak Credentials)

## Why this document exists

Credential incident response sometimes goes wrong. Operators
reach for "undo" reflexively, and some undo paths in the
credential pipeline are themselves dangerous. This document
lists what is reversible, what is conditionally reversible, and
what is permanently one-way.

## Reversible

| Action                              | How to roll back                                       |
|-------------------------------------|--------------------------------------------------------|
| `EmergencyPolicyOverride` registration | Stop using the override record; no state change resulted from instantiating it. |
| `AbuseDecision.Block` throttle      | Wait for the window to expire, or restart with a tighter window.        |
| Policy version increment            | Decrement (deploy the previous policy) — old envelopes still verify under it. |
| Provider downgrade (pin previous version) | Re-pin the affected dependency; SBOM diff verifies the change.    |
| `MUST_CHANGE` status flip           | Operator-issued `CredentialLifecycleService` transition back to `ACTIVE`. Rare; needs an audit-recorded justification. Never for a credential that was `COMPROMISED`: since V00.84.00 `COMPROMISED` cannot return to `ACTIVE` without a new secret (JS-SEC-076), and a detour through `MUST_CHANGE` would accept the compromised secret again. |

## Conditionally reversible

These actions are reversible only within a *window* and only if
no downstream operation has consumed the new state.

| Action                       | Window                                                            |
|------------------------------|-------------------------------------------------------------------|
| Pepper key rotation          | Until **any** credential has been rehashed under the new key. After the first rehash, the old key cannot re-derive the new envelope's HMAC tag. |
| Algorithm deprecation        | Until **any** credential has been rehashed under the new algorithm. |
| Token (reset / API key) bulk invalidation | Until the new token issuance has been published. Once a user has obtained a new token, the old digest cannot be restored without re-issuance. |
| Framework downgrade from V00.84.00 | Until V00.84.00 writes the first bcrypt hash — a rehash at login, a new or changed password: its envelope carries `term=1`, which no earlier release can verify (JS-SEC-133), and until the Eclipse-Store storage is first opened and converted to the 00.84.00 layout (`persistence/storage-layout-migrated`), which no earlier release can open (JS-SEC-125). Back up the storage directory before the upgrade. |

## One-way (no rollback)

These actions cannot be undone. Operators must be certain before
executing them.

- **Pepper key destruction.** Once an HSM key has been
  destroyed (not merely disabled), every envelope produced under
  it is permanently unverifiable. The credential is effectively
  reset to no-password state and the user must re-enrol.
- **Credential hash deletion** (admin force-reset that overwrites
  the stored envelope). The previous envelope is gone; the user
  must re-enrol through the reset flow.
- **Audit log retention purge.** Once an audit retention boundary
  has dropped events, they cannot be recovered. Time-bounded
  incident review must complete before purge.
- **Selector compromise.** Reset / API-key selectors are
  one-shot in the V00.71 design. Once a selector is used or
  marked consumed, the next attempt with the same value will
  fail — by design (CWE-294 / CWE-640).

## Anti-patterns

The following appear safe but are not:

- "Re-upload the database from yesterday." This rolls every CAS
  state back, including legitimate rehashes that happened
  between the backup and the rollback. Users whose credentials
  rehashed in that window will see their fresh envelope
  reverted; a subsequent successful login will rehash them
  again. The audit trail is left inconsistent.
- "Restore the pepper key from the backup." If the backup is
  outside the HSM, it is by definition not the HSM-protected
  key — this is a confidentiality escalation, not a rollback.
- "Disable the abuse detector to clear the queue." Disabling
  the detector lifts the throttle on the legitimate attacker.

## Decision rule

If a recovery step is conditionally reversible or one-way, the
operator must:

1. Confirm a written `EmergencyPolicyOverride` exists for the
   incident.
2. Get a second operator sign-off in the incident record.
3. Snapshot the audit log up to the present moment before acting.
4. Document the expected post-state and the success criterion.

## What the framework does not enforce

- The framework does not refuse one-way actions.
- The framework does not require multi-operator sign-off.

These are organisational controls. The framework provides the
audit hooks that make those controls auditable; the controls
themselves live in the consuming organisation.
