# Playbook — Pepper Compromise

Status: draft — V00.71.00
CWE: CWE-320 (Key Management Errors), CWE-522 (Insufficiently
Protected Credentials), CWE-778 (Insufficient Logging)

## Trigger

One or more of:

- The pepper-key store / HSM is suspected breached.
- A backup containing the pepper key was exfiltrated or leaked.
- Audit logs show pepper-key access from an unexpected principal.
- A staff member with pepper-key access has departed under
  irregular circumstances.

## Pre-conditions

The deployment uses a `PepperService` implementation that supports
key rotation. The default `InMemoryPepperService` does; an
operator-supplied HSM-backed implementation must (see
`../standards/pkcs11-hsm-pepper-key.md`).

## Response

### 1. Contain (minutes)

- Disable the suspected pepper key in the key store / HSM. From this
  point, `PepperService.applyHmac(ref, ...)` for that key id must
  start returning a structured failure or throwing — verifications
  using the old key will fall back to the dummy KDF and audit as
  `CredentialVerificationFailed` with the matching internal type.
- Confirm `JSentinelAuditService` is forwarding events to your
  long-term audit sink. Pepper-compromise response writes a
  significant audit volume; the runbook is unusable without it.

### 2. Rotate (minutes — hours)

- Generate a new pepper key inside the HSM / pepper store.
- Update the `PepperService` configuration so the new key becomes
  the **active** reference.
- The old key remains available **read-only** for the rotation
  window so existing verifications can still re-derive and rehash.

### 3. Re-encode (hours — days)

The credential pipeline already supports transparent re-encoding:

- On every successful verification, `RehashDecisionEngine` emits
  `RehashDecision.Required(RehashReason.PEPPER_KEY_ROTATED)`.
- The change-flow callers re-hash with the new active pepper key
  and CAS-update the store.

For deployments that cannot wait for organic re-encoding (large
user base, idle accounts):

- Use `MassCredentialStatusChange.forceAllToStatus(...,
  CredentialStatus.MUST_CHANGE, override)` to mark every account
  as needing a credential refresh.
- The override record carries
  `EmergencyPolicyOverride.Reason.PEPPER_COMPROMISE` so every
  status change is auditable as part of the same incident.
- Since V00.84.00 a failing audit sink no longer stops the run
  (JS-SEC-077): the helper goes on with the remaining accounts, and
  the returned `Report.auditFailures()` counts the status changes
  whose audit event was lost. A non-zero count means the incident
  record has to be completed from the report, not from the audit
  stream.

### 4. Decommission the old key (after re-encoding completes)

- Wait until audit shows no further verifications using the old
  pepper key id.
- Disable the old key entirely in the HSM. Verifications that still
  reference it after this point are guaranteed to fail — the dummy
  KDF preserves observational equivalence to unknown-user lookups
  (CWE-203).
- Archive the old key id and the rotation timestamps in the
  incident record. Do **not** archive the key material.

## Rollback boundary

You cannot roll back the **rotation** itself — once rehashing has
re-encoded credentials under the new key, the old key cannot decode
them. Rollback is only meaningful in the narrow window before any
account has been rehashed.

## Operator checklist

- [ ] Disable suspected pepper key.
- [ ] Generate new pepper key inside the HSM.
- [ ] Update `PepperService` active reference.
- [ ] Verify that new verifications carry `pepperKeyIdPresent=true`
      with the new id (`CredentialVerificationSucceeded` audit).
- [ ] (Optional) Force MUST_CHANGE for affected scope via the
      `MassCredentialStatusChange` helper.
- [ ] Decommission old key after re-encoding completes.
- [ ] File post-incident review using
      `audit-review-checklist.md`.

## What the framework does not do

- It does **not** detect pepper-key compromise — that is an HSM /
  audit-pipeline concern.
- It does **not** automatically force MUST_CHANGE — the operator
  invokes the mass-change helper explicitly.
- It does **not** notify users — notification belongs in the
  consuming application.
