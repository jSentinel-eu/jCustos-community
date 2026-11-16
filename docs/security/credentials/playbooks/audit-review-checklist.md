# Audit Review Checklist

Status: draft — V00.71.00
CWE: CWE-778 (Insufficient Logging), CWE-693 (Protection
Mechanism Failure)

## Purpose

A reproducible review path for the credential audit stream.
Use it after every incident covered by the playbooks in this
directory; use it on a recurring schedule (weekly / monthly) for
hygiene.

## Audit events to review

The credential pipeline produces a fixed inventory of events
under `JSentinelAuditService`. The review covers:

| Event                              | Look for                                                |
|------------------------------------|---------------------------------------------------------|
| `CredentialVerificationSucceeded`  | Volume by algorithm + policy version; rehash trend.    |
| `CredentialVerificationFailed`     | Spike by `internalAuditEventType`; unknown user vs malformed envelope vs limiter rejection. |
| `CredentialRehashed`               | Rehash reason distribution: `ALGORITHM_DEPRECATED`, `PARAMETERS_OUTDATED`, `POLICY_VERSION_OUTDATED`, `PEPPER_KEY_ROTATED`. |
| `CredentialStatusChanged`          | Bulk transitions; presence of an incident id in `reason` field. |
| `PasswordResetRequested` / `PasswordResetCompleted` | Volume; per-user cardinality. |
| `RateLimitExceeded`                | Scope distribution; sustained vs burst patterns.       |
| `LoginSucceeded` / `LoginFailed`   | Failure rate baseline shift; new client-address surfaces. Since V00.84.00 the login-attempt policy audits every rejected login exactly once (before, `StandaloneLoginFlow` audited it twice and the store-backed and Noop policies not at all) — do not compare a baseline across that upgrade. |
| `BruteForceLimitReached`           | Affected accounts; lockout durations.                  |

## Review steps

1. **Time-bound the query.** Pick the smallest window that still
   covers the suspected event. Wider is not better — overlong
   queries blur the signal.
2. **Bucket by event type.** Counts only, no payload at this stage.
3. **Drill into outliers.** Inspect the payload of events that
   break the baseline. Verify no field carries a secret-shaped
   value (password material, token verifier, derived key) —
   if any does, the leak is in the consuming application, not
   in the framework.
4. **Correlate with abuse patterns.**
   `AbusePatternSignal` events should match the throttle decisions
   in `RateLimitExceeded`. Mismatches indicate a misconfigured
   detector window.
5. **Verify rehash health.**
   Successful verifications with `rehashRequired=true` should
   produce a matching `CredentialRehashed` event soon after. A
   widening gap indicates a CAS-update problem in the store.
6. **Verify status-change accountability.** Every
   `CredentialStatusChanged` must carry a non-empty `reason`. A
   blank reason indicates application code skipping the
   `EmergencyPolicyOverride` discipline.

## Data minimisation invariants

The review must **not** rely on:

- raw passwords, derived keys, salt bytes, pepper key material;
- token verifiers (only digests are stored);
- secret-shaped fields in `toString()` output.

Any event whose `toString()` exposes such data is a defect in the
event record — file it as a bug against `jSentinel-core` rather
than working around it in the review tooling.

## Reporting

A review produces an artefact-only summary:

- counts per event category;
- list of incidents identified (each with an `incidentId`);
- list of follow-ups (each with an owner and target date).

The summary is archived alongside the audit-store retention
record. It does **not** include raw event payloads.

## What this checklist does not cover

- Application-level audit events that the consuming application
  publishes through its own pipeline.
- HSM operator-action audit (key creation, key disable) — that is
  in the HSM's audit scope.
- OS-level access audit for the audit store itself — that is in
  the platform's scope.
