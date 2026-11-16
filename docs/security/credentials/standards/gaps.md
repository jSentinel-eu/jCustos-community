# Gaps and Deferred Items

Status: draft — V00.71.00

This document is the **honest counterpart** of the ASVS / NIST
mappings. Every requirement that the framework does not satisfy
in V00.71.00 has a row here so reviewers can see the boundary
between "implemented" and "not yet" without reading every other
document.

## Glossary

- **Out of scope**: The requirement does not belong inside a
  credential framework. Examples: TLS configuration, UX flows,
  organisational policy.
- **Deferred**: Planned but not in V00.71.00. Tracked against a
  future minor version.
- **Operator-only**: The framework provides no automation; the
  requirement is satisfied by the consuming application or the
  operator's runbook.

## Gaps with planned remediation

| Source | Requirement                                                              | Status   | Target version |
|--------|--------------------------------------------------------------------------|----------|----------------|
| ASVS 2.7 | Out-of-band verifier (SMS / email OTP, hardware token)                  | Deferred | V00.75 (TBD)   |
| ASVS 2.8 | One-time verifier (TOTP / HOTP)                                          | Deferred | V00.75 (TBD)   |
| ASVS 2.9 | Cryptographic verifier (WebAuthn / FIDO2)                                | Deferred | V00.80 (TBD)   |
| NIST 8.1.5 | Verifier impersonation resistance                                       | Deferred | V00.80 (TBD)   |
| Konzept V00.71 §10 | Optional foreign hash import for brownfield migration            | Deferred | V00.71 Prompt 036 (still open) |
| Konzept V00.71 §3 | Password strength estimator implementation (zxcvbn-style)         | Deferred | TBD — no committed version |
| V00.74 Framework Feedback §1 | App-side persistence has no extension slot in `EclipseStoreJSentinelStorage`; consumers run a parallel `EmbeddedStorageManager` with hand-managed lifecycle (or, in current skill scaffolding, fall back to JDK `ObjectOutputStream` on a `.ser` file — the latter is rejected by `serialization-policy.md`) | Deferred | V00.74.20 — Storage-Pair (Option B), see `Konzept-V00.74.20.md` |
| JS-SEC-009 (V00.79.30) | Mixed-algorithm timing side channel — during a lazy KDF migration the anti-enumeration dummy KDF runs the *preferred* algorithm, so a wrong-password attempt against an existing-but-unmigrated user can be timing-distinguishable (leaks "existing & unmigrated"). | Documented (`DefaultPasswordHashingService` JavaDoc) | Backlog — optional per-outcome cost-floor; mitigate with forced-rehash migration |

## Operator-only items

These items are listed in ASVS / NIST but cannot be satisfied
by the framework alone — the consuming application or the
operator is responsible.

| Source | Requirement                                                  |
|--------|--------------------------------------------------------------|
| ASVS 2.2.4 | Phishing resistance (depends on MFA + UX choice)         |
| ASVS 2.2.7 | Intent confirmation for sensitive operations             |
| ASVS 2.5.5 | Recovery uses out-of-band channel (delivery is operator's) |
| ASVS 2.3.2 | Time-limited initial credential (TTL is operator's)      |
| NIST 6.1.2.3 | Enrolment binds credential to verified subject         |
| NIST 8.1.1 | TLS / transport eavesdropping                            |
| NIST 8.1.6 | Phishing / pharming resistance                           |
| ASVS 2.1.10 | No periodic forced rotation (framework does not impose; operator may) |

## Out of scope

These items will not be implemented inside `jSentinel`
regardless of release. The framework is not the right place.

- Audit log retention enforcement (the audit sink decides).
- CAPTCHA selection and integration (UX concern).
- Email / SMS delivery for OTP and reset notifications.
- Identity proofing (NIST SP 800-63A).
- Threat-intel feed integration beyond HIBP-style k-anonymity.

## Documented limitations

Even within scope, V00.71.00 has known limitations:

| Area       | Limitation                                                                 | Mitigation |
|------------|----------------------------------------------------------------------------|------------|
| Pepper     | `InMemoryPepperService` holds keys in heap                                  | HSM-backed implementation via PKCS#11 — see `pkcs11-hsm-pepper-key.md`. |
| Compromise check | `LocalBlocklist` requires operator-maintained list                    | Pair with `jSentinel-credentials-hibp` for breach-corpus check. |
| Rate limiting | `InMemoryAbuseDetectionService` does not survive a JVM restart         | Persist counters via a custom `AbuseDetectionService` impl. |
| Password history | History compares re-derived hashes per attempt; bounded cost via `retainLast`. Since V00.84.00 an entry that cannot be verified — limiter saturated, algorithm retired, pepper key gone — is `PasswordHistoryCheck.Indeterminate`, and `evaluate(...)` rejects the change instead of allowing it (JS-SEC-126) | Tune `retainLast`; disable for low-assurance services. After an algorithm or pepper migration, resolve unverifiable entries; `check(...)` names the reason. |
| HIBP module | Optional; requires outbound HTTPS                                        | Air-gapped deployments use local blocklist only.   |
| Error reporting | `InitialAdminBootstrapService.createInitialAdmin(...)` swallows the underlying `RuntimeException`; same Catch-and-generic-Error pattern is repeated in `RoleAssignmentService`, `PasswordResetTokenService`, `EmailVerificationTokenService`, `RememberMeTokenService` | Reported in V00.74 Framework Feedback §2; lift in V00.74.10 via `Result`-extension with `Throwable cause` + `HasLogger`-discipline WARN log. |
| UI hint surface | `PasswordPolicy` has no length / attribute getter; consumers duplicate the minimum length in UI helper text + server policy | Reported in V00.74 Framework Feedback §3; lift in V00.74.10 via `default OptionalInt minLength()` on `PasswordPolicy`. |

## Tracking

Each gap row that has a target version is mirrored as an entry
in `Konzept-V00.75.00.md` / `Konzept-V00.80.00.md`. When a row
lands in an implementation plan, the corresponding entry here
flips from "Deferred" to "✅" and the row moves into
`traceability-matrix.md`.
