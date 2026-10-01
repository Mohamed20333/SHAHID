# SHAHID Security Threat Model

## Security objective

SHAHID must make attendance evidence harder to forge without turning a probabilistic signal into an automatic disciplinary verdict.

The primary trust boundary is:

> **The client is untrusted. Evidence used for an attendance or risk decision must be derived or verified by the server.**

## Assets

- Account credentials and authentication tokens
- Student/device identity bindings
- Attendance records
- Witness observations
- Engagement and liveness metadata
- Risk assessments and explanations
- Instructor dashboards
- Audit/security events
- Database credentials and JWT signing secret

## Threat actors

| Actor | Capability | Goal |
|---|---|---|
| Unauthenticated attacker | Internet/API access | Account abuse, DoS |
| Student | Valid student account | Forge attendance or manipulate risk evidence |
| Compromised student | Valid credentials + device | Impersonation / replay |
| Malicious instructor | Valid instructor account | Access another instructor's session data |
| Database attacker | Database read/write | Tamper with evidence |
| Network attacker | Can observe/modify insecure transport | Credential/token theft |

## STRIDE analysis

| Threat | Example | Primary control |
|---|---|---|
| Spoofing | Student claims another device as observer | Server verifies X-Device-ID belongs to authenticated user |
| Tampering | Client submits a fake risk score/pair history | Risk engine reads server-owned evidence only |
| Repudiation | User disputes who created an observation | Audit trail + immutable event design |
| Information disclosure | Professor reads another professor's session | Session-owner authorization |
| Denial of service | Oversized JSON request | 64 KiB body limit + rate limiting |
| Elevation of privilege | Public registration requests platform_admin | Public registration is student-only |

## Authentication model

- Passwords are salted and hashed with memory-hard scrypt.
- Access JWTs are short-lived and validate algorithm, type, issuer, audience, expiry, issue time, and ID.
- Refresh credentials are opaque random values.
- Only refresh-token hashes are stored.
- Refresh tokens rotate on every successful refresh.
- Reuse of a revoked refresh token revokes its token family.

## Evidence model

Current prototype evidence is intentionally metadata-only:

1. Device enrollment identifier is hashed before persistence.
2. Observer identity is derived from the authenticated account's owned device.
3. Witness observations are validated against active sessions and known devices.
4. Risk calculation loads engagement, liveness, witness, and pair statistics from server-side persistence.
5. Client-supplied risk inputs are ignored.

### Important limitation

A client-supplied enrollment identifier is **not hardware-backed attestation**. A production mobile implementation should replace it with a hardware-backed key and challenge-response proof (for example, platform attestation where available).

Likewise, RSSI is an environmental radio measurement, not proof of physical identity. A production anti-collusion design should use signed, freshness-bound device observations and replay protection.

## Residual risks

- A compromised legitimate device can still produce valid observations.
- BLE/RSSI observations can be manipulated or relayed.
- A malicious participant can collude with other participants.
- Availability controls are process-local in the prototype and should move to a distributed limiter such as Redis in a horizontally scaled deployment.
- MFA, account recovery, key rotation, and centralized audit-log shipping remain production hardening work.

## Security testing strategy

Every trust-boundary change should have an adversarial regression test for:

- privilege escalation
- IDOR/BOLA
- device spoofing
- token confusion
- refresh-token replay
- forged risk evidence
- oversized request bodies
- CORS origin abuse
- malformed authentication material
- cross-instructor data access

## Decision rule

A risk score is an investigation signal. It must never be treated as proof of misconduct by itself.
