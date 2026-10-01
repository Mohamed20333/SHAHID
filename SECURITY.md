# Security Policy

## Scope

SHAHID is an academic prototype. It is not presented as production-ready security software.

## Reporting a vulnerability

Please do not publish sensitive vulnerability details in a public issue. Contact the repository owner privately through GitHub.

When reporting a vulnerability, include:

- affected endpoint/file
- reproduction steps or a minimal proof of concept
- expected versus actual security behavior
- impact
- suggested remediation, if known

Do not include real credentials, student records, or other private data.

## Current security controls

- Passwords are protected with salted, memory-hard scrypt.
- Public registration is restricted to the student role.
- Access JWTs are short-lived and validate algorithm, type, issuer, audience, expiry, issue time, and token ID.
- Refresh tokens are opaque, hashed at rest, rotated, and revocable.
- Refresh-token replay triggers family revocation.
- Session dashboards enforce instructor ownership.
- Witness observer devices must belong to the authenticated account.
- Risk calculations use server-owned evidence rather than client-supplied risk inputs.
- JSON request bodies are size-limited.
- Authentication endpoints are rate-limited.
- CORS is origin allowlisted.
- Sensitive responses are not cacheable.
- Client errors do not expose database or stack details.
- CI includes adversarial regression tests, dependency auditing, and CodeQL.

## Known limitations

The current device enrollment mechanism is a hashed client-provided enrollment identifier. It is deliberately not described as hardware-backed attestation.

Production mobile clients should add:

1. hardware-backed asymmetric device keys where supported;
2. server challenge-response proof of key possession;
3. signed, freshness-bound witness observations;
4. replay protection and clock/epoch validation;
5. MFA and secure account recovery;
6. centralized, tamper-evident audit logging;
7. distributed rate limiting;
8. PostgreSQL runtime migrations and production deployment controls.

RSSI measurements are environmental signals and must not be treated as cryptographic proof of physical proximity.

Risk flags are review signals, not automatic disciplinary decisions.

See [docs/security/threat-model.md](docs/security/threat-model.md).
