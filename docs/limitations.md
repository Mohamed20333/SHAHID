# Limitations

SHAHID is an attendance-integrity evidence system, not a mathematical proof of physical presence.

Known platform/environment limitations:

- RSSI is noisy radio evidence.
- BLE does not prove a specific physical location.
- iOS background BLE execution is constrained by Apple's platform behavior.
- Hardware-backed attestation is not universally guaranteed by the reference clients.
- Risk scoring is explainable and deterministic; it is not a validated ML model.
- Physical Android/iOS interoperability requires real-device testing.
- Production deployment requires HTTPS, secret management, managed PostgreSQL/Redis, backups, monitoring and institutional privacy/legal review.
- No biometric liveness claim is made.

Any environment-dependent item must remain explicitly labeled as such until tested.
