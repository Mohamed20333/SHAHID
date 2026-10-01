# Pilot test plan

## Automated

Run:

`npm run typecheck`
`npm test`
`npm run db:migrate`
`npm audit --audit-level=high`

Build:

- frontend;
- Android;
- iOS on macOS;
- Docker API/web images.

## Physical

Use:

- Android Student A
- Android Student B
- iPhone Student A
- iPhone Student B
- Professor laptop

Validate:

1. Android → Android BLE.
2. Android → iPhone BLE.
3. iPhone → Android BLE.
4. iPhone → iPhone BLE.
5. Enrollment.
6. Cryptographic check-in.
7. Witness challenge/signature.
8. Heartbeat.
9. Evidence graph.
10. Risk assessment.
11. Session end.

Failure tests:

- Bluetooth disabled;
- permission denied;
- network loss;
- revoked device;
- expired challenge;
- replayed challenge;
- duplicate witness;
- wrong session;
- wrong student;
- forged signature.

Do not mark a physical test PASS unless it was actually run on the corresponding hardware.
