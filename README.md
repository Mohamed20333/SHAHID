# SHAHID — Attendance Integrity & Evidence Platform

SHAHID is an evidence-first university attendance-integrity platform. It combines authenticated attendance, cryptographic device proof, session-scoped BLE proximity observations, signed witnesses, continuity heartbeats, an explainable risk engine, and professor/admin control surfaces.

## Current system

- **Android student app:** native Kotlin workflow for login, device enrollment, cryptographic check-in, BLE advertising/scanning, signed witnesses and heartbeats.
- **iOS/iPhone student app:** native SwiftUI/CoreBluetooth workflow with Keychain-backed Ed25519 identity, enrollment, check-in and BLE evidence.
- **Professor web control center:** live session monitoring, attendance/evidence states and session-scoped evidence graph.
- **Admin/security control center:** scoped user, device, session, risk and audit visibility.
- **Backend:** PostgreSQL + Redis capable production-oriented API with authentication, RBAC, challenge-response, evidence verification and audit logging.
- **Security:** scrypt passwords, short-lived access JWTs, rotating opaque refresh tokens, explicit CORS, request limits, replay protection and CodeQL/automated regression tests.
- **Deployment:** Docker Compose for PostgreSQL, Redis, API and web, with configurable LAN binding for a trusted pilot network.
- **Documentation:** architecture, deployment, privacy, threat model, mobile and pilot guidance.

## Evidence model

```
Student device
   │
   ├── cryptographic check-in
   │
   └── session-scoped BLE ephemeral identifier
             │
             ▼
      Nearby participant
             │
             ├── RSSI observation
             ├── server witness challenge
             └── Ed25519 signature
                       │
                       ▼
                 Evidence store
                       │
                 ┌─────┴─────┐
                 ▼           ▼
            Evidence       Risk
              Graph       Assessment
```

BLE is **not** treated as proof of physical presence. Cryptographic signatures prove control of an enrolled key; BLE provides environmental proximity evidence; the risk engine evaluates the evidence and can require human review.

## Run locally

```bash
npm install
cp .env.example .env
npm run typecheck
npm test
```

For the PostgreSQL/Redis stack:

```bash
docker compose up -d
npm run db:migrate
```

For an isolated pilot dataset:

```bash
ALLOW_DEMO_SEED=true SHAHID_SEED_PASSWORD='use-a-local-password-12+' npm run seed:pilot
```

Never use pilot credentials or demo seed data in a real university deployment.

## LAN pilot

For physical phones on the same trusted network:

1. Set `SHAHID_BIND_HOST=0.0.0.0`.
2. Set `SHAHID_ALLOWED_ORIGINS` to the exact web origin you will use.
3. Start Compose.
4. Use the host machine's LAN IP as the API URL in the Android/iOS app.
5. For production use HTTPS and a proper certificate/reverse proxy. Plain HTTP is only a development-network experiment and may be restricted by mobile platform security policies.

The API is intentionally configurable rather than permanently exposed to every network.

## Professor workflow

`Sign in → select/create session → start → monitor live attendance → inspect evidence → review risk → end session → export/report`.

The professor UI distinguishes:

- cryptographic check-in
- BLE observation
- witness verification
- evidence freshness
- risk assessment

It does not display a misleading "guaranteed physical presence" verdict.

## iOS

Open `ios/SHAHID.xcodeproj` with Xcode. The target uses SwiftUI, CoreBluetooth, CryptoKit and Keychain. A physical iPhone is required for real BLE validation.

iOS background execution is platform-controlled. SHAHID therefore does not claim unrestricted continuous BLE collection. The repository must be physically tested before any deployment claim about background continuity.

## Testing

CI validates backend typecheck/tests, PostgreSQL migrations, frontend build, dependency audit, Docker images, CodeQL, Android compilation, and an unsigned iOS simulator build on a macOS runner.

Physical BLE tests remain device/environment dependent and are explicitly reported as not executed unless real phones are available.

## Security truthfulness

SHAHID does not claim to:

- eliminate cheating with certainty;
- mathematically prove physical presence from BLE;
- provide hardware attestation unless a hardware-backed implementation is actually configured;
- provide biometric liveness unless biometric verification is actually implemented.

See `SECURITY.md`, `docs/security/threat-model.md`, `docs/limitations.md`, and `docs/pilot-test.md`.

## License

MIT.
