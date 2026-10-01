# SHAHID — Attendance Verification & Academic-Integrity Intelligence

> CN3030 Term Project · University of East London · Red Hat Edition

SHAHID is an academic prototype designed around one practical question:

**How can an attendance system make proxy attendance visible without pretending that manual attendance itself is unforgeable?**

The design keeps attendance as an administrative signal and adds an independent smart layer based on engagement and behavioural evidence. A risk flag is a signal for instructor review — **not an automatic penalty or verdict**.

## Security posture

SHAHID treats the client as untrusted. Security-sensitive decisions are based on server-owned evidence rather than client-supplied risk values.

### Hardened controls

- Public registration creates students only; privileged roles cannot be self-assigned.
- Passwords use salted, memory-hard scrypt with an explicit work factor.
- Access JWTs are short-lived and validate algorithm, token type, issuer, audience, expiry, issue time, and token ID.
- Refresh credentials are opaque random tokens stored only as SHA-256 hashes.
- Refresh tokens rotate on use; replay of a revoked token revokes the token family.
- Witness submissions cannot nominate an arbitrary observer device; the observer must belong to the authenticated account.
- Risk calculation loads evidence from server-side persistence and ignores forged client-side evidence.
- JSON request bodies are capped at 64 KiB.
- Authentication has stricter rate limiting.
- CORS uses an explicit origin allowlist rather than a wildcard.
- Sensitive responses use no-store caching and generic client-facing errors.
- CI performs type checking, adversarial regression tests, dependency auditing, and CodeQL analysis.

### Security limitations that are intentionally not hidden

The current device enrollment value is hashed, but it is not hardware-backed attestation. Production mobile integration should use hardware-backed keys and challenge-response proof. RSSI is also an environmental radio measurement, not cryptographic proof of physical proximity.

See [docs/security/threat-model.md](docs/security/threat-model.md) for the threat model, trust boundaries, residual risks, and security test strategy.

## Project contents

```text
SHAHID/
├── backend/
│   ├── shahid-server.ts
│   ├── shahid-auth.ts
│   ├── shahid-db.ts
│   ├── shahid-escalation-logic.ts
│   ├── shahid-server.test.ts
│   └── shahid-demo.ts
├── frontend/
│   └── shahid-dashboard-redhat.jsx
├── database/
│   └── schema.sql
├── docs/
│   ├── architecture.md
│   ├── shahid-presentation-2.pptx
│   └── shahid-technical-report.docx
├── .github/workflows/ci.yml
├── .env.example
├── docker-compose.yml
├── package.json
├── tsconfig.json
├── SECURITY.md
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

## Key design decision

The project considered automatic capture (QR, ID/RFID, face recognition) versus manual attendance plus smart analytics. The selected design deliberately avoids making biometrics the default path and instead evaluates independent engagement signals.

The technical report documents the trade-off and limitations in detail.

## Risk model

The implemented weights are:

| Signal | Weight |
|---|---:|
| Low engagement despite marked present | +0.35 |
| Statistically suspicious pairing | +0.40 |
| Missed randomized live-check prompt | +0.25 |
| Escalation threshold | 0.60 |

Escalations are rate-limited to at most one per student per rolling week.

## Requirements

- Node.js 22+
- npm
- Docker Desktop / Docker Engine (optional, for PostgreSQL)

## Local setup

```bash
git clone https://github.com/YOUR_USERNAME/SHAHID.git
cd SHAHID
npm install
cp .env.example .env
```

Set a local `SHAHID_JWT_SECRET` in `.env`.

### Run the automated suite

```bash
npm test
```

The suite starts the real HTTP server against an in-memory SQLite database and verifies authentication, authorization, attendance logic, risk escalation, weekly caps, and JWT integrity.

### Typecheck + test

```bash
npm run check
```

### Run the logic demonstration

```bash
npm run demo
```

### Run the server

```bash
npm start
```

By default the server listens on port `3000`.

For persistent local SQLite storage:

```bash
SHAHID_DB_PATH=./data/shahid.db npm start
```

## PostgreSQL development database

The supplied Compose configuration initializes the PostgreSQL schema:

```bash
docker compose up -d
```

The application prototype currently uses Node's built-in SQLite implementation for its runnable local test path. PostgreSQL is the intended production persistence target.

## Security notes

- Do not commit `.env` or database files.
- Production must set `SHAHID_JWT_SECRET`.
- Passwords use `scrypt`.
- JWT verification is HS256-only.
- Professor dashboards enforce ownership authorization.
- The prototype does not store biometric images.
- Risk flags are for human review and are not automatic disciplinary decisions.

See [`SECURITY.md`](SECURITY.md) and the technical report in `docs/`.

## Honest limitations

This is a term-project prototype, not a production attendance platform. It does not claim to eliminate fully voluntary, sustained collusion with certainty. Hardware/BLE integration, a native mobile client, production deployment, load/chaos testing, and migration to the production PostgreSQL schema remain future work.

## Academic material

The presentation and technical report supplied with the project are preserved under `docs/` for reproducibility and assessment context.

## License

MIT — see `LICENSE`.
