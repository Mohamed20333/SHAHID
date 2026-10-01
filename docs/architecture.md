# SHAHID Architecture

SHAHID has two persistence/runtime paths:

- backend/shahid-server.ts: deterministic SQLite prototype/test server.
- backend/shahid-prod-server.ts: PostgreSQL + Redis production-oriented API.

Production trust boundary:

Android/Browser -> HTTPS API -> authentication/authorization -> PostgreSQL evidence store.

Device identity uses Ed25519 signatures. A challenge is bound to user, device/key, purpose and optionally session. Signed witness observations bind session, observer, observed device, timestamp, nonce and proximity metadata.

The production API separates authentication, authorization, device identity, attendance, evidence and audit concerns at the route/service boundary. PostgreSQL enforces relational ownership and replay constraints; Redis provides distributed rate-limit state when configured.

BLE is a noisy proximity signal. It is never treated as proof of physical human presence. Android background execution remains platform-controlled.
