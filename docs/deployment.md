# SHAHID Deployment

## Local
1. Copy .env.example to .env.
2. Set a strong POSTGRES_PASSWORD and SHAHID_JWT_SECRET.
3. Run docker compose up --build.
4. API: http://localhost:8080
5. Web: http://localhost:8081

The API container uses PostgreSQL and Redis. The legacy SQLite server remains available for deterministic tests/demo workflows.

## Production
- Put the API behind TLS termination.
- Use a managed PostgreSQL service.
- Use managed Redis or a secured Redis deployment.
- Restrict database/network exposure to private networks.
- Store secrets in a secret manager.
- Set an explicit allowed-origin list.
- Configure log/metric shipping.
- Configure evidence retention before collecting real student data.

## Android
Build with:
gradle -p mobile :app:assembleDebug

The Android app requests Nearby Devices permissions and starts evidence collection from a visible user action. Android platform background restrictions remain authoritative.

## Pilot test
After the API is running and migrations have completed, an isolated demo dataset can be created explicitly:

```bash
ALLOW_DEMO_SEED=true SHAHID_SEED_PASSWORD='use-a-12+-char-demo-password' npm run seed:pilot
```

This creates one pilot professor, three pilot students, one course/section, and an active session. Do not run the demo seed against a real university database.

For physical Android devices, set the app API URL to the server's LAN address (for example `http://192.168.x.x:8080`) and ensure the pilot VLAN/firewall permits that connection. The emulator default `10.0.2.2` points back to the development host.

## End-to-end test
1. Sign in as a pilot student on two or more Android devices.
2. Each device enrolls its Ed25519 identity once.
3. The student device performs a server-challenged cryptographic check-in.
4. The device receives a session-scoped ephemeral BLE identifier and advertises it.
5. Nearby student devices scan the SHAHID BLE service, request a server witness challenge, sign the observation, and upload it over HTTPS/API transport.
6. The backend resolves the ephemeral identifier inside the session scope, verifies the witness signature, prevents challenge replay, and stores the observation.
7. The foreground evidence service sends signed continuity heartbeats.
8. A professor can inspect the session overview and trigger the explainable risk assessment endpoint.
