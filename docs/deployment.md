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
