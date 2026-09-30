# Security Policy

## Scope

Shahid is an academic prototype. It is not presented as production-ready security software.

## Reporting a vulnerability

Please do not publish sensitive vulnerability details in a public issue. Contact the repository owner privately through GitHub.

## Security design notes

- Passwords are hashed with Node.js `scrypt`.
- JWT verification is restricted to HS256.
- Production deployments must provide `SHAHID_JWT_SECRET`.
- No biometric image is stored by the current backend.
- Session dashboard access is restricted to the owning professor.
- Risk flags are review signals, not automatic disciplinary decisions.

See the technical report in `docs/` for the project's documented limitations and future work.