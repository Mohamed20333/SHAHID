# Architecture

Shahid separates administrative attendance from independent engagement verification.

## Runtime flow

1. A professor starts a class session.
2. Attendance is recorded through the administrative layer.
3. Independent witness observations and engagement signals feed the smart layer.
4. Risk scoring combines low engagement, suspicious pairing patterns, and missed liveness prompts.
5. Scores at or above `0.60` can create an instructor-review flag, subject to the weekly escalation cap.

## Core components

- `backend/shahid-server.ts` — HTTP API and authorization.
- `backend/shahid-db.ts` — SQLite persistence used for the runnable prototype.
- `backend/shahid-auth.ts` — password hashing and HS256 JWT primitives.
- `backend/shahid-escalation-logic.ts` — quorum, pairing, risk scoring, and escalation logic.
- `frontend/shahid-dashboard-redhat.jsx` — dashboard artifact.
- `database/schema.sql` — PostgreSQL-oriented production schema.

The project explicitly does not claim that voluntary, sustained collusion can be defeated with certainty.