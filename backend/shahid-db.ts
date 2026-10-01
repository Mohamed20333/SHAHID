/**
 * SHAHID — Persistence layer.
 *
 * SQLite is retained as the deterministic local/test backend. The schema is
 * intentionally aligned with the security invariants used by the HTTP layer.
 * Production PostgreSQL migrations must preserve these constraints.
 */
import { DatabaseSync } from "node:sqlite";
import { randomUUID } from "node:crypto";

let db: DatabaseSync | null = null;

export function getDb(path: string = ":memory:"): DatabaseSync {
  if (db) return db;
  db = new DatabaseSync(path);
  db.exec("PRAGMA foreign_keys = ON;");
  migrate(db);
  return db;
}

export function closeDb(): void {
  db?.close();
  db = null;
}

function migrate(database: DatabaseSync): void {
  database.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      role TEXT NOT NULL CHECK (role IN ('student','professor','dept_admin','university_admin','platform_admin')),
      full_name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      device_enrollment_key_hash TEXT NOT NULL UNIQUE,
      enrolled_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS class_sessions (
      id TEXT PRIMARY KEY,
      instructor_id TEXT NOT NULL REFERENCES users(id),
      started_at TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('scheduled','active','closed','compliance_degraded'))
    );

    CREATE TABLE IF NOT EXISTS witness_observations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL REFERENCES class_sessions(id) ON DELETE CASCADE,
      observer_device_id TEXT NOT NULL REFERENCES devices(id),
      observed_device_id TEXT NOT NULL REFERENCES devices(id),
      rssi INTEGER NOT NULL CHECK (rssi BETWEEN -127 AND 0),
      observed_at TEXT NOT NULL,
      CHECK (observer_device_id <> observed_device_id)
    );

    CREATE TABLE IF NOT EXISTS pair_stats (
      device_a_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      device_b_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      sessions_observed INTEGER NOT NULL DEFAULT 0,
      co_occurrence_rate REAL NOT NULL DEFAULT 0 CHECK (co_occurrence_rate BETWEEN 0 AND 1),
      variance_score REAL NOT NULL DEFAULT 1 CHECK (variance_score BETWEEN 0 AND 1),
      PRIMARY KEY (device_a_id, device_b_id)
    );

    CREATE TABLE IF NOT EXISTS session_engagement_scores (
      student_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      session_id TEXT NOT NULL REFERENCES class_sessions(id) ON DELETE CASCADE,
      score REAL NOT NULL CHECK (score BETWEEN 0 AND 1),
      recorded_at TEXT NOT NULL,
      PRIMARY KEY (student_id, session_id)
    );

    CREATE TABLE IF NOT EXISTS liveness_events (
      id TEXT PRIMARY KEY,
      student_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      session_id TEXT NOT NULL REFERENCES class_sessions(id) ON DELETE CASCADE,
      sent_at TEXT NOT NULL,
      answered_at TEXT,
      passed INTEGER NOT NULL DEFAULT 0 CHECK (passed IN (0,1)),
      UNIQUE(student_id, session_id)
    );

    CREATE TABLE IF NOT EXISTS risk_assessments (
      id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL REFERENCES class_sessions(id) ON DELETE CASCADE,
      student_id TEXT NOT NULL REFERENCES users(id),
      risk_score REAL NOT NULL CHECK (risk_score BETWEEN 0 AND 1),
      reasons_json TEXT NOT NULL,
      computed_at TEXT NOT NULL,
      UNIQUE (session_id, student_id)
    );

    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      family_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      revoked_at TEXT,
      replaced_by TEXT REFERENCES refresh_tokens(id)
    );

    CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
    CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id);
    CREATE INDEX IF NOT EXISTS idx_witness_session_observed ON witness_observations(session_id, observed_device_id);

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_id TEXT,
      reason_code TEXT,
      metadata_json TEXT NOT NULL DEFAULT '{}',
      occurred_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id, occurred_at);
    CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target_type, target_id);

    CREATE TABLE IF NOT EXISTS device_challenges (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      public_key TEXT NOT NULL,
      key_id TEXT NOT NULL,
      purpose TEXT NOT NULL,
      session_id TEXT REFERENCES class_sessions(id) ON DELETE CASCADE,
      nonce TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      consumed_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_device_challenges_user ON device_challenges(user_id, expires_at);

    CREATE TABLE IF NOT EXISTS device_crypto (
      device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
      public_key TEXT NOT NULL,
      key_id TEXT NOT NULL UNIQUE,
      algorithm TEXT NOT NULL DEFAULT 'Ed25519',
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
      updated_at TEXT NOT NULL
    );
  `);
}

export function createDeviceChallenge(database: DatabaseSync, params: {
  userId: string; publicKey: string; keyId: string; purpose: string; sessionId?: string | null;
}): { id: string; nonce: string; expiresAt: string } {
  const id = randomUUID();
  const nonce = randomUUID().replaceAll("-", "") + randomUUID().replaceAll("-", "");
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + 2 * 60 * 1000);
  database.prepare(`
    INSERT INTO device_challenges
      (id,user_id,public_key,key_id,purpose,session_id,nonce,created_at,expires_at)
    VALUES (?,?,?,?,?,?,?,?,?)
  `).run(id, params.userId, params.publicKey, params.keyId, params.purpose, params.sessionId ?? null,
    nonce, createdAt.toISOString(), expiresAt.toISOString());
  return { id, nonce, expiresAt: expiresAt.toISOString() };
}

export function getDeviceChallenge(database: DatabaseSync, id: string) {
  return database.prepare("SELECT * FROM device_challenges WHERE id = ?").get(id) as any;
}

export function consumeDeviceChallenge(database: DatabaseSync, id: string): boolean {
  const result = database.prepare("UPDATE device_challenges SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL")
    .run(new Date().toISOString(), id);
  return Number(result.changes) === 1;
}

export function enrollCryptographicDevice(database: DatabaseSync, params: {
  userId: string; publicKey: string; keyId: string;
}): string {
  const existing = database.prepare("SELECT device_id FROM device_crypto WHERE key_id = ?").get(params.keyId) as {device_id:string}|undefined;
  if (existing) {
    const owner = getDevice(database, existing.device_id);
    if (!owner || owner.user_id !== params.userId) throw new Error("device_key_already_owned");
    return existing.device_id;
  }
  const deviceId = randomUUID();
  const now = new Date().toISOString();
  database.prepare(`
    INSERT INTO devices (id,user_id,device_enrollment_key_hash,enrolled_at)
    VALUES (?,?,?,?)
  `).run(deviceId, params.userId, randomUUID(), now);
  database.prepare(`
    INSERT INTO device_crypto (device_id,public_key,key_id,algorithm,status,updated_at)
    VALUES (?,?,?,?,?,?)
  `).run(deviceId, params.publicKey, params.keyId, "Ed25519", "active", now);
  return deviceId;
}

export function getCryptoDevice(database: DatabaseSync, deviceId: string) {
  return database.prepare(`
    SELECT d.id,d.user_id,d.enrolled_at,c.public_key,c.key_id,c.algorithm,c.status
    FROM devices d JOIN device_crypto c ON c.device_id=d.id
    WHERE d.id=?
  `).get(deviceId) as any;
}

export function revokeCryptoDevice(database: DatabaseSync, deviceId: string): void {
  database.prepare("UPDATE device_crypto SET status='revoked', updated_at=? WHERE device_id=?")
    .run(new Date().toISOString(), deviceId);
}

export interface UserRow {
  id: string; role: string; full_name: string; email: string; password_hash: string; created_at: string;
}

export function writeAuditLog(
  database: DatabaseSync,
  params: {
    actorId?: string | null;
    action: string;
    targetType: string;
    targetId?: string | null;
    reasonCode?: string | null;
    metadata?: Record<string, unknown>;
  },
): void {
  database.prepare(`
    INSERT INTO audit_log
      (actor_id, action, target_type, target_id, reason_code, metadata_json, occurred_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    params.actorId ?? null,
    params.action,
    params.targetType,
    params.targetId ?? null,
    params.reasonCode ?? null,
    JSON.stringify(params.metadata ?? {}),
    new Date().toISOString(),
  );
}

export function insertUser(database: DatabaseSync, params: { role: string; fullName: string; email: string; passwordHash: string }): UserRow {
  const id = randomUUID();
  const createdAt = new Date().toISOString();
  database.prepare(`
    INSERT INTO users (id, role, full_name, email, password_hash, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, params.role, params.fullName.trim(), params.email.trim().toLowerCase(), params.passwordHash, createdAt);
  return { id, role: params.role, full_name: params.fullName.trim(), email: params.email.trim().toLowerCase(), password_hash: params.passwordHash, created_at: createdAt };
}

export function findUserByEmail(database: DatabaseSync, email: string): UserRow | undefined {
  return database.prepare("SELECT * FROM users WHERE email = ?").get(email.trim().toLowerCase()) as UserRow | undefined;
}

export function findUserById(database: DatabaseSync, id: string): UserRow | undefined {
  return database.prepare("SELECT * FROM users WHERE id = ?").get(id) as UserRow | undefined;
}

export function insertSession(database: DatabaseSync, instructorId: string): { id: string; started_at: string } {
  const id = randomUUID();
  const startedAt = new Date().toISOString();
  database.prepare(`
    INSERT INTO class_sessions (id, instructor_id, started_at, status)
    VALUES (?, ?, ?, 'active')
  `).run(id, instructorId, startedAt);
  return { id, started_at: startedAt };
}

export function getSessionById(database: DatabaseSync, sessionId: string): { id: string; instructor_id: string; started_at: string; status: string } | undefined {
  return database.prepare("SELECT id, instructor_id, started_at, status FROM class_sessions WHERE id = ?").get(sessionId) as any;
}

export function insertWitnessObservation(database: DatabaseSync, params: { sessionId: string; observerDeviceId: string; observedDeviceId: string; rssi: number }): void {
  database.prepare(`
    INSERT INTO witness_observations
      (session_id, observer_device_id, observed_device_id, rssi, observed_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(params.sessionId, params.observerDeviceId, params.observedDeviceId, params.rssi, new Date().toISOString());
}

export function countIndependentWitnesses(database: DatabaseSync, sessionId: string, observedDeviceId: string): number {
  const row = database.prepare(`
    SELECT COUNT(DISTINCT observer.user_id) AS cnt
    FROM witness_observations w
    JOIN devices observer ON observer.id = w.observer_device_id
    JOIN devices observed ON observed.id = w.observed_device_id
    WHERE w.session_id = ?
      AND w.observed_device_id = ?
      AND observer.user_id <> observed.user_id
  `).get(sessionId, observedDeviceId) as { cnt: number };
  return row.cnt;
}

export function getDevice(database: DatabaseSync, deviceId: string): { id: string; user_id: string; device_enrollment_key_hash: string } | undefined {
  return database.prepare("SELECT id, user_id, device_enrollment_key_hash FROM devices WHERE id = ?").get(deviceId) as any;
}

export function getUserDevice(database: DatabaseSync, userId: string, deviceId: string): { id: string; user_id: string } | undefined {
  return database.prepare("SELECT id, user_id FROM devices WHERE id = ? AND user_id = ?").get(deviceId, userId) as any;
}

export function getUserDevices(database: DatabaseSync, userId: string): Array<{ id: string; user_id: string }> {
  return database.prepare("SELECT id, user_id FROM devices WHERE user_id = ? ORDER BY enrolled_at ASC").all(userId) as any;
}

export function ensureDevice(database: DatabaseSync, userId: string, deviceEnrollmentKeyHash: string): string {
  const existing = database.prepare("SELECT id, user_id FROM devices WHERE device_enrollment_key_hash = ?").get(deviceEnrollmentKeyHash) as { id: string; user_id: string } | undefined;
  if (existing) {
    if (existing.user_id !== userId) throw new Error("device_enrollment_already_owned");
    return existing.id;
  }
  const id = randomUUID();
  database.prepare(`
    INSERT INTO devices (id, user_id, device_enrollment_key_hash, enrolled_at)
    VALUES (?, ?, ?, ?)
  `).run(id, userId, deviceEnrollmentKeyHash, new Date().toISOString());
  return id;
}

export function upsertRiskAssessment(database: DatabaseSync, params: { sessionId: string; studentId: string; riskScore: number; reasons: string[] }): void {
  const id = randomUUID();
  database.prepare(`
    INSERT INTO risk_assessments (id, session_id, student_id, risk_score, reasons_json, computed_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(session_id, student_id) DO UPDATE SET
      risk_score = excluded.risk_score,
      reasons_json = excluded.reasons_json,
      computed_at = excluded.computed_at
  `).run(id, params.sessionId, params.studentId, params.riskScore, JSON.stringify(params.reasons), new Date().toISOString());
}

export interface SessionDeviceWitnessCount { observed_device_id: string; witness_count: number; }

export function getSessionWitnessSummary(database: DatabaseSync, sessionId: string): SessionDeviceWitnessCount[] {
  return database.prepare(`
    SELECT observed_device_id, COUNT(DISTINCT observer_device_id) AS witness_count
    FROM witness_observations
    WHERE session_id = ?
    GROUP BY observed_device_id
  `).all(sessionId) as unknown as SessionDeviceWitnessCount[];
}

export interface RiskAssessmentRow { student_id: string; risk_score: number; reasons_json: string; computed_at: string; }

export function getSessionRiskAssessments(database: DatabaseSync, sessionId: string): RiskAssessmentRow[] {
  return database.prepare("SELECT student_id, risk_score, reasons_json, computed_at FROM risk_assessments WHERE session_id = ?").all(sessionId) as unknown as RiskAssessmentRow[];
}

export function getPairStatsForDevice(database: DatabaseSync, deviceId: string): Array<{
  deviceA: string; deviceB: string; coOccurrenceRate: number; varianceScore: number; sessionsObserved: number;
}> {
  return database.prepare(`
    SELECT device_a_id AS deviceA, device_b_id AS deviceB,
           co_occurrence_rate AS coOccurrenceRate,
           variance_score AS varianceScore,
           sessions_observed AS sessionsObserved
    FROM pair_stats
    WHERE device_a_id = ? OR device_b_id = ?
  `).all(deviceId, deviceId) as any;
}

export function getEngagementScore(database: DatabaseSync, studentId: string, sessionId: string): number | null {
  const row = database.prepare("SELECT score FROM session_engagement_scores WHERE student_id = ? AND session_id = ?").get(studentId, sessionId) as { score: number } | undefined;
  return row?.score ?? null;
}

export function countRecentRiskAssessments(database: DatabaseSync, studentId: string, sinceIso: string): number {
  const row = database.prepare("SELECT COUNT(*) AS cnt FROM risk_assessments WHERE student_id = ? AND computed_at >= ?").get(studentId, sinceIso) as { cnt: number };
  return row.cnt;
}

export function getLivenessEvent(database: DatabaseSync, studentId: string, sessionId: string): { sentAt: string; answeredAt: string | null; passed: boolean } | null {
  const row = database.prepare("SELECT sent_at, answered_at, passed FROM liveness_events WHERE student_id = ? AND session_id = ?").get(studentId, sessionId) as { sent_at: string; answered_at: string | null; passed: number } | undefined;
  return row ? { sentAt: row.sent_at, answeredAt: row.answered_at, passed: row.passed === 1 } : null;
}

export function createRefreshTokenRecord(database: DatabaseSync, userId: string, tokenHash: string, expiresAt: string, familyId = randomUUID()): { id: string; familyId: string } {
  const id = randomUUID();
  database.prepare(`
    INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, userId, tokenHash, familyId, new Date().toISOString(), expiresAt);
  return { id, familyId };
}

export function getRefreshToken(database: DatabaseSync, tokenHash: string): {
  id: string; user_id: string; family_id: string; expires_at: string; revoked_at: string | null;
} | undefined {
  return database.prepare(`
    SELECT id, user_id, family_id, expires_at, revoked_at
    FROM refresh_tokens WHERE token_hash = ?
  `).get(tokenHash) as any;
}

export function rotateRefreshToken(database: DatabaseSync, oldId: string, newHash: string, userId: string, familyId: string, expiresAt: string): string {
  const newId = randomUUID();
  const now = new Date().toISOString();
  database.exec("BEGIN IMMEDIATE");
  try {
    const old = database.prepare("SELECT id, revoked_at FROM refresh_tokens WHERE id = ?").get(oldId) as { id: string; revoked_at: string | null } | undefined;
    if (!old || old.revoked_at) {
      database.exec("ROLLBACK");
      throw new Error("refresh_token_reuse");
    }
    database.prepare(`
      INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(newId, userId, newHash, familyId, now, expiresAt);
    database.prepare("UPDATE refresh_tokens SET revoked_at = ?, replaced_by = ? WHERE id = ? AND revoked_at IS NULL").run(now, newId, oldId);
    database.exec("COMMIT");
    return newId;
  } catch (error) {
    try { database.exec("ROLLBACK"); } catch {}
    throw error;
  }
}

export function revokeRefreshToken(database: DatabaseSync, tokenHash: string): void {
  database.prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL").run(new Date().toISOString(), tokenHash);
}

export function revokeRefreshFamily(database: DatabaseSync, familyId: string): void {
  database.prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL").run(new Date().toISOString(), familyId);
}
