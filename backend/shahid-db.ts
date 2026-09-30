/**
 * Shahid — Persistence layer (SQLite stand-in for this sandbox)
 */

import { DatabaseSync } from "node:sqlite";
import { randomUUID } from "node:crypto";

let db: DatabaseSync | null = null;

export function getDb(path: string = ":memory:"): DatabaseSync {
  if (db) return db;
  db = new DatabaseSync(path);
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
      hardware_attestation_id TEXT NOT NULL UNIQUE,
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
      session_id TEXT NOT NULL REFERENCES class_sessions(id),
      observer_device_id TEXT NOT NULL REFERENCES devices(id),
      observed_device_id TEXT NOT NULL REFERENCES devices(id),
      rssi INTEGER NOT NULL,
      observed_at TEXT NOT NULL,
      CHECK (observer_device_id <> observed_device_id)
    );

    CREATE TABLE IF NOT EXISTS pair_stats (
      device_a_id TEXT NOT NULL,
      device_b_id TEXT NOT NULL,
      sessions_observed INTEGER NOT NULL DEFAULT 0,
      co_occurrence_rate REAL NOT NULL DEFAULT 0,
      variance_score REAL NOT NULL DEFAULT 1,
      PRIMARY KEY (device_a_id, device_b_id)
    );

    CREATE TABLE IF NOT EXISTS risk_assessments (
      id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL REFERENCES class_sessions(id),
      student_id TEXT NOT NULL REFERENCES users(id),
      risk_score REAL NOT NULL,
      reasons_json TEXT NOT NULL,
      computed_at TEXT NOT NULL,
      UNIQUE (session_id, student_id)
    );
  `);
}

export interface UserRow {
  id: string; role: string; full_name: string; email: string; password_hash: string; created_at: string;
}

export function insertUser(database: DatabaseSync, params: { role: string; fullName: string; email: string; passwordHash: string }): UserRow {
  const id = randomUUID();
  const createdAt = new Date().toISOString();
  database.prepare(`INSERT INTO users (id, role, full_name, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)`).run(id, params.role, params.fullName, params.email, params.passwordHash, createdAt);
  return { id, role: params.role, full_name: params.fullName, email: params.email, password_hash: params.passwordHash, created_at: createdAt };
}

export function findUserByEmail(database: DatabaseSync, email: string): UserRow | undefined {
  return database.prepare(`SELECT * FROM users WHERE email = ?`).get(email) as UserRow | undefined;
}

export function insertSession(database: DatabaseSync, instructorId: string): { id: string; started_at: string } {
  const id = randomUUID();
  const startedAt = new Date().toISOString();
  database.prepare(`INSERT INTO class_sessions (id, instructor_id, started_at, status) VALUES (?, ?, ?, 'active')`).run(id, instructorId, startedAt);
  return { id, started_at: startedAt };
}

export function insertWitnessObservation(database: DatabaseSync, params: { sessionId: string; observerDeviceId: string; observedDeviceId: string; rssi: number }): void {
  database.prepare(`INSERT INTO witness_observations (session_id, observer_device_id, observed_device_id, rssi, observed_at) VALUES (?, ?, ?, ?, ?)`).run(params.sessionId, params.observerDeviceId, params.observedDeviceId, params.rssi, new Date().toISOString());
}

export function countIndependentWitnesses(database: DatabaseSync, sessionId: string, observedDeviceId: string): number {
  const row = database.prepare(`SELECT COUNT(DISTINCT observer_device_id) as cnt FROM witness_observations WHERE session_id = ? AND observed_device_id = ?`).get(sessionId, observedDeviceId) as { cnt: number };
  return row.cnt;
}

export function upsertRiskAssessment(database: DatabaseSync, params: { sessionId: string; studentId: string; riskScore: number; reasons: string[] }): void {
  const id = randomUUID();
  database.prepare(`INSERT INTO risk_assessments (id, session_id, student_id, risk_score, reasons_json, computed_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(session_id, student_id) DO UPDATE SET risk_score = excluded.risk_score, reasons_json = excluded.reasons_json, computed_at = excluded.computed_at`).run(id, params.sessionId, params.studentId, params.riskScore, JSON.stringify(params.reasons), new Date().toISOString());
}

export interface SessionDeviceWitnessCount { observed_device_id: string; witness_count: number; }

export function getSessionWitnessSummary(database: DatabaseSync, sessionId: string): SessionDeviceWitnessCount[] {
  return database.prepare(`SELECT observed_device_id, COUNT(DISTINCT observer_device_id) as witness_count
       FROM witness_observations WHERE session_id = ? GROUP BY observed_device_id`).all(sessionId) as unknown as SessionDeviceWitnessCount[];
}

export interface RiskAssessmentRow { student_id: string; risk_score: number; reasons_json: string; computed_at: string; }

export function getSessionRiskAssessments(database: DatabaseSync, sessionId: string): RiskAssessmentRow[] {
  return database.prepare(`SELECT student_id, risk_score, reasons_json, computed_at FROM risk_assessments WHERE session_id = ?`).all(sessionId) as unknown as RiskAssessmentRow[];
}

export function getSessionById(database: DatabaseSync, sessionId: string): { id: string; instructor_id: string; started_at: string; status: string } | undefined {
  return database.prepare(`SELECT id, instructor_id, started_at, status FROM class_sessions WHERE id = ?`).get(sessionId) as any;
}

export function ensureDevice(database: DatabaseSync, userId: string, hardwareAttestationId: string): string {
  const existing = database.prepare(`SELECT id FROM devices WHERE hardware_attestation_id = ?`).get(hardwareAttestationId) as { id: string } | undefined;
  if (existing) return existing.id;
  const id = randomUUID();
  database.prepare(`INSERT INTO devices (id, user_id, hardware_attestation_id, enrolled_at) VALUES (?, ?, ?, ?)`).run(id, userId, hardwareAttestationId, new Date().toISOString());
  return id;
}