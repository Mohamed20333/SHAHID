import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { createShahidServer } from "./shahid-server";
import { closeDb, getDb, insertUser } from "./shahid-db";
import { hashPassword } from "./shahid-auth";

let server: Server;
const PORT = 3999;
const BASE = `http://localhost:${PORT}`;
const PASSWORD = "Correct-Horse-123!";

before(async () => {
  process.env.NODE_ENV = "test";
  process.env.SHAHID_ALLOWED_ORIGINS = "http://localhost:5173";
  server = createShahidServer(":memory:");
  await new Promise<void>((resolve) => server.listen(PORT, resolve));
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  closeDb();
});

async function registerStudent(email: string): Promise<void> {
  const res = await fetch(`${BASE}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ role: "student", fullName: "Test Student", email, password: PASSWORD }),
  });
  assert.equal(res.status, 201);
}

function createProfessor(email: string): string {
  const db = getDb();
  return insertUser(db, {
    role: "professor",
    fullName: "Test Professor",
    email,
    passwordHash: hashPassword(PASSWORD),
  }).id;
}

async function login(email: string): Promise<{ accessToken: string; refreshToken: string; role: string }> {
  const res = await fetch(`${BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: PASSWORD }),
  });
  assert.equal(res.status, 200);
  return (await res.json()) as { accessToken: string; refreshToken: string; role: string };
}

async function enroll(accessToken: string, key: string): Promise<string> {
  const res = await fetch(`${BASE}/devices/enroll`, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ deviceEnrollmentKey: key }),
  });
  assert.equal(res.status, 200);
  return ((await res.json()) as { deviceId: string }).deviceId;
}

function auth(token: string, deviceId?: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    ...(deviceId ? { "X-Device-ID": deviceId } : {}),
  };
}

async function createSession(professorToken: string): Promise<string> {
  const res = await fetch(`${BASE}/sessions`, {
    method: "POST",
    headers: auth(professorToken),
    body: "{}",
  });
  assert.equal(res.status, 201);
  return ((await res.json()) as { id: string }).id;
}

test("requires an access token for protected endpoints", async () => {
  const res = await fetch(`${BASE}/sessions`, { method: "POST" });
  assert.equal(res.status, 401);
});

test("public registration can create students but cannot self-assign privileged roles", async () => {
  await registerStudent("role-student@test.com");

  const res = await fetch(`${BASE}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      role: "platform_admin",
      fullName: "Attacker",
      email: "attacker-admin@test.com",
      password: PASSWORD,
    }),
  });
  assert.equal(res.status, 403);
});

test("rejects weak passwords and malformed registration", async () => {
  const res = await fetch(`${BASE}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ role: "student", fullName: "X", email: "bad", password: "short" }),
  });
  assert.equal(res.status, 400);
});

test("rejects login with wrong password", async () => {
  await registerStudent("wrongpass@test.com");
  const res = await fetch(`${BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "wrongpass@test.com", password: "Wrong-Password-123!" }),
  });
  assert.equal(res.status, 401);
});

test("refresh tokens are opaque, rotated, and cannot be reused", async () => {
  await registerStudent("refresh@test.com");
  const first = await login("refresh@test.com");
  assert.ok(first.refreshToken.length >= 60);

  const rotated = await fetch(`${BASE}/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refreshToken: first.refreshToken }),
  });
  assert.equal(rotated.status, 200);
  const second = (await rotated.json()) as { accessToken: string; refreshToken: string };
  assert.notEqual(second.refreshToken, first.refreshToken);

  const reuse = await fetch(`${BASE}/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refreshToken: first.refreshToken }),
  });
  assert.equal(reuse.status, 401);
});

test("a refresh token is not accepted as an access token", async () => {
  await registerStudent("token-type@test.com");
  const tokens = await login("token-type@test.com");
  const res = await fetch(`${BASE}/devices/enroll`, {
    method: "POST",
    headers: auth(tokens.refreshToken),
    body: JSON.stringify({ deviceEnrollmentKey: "x" }),
  });
  assert.equal(res.status, 401);
});

test("witness observer identity must belong to the authenticated user", async () => {
  const professor = createProfessor("prof-witness@test.com");
  const profLogin = await login("prof-witness@test.com");
  assert.equal(profLogin.role, "professor");

  await registerStudent("observer@test.com");
  await registerStudent("target@test.com");
  const observer = await login("observer@test.com");
  const target = await login("target@test.com");
  const observerDevice = await enroll(observer.accessToken, "observer-device-secret");
  const targetDevice = await enroll(target.accessToken, "target-device-secret");
  const sessionId = await createSession(profLogin.accessToken);
  assert.ok(professor);

  const forgedObserver = await fetch(`${BASE}/sessions/${sessionId}/witnesses`, {
    method: "POST",
    headers: auth(observer.accessToken, targetDevice),
    body: JSON.stringify({ observedDeviceId: targetDevice, rssi: -60 }),
  });
  assert.equal(forgedObserver.status, 403);
  const audit = getDb().prepare("SELECT action, reason_code FROM audit_log WHERE actor_id = ? ORDER BY id DESC LIMIT 1").get(
    JSON.parse(Buffer.from(observer.accessToken.split(".")[1], "base64url").toString()).sub,
  ) as { action: string; reason_code: string };
  assert.equal(audit.action, "DEVICE_SPOOF_ATTEMPT");
  assert.equal(audit.reason_code, "observer_not_owned");

  const legitimate = await fetch(`${BASE}/sessions/${sessionId}/witnesses`, {
    method: "POST",
    headers: auth(observer.accessToken, observerDevice),
    body: JSON.stringify({ observedDeviceId: targetDevice, rssi: -60 }),
  });
  assert.equal(legitimate.status, 201);
});

test("multiple devices owned by one student do not create an independent quorum", async () => {
  const prof = await login("prof-witness@test.com");
  await registerStudent("single-owner@test.com");
  const student = await login("single-owner@test.com");
  const target = await enroll(student.accessToken, "single-target");
  const ownDevices = [];
  for (let i = 1; i <= 4; i++) ownDevices.push(await enroll(student.accessToken, `single-owner-device-${i}`));
  const sessionId = await createSession(prof.accessToken);

  for (const observerDevice of ownDevices) {
    const res = await fetch(`${BASE}/sessions/${sessionId}/witnesses`, {
      method: "POST",
      headers: auth(student.accessToken, observerDevice),
      body: JSON.stringify({ observedDeviceId: target, rssi: -60 }),
    });
    assert.equal(res.status, 403);
  }

  const attendance = await fetch(`${BASE}/sessions/${sessionId}/attendance/${target}`, {
    headers: auth(student.accessToken),
  });
  assert.equal(attendance.status, 200);
  const body = (await attendance.json()) as { witnessCount: number; outcome: string };
  assert.equal(body.witnessCount, 0);
  assert.equal(body.outcome, "absent");
});

test("attendance is visible only to the session owner or device owner", async () => {
  const prof1 = await login("prof-witness@test.com");
  const prof2Id = createProfessor("prof-other@test.com");
  const prof2 = await login("prof-other@test.com");
  assert.ok(prof2Id);

  await registerStudent("attendance-student@test.com");
  const student = await login("attendance-student@test.com");
  const device = await enroll(student.accessToken, "attendance-device");
  const sessionId = await createSession(prof1.accessToken);

  const owner = await fetch(`${BASE}/sessions/${sessionId}/attendance/${device}`, { headers: auth(prof1.accessToken) });
  assert.equal(owner.status, 200);

  const studentView = await fetch(`${BASE}/sessions/${sessionId}/attendance/${device}`, { headers: auth(student.accessToken) });
  assert.equal(studentView.status, 200);

  const other = await fetch(`${BASE}/sessions/${sessionId}/attendance/${device}`, { headers: auth(prof2.accessToken) });
  assert.equal(other.status, 403);
});

test("risk calculation ignores client-supplied evidence and reads server-owned evidence", async () => {
  const prof = await login("prof-witness@test.com");
  await registerStudent("risk-student@test.com");
  const student = await login("risk-student@test.com");
  const device = await enroll(student.accessToken, "risk-device");
  const secondDevice = await enroll(student.accessToken, "risk-device-2");
  const sessionId = await createSession(prof.accessToken);

  for (let i = 1; i <= 4; i++) {
    const email = `risk-observer-${i}@test.com`;
    await registerStudent(email);
    const observer = await login(email);
    const observerDevice = await enroll(observer.accessToken, `risk-observer-device-${i}`);
    const witness = await fetch(`${BASE}/sessions/${sessionId}/witnesses`, {
      method: "POST",
      headers: auth(observer.accessToken, observerDevice),
      body: JSON.stringify({ observedDeviceId: device, rssi: -60 }),
    });
    assert.equal(witness.status, 201);
  }

  const db = getDb();
  db.prepare(`INSERT INTO pair_stats (device_a_id, device_b_id, sessions_observed, co_occurrence_rate, variance_score)
              VALUES (?, ?, ?, ?, ?)`).run(device, secondDevice, 22, 0.97, 0.05);

  // Deliberately send forged risk evidence. The API must ignore it.
  const res = await fetch(`${BASE}/sessions/${sessionId}/risk/${JSON.parse(Buffer.from(student.accessToken.split(".")[1], "base64url").toString()).sub}`, {
    method: "POST",
    headers: auth(student.accessToken),
    body: JSON.stringify({
      deviceId: "attacker-controlled-device",
      pulseScore: 0.01,
      livenessPingSent: true,
      livenessPingAnsweredMs: null,
      pairStats: [{ deviceA: device, deviceB: "fake", coOccurrenceRate: 1, varianceScore: 0, sessionsObserved: 999 }],
      escalationsThisWeek: 0,
    }),
  });

  assert.equal(res.status, 403);
  const professorOnly = await fetch(`${BASE}/sessions/${sessionId}/risk/${JSON.parse(Buffer.from(student.accessToken.split(".")[1], "base64url").toString()).sub}`, {
    method: "POST",
    headers: auth(prof.accessToken),
    body: JSON.stringify({ pulseScore: 0, pairStats: [{ coOccurrenceRate: 1 }] }),
  });
  assert.equal(professorOnly.status, 200);
  const risk = (await professorOnly.json()) as { riskScore: number; evidence: { engagementScore: number | null; pairSignals: number } };
  assert.equal(risk.evidence.engagementScore, null);
  assert.equal(risk.evidence.pairSignals, 1);
  assert.ok(risk.riskScore >= 0.4);
});

test("oversized JSON bodies are rejected", async () => {
  const body = JSON.stringify({ role: "student", fullName: "A".repeat(70_000), email: "large@test.com", password: PASSWORD });
  const res = await fetch(`${BASE}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
  assert.equal(res.status, 413);
});

test("CORS is allowlisted rather than wildcarded", async () => {
  const allowed = await fetch(`${BASE}/auth/login`, {
    method: "OPTIONS",
    headers: { Origin: "http://localhost:5173" },
  });
  assert.equal(allowed.status, 204);
  assert.equal(allowed.headers.get("access-control-allow-origin"), "http://localhost:5173");

  const forbidden = await fetch(`${BASE}/auth/login`, {
    method: "OPTIONS",
    headers: { Origin: "https://attacker.example" },
  });
  assert.equal(forbidden.status, 204);
  assert.equal(forbidden.headers.get("access-control-allow-origin"), null);
});

test("JWT tampering is rejected", async () => {
  await registerStudent("tamper@test.com");
  const token = (await login("tamper@test.com")).accessToken;
  const tampered = token.slice(0, -2) + "xx";
  const res = await fetch(`${BASE}/devices/enroll`, {
    method: "POST",
    headers: auth(tampered),
    body: JSON.stringify({ deviceEnrollmentKey: "irrelevant" }),
  });
  assert.equal(res.status, 401);
});

test("dashboard access remains owner-scoped", async () => {
  const owner = await login("prof-witness@test.com");
  const other = await login("prof-other@test.com");
  const sessionId = await createSession(owner.accessToken);

  const ownerView = await fetch(`${BASE}/sessions/${sessionId}/dashboard`, { headers: auth(owner.accessToken) });
  assert.equal(ownerView.status, 200);

  const otherView = await fetch(`${BASE}/sessions/${sessionId}/dashboard`, { headers: auth(other.accessToken) });
  assert.equal(otherView.status, 403);
});
