import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { createShahidServer } from "./shahid-server";
import { closeDb } from "./shahid-db";

let server: Server;
const PORT = 3999;
const BASE = `http://localhost:${PORT}`;

before(async () => {
  server = createShahidServer(":memory:");
  await new Promise<void>((resolve) => server.listen(PORT, resolve));
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  closeDb();
});

async function registerAndLogin(role: string, email: string) {
  await fetch(`${BASE}/auth/register`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ role, fullName: "Test User", email, password: "S3cure!Pass" }) });
  const loginRes = await fetch(`${BASE}/auth/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password: "S3cure!Pass" }) });
  const body = (await loginRes.json()) as { accessToken: string };
  return body.accessToken;
}

test("rejects requests with no auth token", async () => {
  const res = await fetch(`${BASE}/sessions`, { method: "POST" });
  assert.equal(res.status, 401);
});

test("rejects login with wrong password", async () => {
  await fetch(`${BASE}/auth/register`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ role: "student", fullName: "X", email: "wrongpass@test.com", password: "correct-horse" }) });
  const res = await fetch(`${BASE}/auth/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: "wrongpass@test.com", password: "incorrect" }) });
  assert.equal(res.status, 401);
});

test("rejects duplicate email registration", async () => {
  const email = "dupe@test.com";
  const first = await fetch(`${BASE}/auth/register`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ role: "student", fullName: "A", email, password: "pass1234" }) });
  assert.equal(first.status, 201);
  const second = await fetch(`${BASE}/auth/register`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ role: "student", fullName: "B", email, password: "otherpass" }) });
  assert.equal(second.status, 409);
});

test("student with 0 witnesses is absent, with quorum is present", async () => {
  const profToken = await registerAndLogin("professor", "prof-quorum@test.com");
  const studentToken = await registerAndLogin("student", "student-quorum@test.com");
  const authHeader = (t: string) => ({ Authorization: `Bearer ${t}`, "Content-Type": "application/json" });
  const deviceIds: string[] = [];
  for (const hw of ["hwA", "hwB", "hwC", "hwD", "hwE"]) {
    const r = await fetch(`${BASE}/devices/enroll`, { method: "POST", headers: authHeader(studentToken), body: JSON.stringify({ hardwareAttestationId: hw }) });
    deviceIds.push(((await r.json()) as { deviceId: string }).deviceId);
  }
  const [deviceA, deviceB, deviceC, deviceD, deviceE] = deviceIds;
  const sessionRes = await fetch(`${BASE}/sessions`, { method: "POST", headers: authHeader(profToken), body: "{}" });
  const session = (await sessionRes.json()) as { id: string };
  const before = await fetch(`${BASE}/sessions/${session.id}/attendance/${deviceA}`, { headers: authHeader(studentToken) });
  const beforeBody = (await before.json()) as { outcome: string; witnessCount: number };
  assert.equal(beforeBody.outcome, "absent"); assert.equal(beforeBody.witnessCount, 0);
  for (const observer of [deviceB, deviceC, deviceD, deviceE]) {
    const r = await fetch(`${BASE}/sessions/${session.id}/witnesses`, { method: "POST", headers: authHeader(studentToken), body: JSON.stringify({ observerDeviceId: observer, observedDeviceId: deviceA, rssi: -60 }) });
    assert.equal(r.status, 201);
  }
  const after = await fetch(`${BASE}/sessions/${session.id}/attendance/${deviceA}`, { headers: authHeader(studentToken) });
  const afterBody = (await after.json()) as { outcome: string; witnessCount: number };
  assert.equal(afterBody.outcome, "present"); assert.equal(afterBody.witnessCount, 4);
});

test("a student who never enrolls a device cannot self-witness (FK integrity holds)", async () => {
  const profToken = await registerAndLogin("professor", "prof-fk@test.com");
  const sessionRes = await fetch(`${BASE}/sessions`, { method: "POST", headers: { Authorization: `Bearer ${profToken}`, "Content-Type": "application/json" }, body: "{}" });
  const session = (await sessionRes.json()) as { id: string };
  const res = await fetch(`${BASE}/sessions/${session.id}/witnesses`, { method: "POST", headers: { Authorization: `Bearer ${profToken}`, "Content-Type": "application/json" }, body: JSON.stringify({ observerDeviceId: "never-enrolled-1", observedDeviceId: "never-enrolled-2", rssi: -60 }) });
  assert.equal(res.status, 500);
  const body = (await res.json()) as { message: string };
  assert.match(body.message, /FOREIGN KEY/);
});

test("suspicious pattern escalates with all three risk reasons", async () => {
  const profToken = await registerAndLogin("professor", "prof-risk@test.com");
  const studentToken = await registerAndLogin("student", "student-risk@test.com");
  const authHeader = (t: string) => ({ Authorization: `Bearer ${t}`, "Content-Type": "application/json" });
  const [, payloadB64] = studentToken.split(".");
  const studentId = (JSON.parse(Buffer.from(payloadB64, "base64url").toString()) as { sub: string }).sub;
  const deviceIds: string[] = [];
  for (const hw of ["r-hwA", "r-hwB", "r-hwC", "r-hwD", "r-hwE"]) {
    const r = await fetch(`${BASE}/devices/enroll`, { method: "POST", headers: authHeader(studentToken), body: JSON.stringify({ hardwareAttestationId: hw }) });
    deviceIds.push(((await r.json()) as { deviceId: string }).deviceId);
  }
  const [deviceA, deviceB, deviceC, deviceD, deviceE] = deviceIds;
  const sessionRes = await fetch(`${BASE}/sessions`, { method: "POST", headers: authHeader(profToken), body: "{}" });
  const session = (await sessionRes.json()) as { id: string };
  for (const observer of [deviceB, deviceC, deviceD, deviceE]) await fetch(`${BASE}/sessions/${session.id}/witnesses`, { method: "POST", headers: authHeader(studentToken), body: JSON.stringify({ observerDeviceId: observer, observedDeviceId: deviceA, rssi: -60 }) });
  const riskRes = await fetch(`${BASE}/sessions/${session.id}/risk/${studentId}`, { method: "POST", headers: authHeader(studentToken), body: JSON.stringify({ deviceId: deviceA, pulseScore: 0.1, livenessPingSent: true, pairStats: [{ deviceA, deviceB: "device-X", coOccurrenceRate: 0.97, varianceScore: 0.05, sessionsObserved: 22 }] }) });
  const risk = (await riskRes.json()) as { escalate: boolean; riskScore: number; reasons: string[] };
  assert.equal(risk.escalate, true); assert.equal(risk.riskScore, 1);
  assert.deepEqual(risk.reasons.sort(), ["low_pulse_score_despite_presence", "missed_liveness_ping", "suspicious_pair_pattern"].sort());
});

test("dashboard endpoint aggregates witness + risk data, and CORS preflight is open", async () => {
  const profToken = await registerAndLogin("professor", "prof-dash@test.com");
  const studentToken = await registerAndLogin("student", "student-dash@test.com");
  const authHeader = (t: string) => ({ Authorization: `Bearer ${t}`, "Content-Type": "application/json" });
  const deviceIds: string[] = [];
  for (const hw of ["d-hwA", "d-hwB", "d-hwC", "d-hwD", "d-hwE"]) {
    const r = await fetch(`${BASE}/devices/enroll`, { method: "POST", headers: authHeader(studentToken), body: JSON.stringify({ hardwareAttestationId: hw }) });
    deviceIds.push(((await r.json()) as { deviceId: string }).deviceId);
  }
  const [deviceA, deviceB, deviceC, deviceD, deviceE] = deviceIds;
  const sessionRes = await fetch(`${BASE}/sessions`, { method: "POST", headers: authHeader(profToken), body: "{}" });
  const session = (await sessionRes.json()) as { id: string };
  for (const observer of [deviceB, deviceC, deviceD, deviceE]) await fetch(`${BASE}/sessions/${session.id}/witnesses`, { method: "POST", headers: authHeader(studentToken), body: JSON.stringify({ observerDeviceId: observer, observedDeviceId: deviceA, rssi: -60 }) });
  const dashRes = await fetch(`${BASE}/sessions/${session.id}/dashboard`, { headers: authHeader(profToken) });
  assert.equal(dashRes.status, 200); assert.equal(dashRes.headers.get("access-control-allow-origin"), "*");
  const dash = (await dashRes.json()) as { presentCount: number; students: Array<{ deviceId: string; outcome: string; witnessCount: number }> };
  assert.equal(dash.presentCount, 1); assert.equal(dash.students[0].deviceId, deviceA); assert.equal(dash.students[0].witnessCount, 4);
  const preflight = await fetch(`${BASE}/sessions/${session.id}/dashboard`, { method: "OPTIONS" });
  assert.equal(preflight.status, 204); assert.equal(preflight.headers.get("access-control-allow-methods"), "GET, POST, OPTIONS");
});

test("a different professor cannot view another professor's session dashboard", async () => {
  const authHeader = (t: string) => ({ Authorization: `Bearer ${t}`, "Content-Type": "application/json" });
  const ownerToken = await registerAndLogin("professor", "prof-owner@test.com");
  const otherToken = await registerAndLogin("professor", "prof-other@test.com");
  const sessionRes = await fetch(`${BASE}/sessions`, { method: "POST", headers: authHeader(ownerToken), body: "{}" });
  const session = (await sessionRes.json()) as { id: string };
  const ownerView = await fetch(`${BASE}/sessions/${session.id}/dashboard`, { headers: authHeader(ownerToken) });
  assert.equal(ownerView.status, 200);
  const otherView = await fetch(`${BASE}/sessions/${session.id}/dashboard`, { headers: authHeader(otherToken) });
  assert.equal(otherView.status, 403);
  const body = (await otherView.json()) as { error: string };
  assert.equal(body.error, "not_your_session");
});

test("tampered JWT signature is rejected", async () => {
  const token = await registerAndLogin("student", "tamper@test.com");
  const tampered = token.slice(0, -2) + "xx";
  const res = await fetch(`${BASE}/devices/enroll`, { method: "POST", headers: { Authorization: `Bearer ${tampered}`, "Content-Type": "application/json" }, body: JSON.stringify({ hardwareAttestationId: "irrelevant" }) });
  assert.equal(res.status, 401);
});