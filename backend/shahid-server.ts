import { createHash, randomUUID } from "node:crypto";
import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

import {
  createRefreshToken,
  hashPassword,
  hashRefreshToken,
  signAccessJwt,
  verifyAccessJwt,
  verifyPassword,
} from "./shahid-auth";
import {
  closeDb,
  countIndependentWitnesses,
  countRecentRiskAssessments,
  createRefreshTokenRecord,
  ensureDevice,
  findUserByEmail,
  findUserById,
  getDb,
  getDevice,
  getEngagementScore,
  getLivenessEvent,
  getPairStatsForDevice,
  getRefreshToken,
  getSessionById,
  getSessionRiskAssessments,
  getSessionWitnessSummary,
  getUserDevice,
  getUserDevices,
  insertSession,
  insertUser,
  insertWitnessObservation,
  revokeRefreshFamily,
  revokeRefreshToken,
  rotateRefreshToken,
  upsertRiskAssessment,
  writeAuditLog,
  createDeviceChallenge,
  getDeviceChallenge,
  consumeDeviceChallenge,
  enrollCryptographicDevice,
  getCryptoDevice,
  recordAttendanceProof,
  getAttendanceProof,
} from "./shahid-db";
import {
  canonicalProof,
  isFreshIsoTimestamp,
  keyFingerprint,
  normalizePublicKey,
  verifyDeviceSignature,
} from "./shahid-device-crypto";
import {
  CONFIG,
  decideEscalation,
  hasQuorum,
  type HistoricalPairStats,
  type SessionRecord,
} from "./shahid-escalation-logic";

const JWT_SECRET =
  process.env.SHAHID_JWT_SECRET ??
  (process.env.NODE_ENV === "production"
    ? (() => {
        throw new Error("SHAHID_JWT_SECRET must be set in production");
      })()
    : "local-development-secret-change-me");

const QUORUM_MIN_WITNESSES = CONFIG.quorumMinWitnesses;
const MAX_BODY_BYTES = 64 * 1024;
const ACCESS_TOKEN_SECONDS = 15 * 60;
const REFRESH_TOKEN_DAYS = 7;

const allowedOrigins = new Set(
  (process.env.SHAHID_ALLOWED_ORIGINS ?? "http://localhost:5173,http://localhost:3000")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean),
);

const rateBuckets = new Map<string, { count: number; windowStart: number }>();
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 120;
const LOGIN_RATE_LIMIT_MAX = process.env.NODE_ENV === "test" ? 100 : 10;
const REGISTER_RATE_LIMIT_MAX = process.env.NODE_ENV === "test" ? 100 : 5;

interface AuthedUser {
  sub: string;
  role: string;
}

function isRateLimited(key: string, max = RATE_LIMIT_MAX): boolean {
  const now = Date.now();
  const bucket = rateBuckets.get(key);
  if (!bucket || now - bucket.windowStart >= RATE_LIMIT_WINDOW_MS) {
    rateBuckets.set(key, { count: 1, windowStart: now });
    return false;
  }
  bucket.count += 1;
  return bucket.count > max;
}

function getClientIp(req: IncomingMessage): string {
  return req.socket.remoteAddress ?? "unknown";
}

function requestId(): string {
  return randomUUID();
}

function corsHeaders(req: IncomingMessage): Record<string, string> {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.has(origin)) {
    return {
      "Access-Control-Allow-Origin": origin,
      Vary: "Origin",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-ID",
      "Access-Control-Max-Age": "600",
    };
  }
  return {
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-ID",
    "Access-Control-Max-Age": "600",
  };
}

function sendJson(res: ServerResponse, req: IncomingMessage, status: number, body: unknown): void {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    ...corsHeaders(req),
  });
  res.end(JSON.stringify(body));
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const contentType = String(req.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase();
  if (contentType !== "application/json") throw new Error("unsupported_media_type");

  const declaredLength = Number(req.headers["content-length"] ?? 0);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) {
    throw new Error("payload_too_large");
  }

  return new Promise((resolveBody, reject) => {
    let raw = "";
    let size = 0;
    let settled = false;

    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      req.destroy();
      reject(error);
    };

    req.on("data", (chunk: Buffer | string) => {
      const bytes = Buffer.byteLength(chunk);
      size += bytes;
      if (size > MAX_BODY_BYTES) {
        fail(new Error("payload_too_large"));
        return;
      }
      raw += chunk.toString();
    });

    req.on("end", () => {
      if (settled) return;
      settled = true;
      if (!raw) {
        resolveBody({});
        return;
      }
      try {
        const parsed = JSON.parse(raw) as unknown;
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          reject(new Error("invalid_json_body"));
          return;
        }
        resolveBody(parsed as Record<string, unknown>);
      } catch {
        reject(new Error("invalid_json_body"));
      }
    });

    req.on("error", () => fail(new Error("request_stream_error")));
  });
}

function requireAccess(req: IncomingMessage): AuthedUser | null {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) return null;
  const payload = verifyAccessJwt(header.slice("Bearer ".length).trim(), JWT_SECRET);
  return payload ? { sub: payload.sub, role: payload.role } : null;
}

function requireRole(user: AuthedUser, ...roles: string[]): boolean {
  return roles.includes(user.role);
}

function validString(value: unknown, max: number): value is string {
  return typeof value === "string" && value.trim().length > 0 && value.length <= max;
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validPassword(value: unknown): value is string {
  return typeof value === "string" && value.length >= 12 && value.length <= 128;
}

function logEvent(fields: Record<string, unknown>): void {
  console.log(JSON.stringify({ ts: new Date().toISOString(), ...fields }));
}

function errorResponse(error: unknown): { status: number; error: string } {
  const code = error instanceof Error ? error.message : "unknown";
  switch (code) {
    case "unsupported_media_type":
      return { status: 415, error: "unsupported_media_type" };
    case "payload_too_large":
      return { status: 413, error: "payload_too_large" };
    case "invalid_json_body":
      return { status: 400, error: "invalid_json_body" };
    case "password_policy_violation":
      return { status: 400, error: "password_policy_violation" };
    case "device_enrollment_already_owned":
      return { status: 409, error: "device_enrollment_conflict" };
    case "refresh_token_reuse":
      return { status: 401, error: "invalid_refresh_token" };
    default:
      return { status: 500, error: "internal_error" };
  }
}

export function createShahidServer(dbPath: string = ":memory:") {
  const db = getDb(dbPath);

  return createServer(async (req, res) => {
    const started = Date.now();
    const id = requestId();
    const ip = getClientIp(req);
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const method = req.method ?? "GET";

    const finish = (status: number, body: unknown) => {
      sendJson(res, req, status, body);
      logEvent({ requestId: id, method, path, status, durationMs: Date.now() - started });
    };

    if (method === "OPTIONS") {
      res.writeHead(204, corsHeaders(req));
      res.end();
      return;
    }

    if (isRateLimited(`ip:${ip}`)) {
      finish(429, { error: "rate_limited", requestId: id });
      return;
    }

    try {
      if (method === "POST" && path === "/auth/register") {
        // Public registration deliberately creates students only. Privileged
        // accounts must be provisioned by an already-authorized administrator.
        if (isRateLimited(`register:${ip}`, REGISTER_RATE_LIMIT_MAX)) {
          finish(429, { error: "rate_limited", requestId: id });
          return;
        }
        const body = await readJsonBody(req);
        if (!validString(body.fullName, 100) || !validEmail(body.email) || !validPassword(body.password)) {
          finish(400, { error: "invalid_registration", requestId: id });
          return;
        }
        if (body.role !== undefined && body.role !== "student") {
          writeAuditLog(db, { action: "PRIVILEGED_REGISTRATION_BLOCKED", targetType: "registration", reasonCode: "public_role_escalation", metadata: { requestId: id, requestedRole: body.role } });
          finish(403, { error: "privileged_role_registration_forbidden", requestId: id });
          return;
        }
        if (findUserByEmail(db, body.email)) {
          finish(409, { error: "email_already_registered", requestId: id });
          return;
        }
        const user = insertUser(db, {
          role: "student",
          fullName: body.fullName,
          email: body.email,
          passwordHash: hashPassword(body.password),
        });
        finish(201, { id: user.id, role: user.role, email: user.email });
        return;
      }

      if (method === "POST" && path === "/auth/login") {
        if (isRateLimited(`login:${ip}`, LOGIN_RATE_LIMIT_MAX)) {
          finish(429, { error: "rate_limited", requestId: id });
          return;
        }
        const body = await readJsonBody(req);
        if (!validEmail(body.email) || typeof body.password !== "string" || body.password.length > 128) {
          finish(401, { error: "invalid_credentials", requestId: id });
          return;
        }

        const user = findUserByEmail(db, body.email);
        if (!user || !verifyPassword(body.password, user.password_hash)) {
          finish(401, { error: "invalid_credentials", requestId: id });
          return;
        }

        const accessToken = signAccessJwt({ sub: user.id, role: user.role }, JWT_SECRET, ACCESS_TOKEN_SECONDS);
        const refresh = createRefreshToken();
        const expiresAt = new Date(Date.now() + REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000).toISOString();
        createRefreshTokenRecord(db, user.id, refresh.hash, expiresAt);
        finish(200, { accessToken, refreshToken: refresh.token, expiresIn: ACCESS_TOKEN_SECONDS, role: user.role });
        return;
      }

      if (method === "POST" && path === "/auth/refresh") {
        const body = await readJsonBody(req);
        if (!validString(body.refreshToken, 256)) {
          finish(401, { error: "invalid_refresh_token", requestId: id });
          return;
        }

        const hash = hashRefreshToken(body.refreshToken);
        const stored = getRefreshToken(db, hash);
        if (!stored) {
          finish(401, { error: "invalid_refresh_token", requestId: id });
          return;
        }

        if (stored.revoked_at) {
          revokeRefreshFamily(db, stored.family_id);
          writeAuditLog(db, { actorId: stored.user_id, action: "REFRESH_TOKEN_REUSE", targetType: "refresh_token", targetId: stored.id, reasonCode: "revoked_token_replay", metadata: { requestId: id } });
          logEvent({ requestId: id, securityEvent: "refresh_token_reuse", userId: stored.user_id });
          finish(401, { error: "invalid_refresh_token", requestId: id });
          return;
        }

        if (Date.parse(stored.expires_at) <= Date.now()) {
          revokeRefreshToken(db, hash);
          finish(401, { error: "invalid_refresh_token", requestId: id });
          return;
        }

        const user = findUserById(db, stored.user_id);
        if (!user) {
          finish(401, { error: "invalid_refresh_token", requestId: id });
          return;
        }

        const next = createRefreshToken();
        const nextExpiry = new Date(Date.now() + REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000).toISOString();
        try {
          rotateRefreshToken(db, stored.id, next.hash, user.id, stored.family_id, nextExpiry);
        } catch {
          revokeRefreshFamily(db, stored.family_id);
          finish(401, { error: "invalid_refresh_token", requestId: id });
          return;
        }

        const accessToken = signAccessJwt({ sub: user.id, role: user.role }, JWT_SECRET, ACCESS_TOKEN_SECONDS);
        finish(200, { accessToken, refreshToken: next.token, expiresIn: ACCESS_TOKEN_SECONDS, role: user.role });
        return;
      }

      if (method === "POST" && path === "/auth/logout") {
        const body = await readJsonBody(req);
        if (validString(body.refreshToken, 256)) {
          revokeRefreshToken(db, hashRefreshToken(body.refreshToken));
        }
        finish(204, null);
        return;
      }

      const authed = requireAccess(req);
      if (!authed) {
        finish(401, { error: "unauthenticated", requestId: id });
        return;
      }

      if (method === "POST" && path === "/devices/enroll/challenge") {
        const body = await readJsonBody(req);
        if (!validString(body.publicKey, 4096) || !validString(body.keyId, 128)) {
          finish(400, { error: "invalid_device_key", requestId: id });
          return;
        }
        let publicKey: string;
        try { publicKey = normalizePublicKey(body.publicKey); } catch {
          finish(400, { error: "invalid_device_key", requestId: id });
          return;
        }
        const challenge = createDeviceChallenge(db, {
          userId: authed.sub,
          publicKey,
          keyId: body.keyId,
          purpose: "device_enrollment",
        });
        finish(200, challenge);
        return;
      }

      if (method === "POST" && path === "/devices/enroll/complete") {
        const body = await readJsonBody(req);
        if (!validString(body.challengeId, 100) || !validString(body.signature, 256)) {
          finish(400, { error: "invalid_device_proof", requestId: id });
          return;
        }
        const challenge = getDeviceChallenge(db, body.challengeId);
        if (!challenge || challenge.user_id !== authed.sub || challenge.purpose !== "device_enrollment" ||
            challenge.consumed_at || Date.parse(challenge.expires_at) <= Date.now()) {
          finish(401, { error: "invalid_device_proof", requestId: id });
          return;
        }
        const message = canonicalProof({
          challengeId: challenge.id,
          nonce: challenge.nonce,
          purpose: challenge.purpose,
          keyId: challenge.key_id,
        });
        if (!verifyDeviceSignature(challenge.public_key, message, body.signature)) {
          writeAuditLog(db, { actorId: authed.sub, action: "DEVICE_SIGNATURE_INVALID", targetType: "device_challenge", targetId: challenge.id, reasonCode: "enrollment_signature_failed", metadata: { requestId: id } });
          finish(401, { error: "invalid_device_proof", requestId: id });
          return;
        }
        if (!consumeDeviceChallenge(db, challenge.id)) {
          finish(409, { error: "challenge_replayed", requestId: id });
          return;
        }
        try {
          const deviceId = enrollCryptographicDevice(db, {
            userId: authed.sub,
            publicKey: challenge.public_key,
            keyId: challenge.key_id,
          });
          finish(201, { deviceId, keyId: challenge.key_id, algorithm: "Ed25519" });
        } catch {
          finish(409, { error: "device_key_conflict", requestId: id });
        }
        return;
      }

      if (method === "POST" && path === "/devices/proof-challenge") {
        const body = await readJsonBody(req);
        if (!validString(body.deviceId, 100)) {
          finish(400, { error: "invalid_device", requestId: id });
          return;
        }
        const device = getUserDevice(db, authed.sub, body.deviceId);
        const cryptoDevice = device ? getCryptoDevice(db, body.deviceId) : null;
        if (!device || !cryptoDevice || cryptoDevice.status !== "active") {
          finish(403, { error: "device_not_authorized", requestId: id });
          return;
        }
        const sessionId = validString(body.sessionId, 100) ? body.sessionId : null;
        if (sessionId) {
          const session = getSessionById(db, sessionId);
          if (!session || session.status !== "active") {
            finish(404, { error: "session_not_found", requestId: id });
            return;
          }
        }
        const challenge = createDeviceChallenge(db, {
          userId: authed.sub,
          publicKey: cryptoDevice.public_key,
          keyId: cryptoDevice.key_id,
          purpose: sessionId ? "session_proof" : "device_proof",
          sessionId,
        });
        finish(200, challenge);
        return;
      }

      if (method === "POST" && path === "/devices/enroll") {
        if (process.env.NODE_ENV !== "test") {
          finish(410, { error: "legacy_device_enrollment_disabled", requestId: id });
          return;
        }
        const body = await readJsonBody(req);
        if (!validString(body.deviceEnrollmentKey, 256)) {
          finish(400, { error: "invalid_device_enrollment", requestId: id });
          return;
        }
        const deviceKeyHash = createHash("sha256").update(body.deviceEnrollmentKey, "utf8").digest("hex");
        const deviceId = ensureDevice(db, authed.sub, deviceKeyHash);
        finish(200, { deviceId });
        return;
      }

      const checkinMatch = path.match(/^\/sessions\/([^/]+)\/check-in$/);
      if (method === "POST" && checkinMatch) {
        const sessionId = checkinMatch[1];
        const session = getSessionById(db, sessionId);
        if (!session || session.status !== "active") {
          finish(404, { error: "session_not_found", requestId: id });
          return;
        }
        const body = await readJsonBody(req);
        if (!validString(body.deviceId, 100) || !validString(body.challengeId, 100) ||
            !validString(body.signature, 256) || !isFreshIsoTimestamp(body.timestamp)) {
          finish(400, { error: "invalid_check_in_proof", requestId: id });
          return;
        }
        const device = getUserDevice(db, authed.sub, body.deviceId);
        const cryptoDevice = device ? getCryptoDevice(db, body.deviceId) : null;
        const challenge = getDeviceChallenge(db, body.challengeId);
        if (!cryptoDevice || cryptoDevice.status !== "active" || !challenge ||
            challenge.user_id !== authed.sub || challenge.session_id !== sessionId ||
            challenge.purpose !== "session_proof" || challenge.consumed_at ||
            Date.parse(challenge.expires_at) <= Date.now()) {
          finish(401, { error: "invalid_check_in_proof", requestId: id });
          return;
        }
        const message = canonicalProof({
          challengeId: challenge.id,
          nonce: challenge.nonce,
          purpose: challenge.purpose,
          sessionId,
          deviceId: body.deviceId,
          timestamp: body.timestamp as string,
        });
        if (!verifyDeviceSignature(cryptoDevice.public_key, message, body.signature)) {
          writeAuditLog(db, { actorId: authed.sub, action: "DEVICE_SIGNATURE_INVALID", targetType: "session", targetId: sessionId, reasonCode: "check_in_signature_failed", metadata: { requestId: id, deviceId: body.deviceId } });
          finish(401, { error: "invalid_check_in_proof", requestId: id });
          return;
        }
        if (!consumeDeviceChallenge(db, challenge.id)) {
          finish(409, { error: "challenge_replayed", requestId: id });
          return;
        }
        recordAttendanceProof(db, { sessionId, studentId: authed.sub, deviceId: body.deviceId, proofVerified: true });
        finish(201, { sessionId, deviceId: body.deviceId, status: "checked_in", proofVerified: true });
        return;
      }

      if (method === "POST" && path === "/sessions") {
        if (!requireRole(authed, "professor")) {
          finish(403, { error: "forbidden_role", requestId: id });
          return;
        }
        finish(201, insertSession(db, authed.sub));
        return;
      }

      const witnessMatch = path.match(/^\/sessions\/([^/]+)\/witnesses$/);
      if (method === "POST" && witnessMatch) {
        const sessionId = witnessMatch[1];
        const session = getSessionById(db, sessionId);
        if (!session || session.status !== "active") {
          finish(404, { error: "session_not_found", requestId: id });
          return;
        }

        const body = await readJsonBody(req);
        const observerDeviceId = String(req.headers["x-device-id"] ?? "");
        const observedDeviceId = body.observedDeviceId;
        const rssi = body.rssi;
        const nonce = body.nonce;
        const signature = body.signature;
        const observationTimestamp = body.timestamp;

        if (!validString(observedDeviceId, 100) || typeof rssi !== "number" || !Number.isInteger(rssi) || rssi < -127 || rssi > 0) {
          finish(400, { error: "invalid_witness_observation", requestId: id });
          return;
        }

        // Critical trust-boundary fix: the observer is derived from the
        // authenticated user and a device they actually own. The body can no
        // longer nominate an arbitrary observer device.
        if (!observerDeviceId || !getUserDevice(db, authed.sub, observerDeviceId)) {
          writeAuditLog(db, { actorId: authed.sub, action: "DEVICE_SPOOF_ATTEMPT", targetType: "device", targetId: observerDeviceId, reasonCode: "observer_not_owned", metadata: { requestId: id, sessionId } });
          finish(403, { error: "observer_device_not_owned", requestId: id });
          return;
        }
        if (observerDeviceId === observedDeviceId) {
          finish(400, { error: "device_cannot_witness_itself", requestId: id });
          return;
        }
        const observedDevice = getDevice(db, observedDeviceId);
        if (!observedDevice) {
          finish(404, { error: "observed_device_not_found", requestId: id });
          return;
        }
        if (observedDevice.user_id === authed.sub) {
          writeAuditLog(db, { actorId: authed.sub, action: "SELF_WITNESS_BLOCKED", targetType: "device", targetId: observedDeviceId, reasonCode: "observer_and_observed_same_user", metadata: { requestId: id, sessionId } });
          finish(403, { error: "self_witness_forbidden", requestId: id });
          return;
        }

        const observerCrypto = getCryptoDevice(db, observerDeviceId);
        const requiresSignedEvidence = process.env.NODE_ENV !== "test";
        if (requiresSignedEvidence) {
          if (!observerCrypto || observerCrypto.status !== "active" || !validString(nonce, 256) ||
              !validString(signature, 256) || !isFreshIsoTimestamp(observationTimestamp)) {
            finish(400, { error: "signed_witness_required", requestId: id });
            return;
          }
          const message = canonicalProof({
            sessionId,
            observerDeviceId,
            observedDeviceId,
            rssi,
            timestamp: observationTimestamp as string,
            nonce: nonce as string,
            observationType: validString(body.observationType, 64) ? body.observationType as string : "ble_proximity",
            protocolVersion: validString(body.protocolVersion, 32) ? body.protocolVersion as string : "1",
          });
          if (!verifyDeviceSignature(observerCrypto.public_key, message, signature as string)) {
            writeAuditLog(db, { actorId: authed.sub, action: "WITNESS_SIGNATURE_INVALID", targetType: "session", targetId: sessionId, reasonCode: "invalid_observation_signature", metadata: { requestId: id, observerDeviceId, observedDeviceId } });
            finish(401, { error: "invalid_witness_signature", requestId: id });
            return;
          }
        }
        try {
          insertWitnessObservation(db, { sessionId, observerDeviceId, observedDeviceId, rssi,
            nonce: validString(nonce, 256) ? nonce as string : null,
            signature: validString(signature, 256) ? signature as string : null,
            observationType: validString(body.observationType, 64) ? body.observationType as string : "ble_proximity",
            protocolVersion: validString(body.protocolVersion, 32) ? body.protocolVersion as string : "1",
            ephemeralId: validString(body.ephemeralId, 128) ? body.ephemeralId as string : null });
        } catch {
          finish(409, { error: "duplicate_witness_observation", requestId: id });
          return;
        }
        finish(201, { recorded: true, signed: requiresSignedEvidence });
        return;
      }

      const attendanceMatch = path.match(/^\/sessions\/([^/]+)\/attendance\/([^/]+)$/);
      if (method === "GET" && attendanceMatch) {
        const [, sessionId, deviceId] = attendanceMatch;
        const session = getSessionById(db, sessionId);
        const device = getDevice(db, deviceId);
        if (!session || !device) {
          finish(404, { error: "not_found", requestId: id });
          return;
        }
        if (session.instructor_id !== authed.sub && device.user_id !== authed.sub) {
          writeAuditLog(db, { actorId: authed.sub, action: "ATTENDANCE_ACCESS_DENIED", targetType: "session", targetId: sessionId, reasonCode: "not_owner_or_subject", metadata: { requestId: id, deviceId } });
          finish(403, { error: "forbidden", requestId: id });
          return;
        }

        const witnessCount = countIndependentWitnesses(db, sessionId, deviceId);
        const record: SessionRecord = {
          sessionId,
          studentId: device.user_id,
          deviceId,
          witnessedBy: Array.from({ length: witnessCount }, (_, i) => `w${i}`),
          pulseScore: null,
          livenessPingSent: false,
          livenessPingAnsweredMs: null,
        };
        finish(200, {
          sessionId,
          deviceId,
          witnessCount,
          outcome: hasQuorum(record) && witnessCount >= QUORUM_MIN_WITNESSES ? "present" : "absent",
        });
        return;
      }

      const riskMatch = path.match(/^\/sessions\/([^/]+)\/risk\/([^/]+)$/);
      if (method === "POST" && riskMatch) {
        const [, sessionId, studentId] = riskMatch;
        const session = getSessionById(db, sessionId);
        const student = findUserById(db, studentId);
        if (!session || !student) {
          finish(404, { error: "not_found", requestId: id });
          return;
        }
        if (session.instructor_id !== authed.sub) {
          writeAuditLog(db, { actorId: authed.sub, action: "SESSION_ACCESS_DENIED", targetType: "session", targetId: sessionId, reasonCode: "not_session_owner", metadata: { requestId: id } });
          finish(403, { error: "not_your_session", requestId: id });
          return;
        }

        // Never accept risk evidence from the client. Every signal below is
        // loaded from server-owned persistence.
        const devices = getUserDevices(db, studentId);
        const primaryDevice = devices[0];
        if (!primaryDevice) {
          finish(404, { error: "student_device_not_found", requestId: id });
          return;
        }

        const witnessCount = countIndependentWitnesses(db, sessionId, primaryDevice.id);
        const engagement = getEngagementScore(db, studentId, sessionId);
        const liveness = getLivenessEvent(db, studentId, sessionId);
        const pairStats = getPairStatsForDevice(db, primaryDevice.id) as HistoricalPairStats[];
        const answeredMs =
          liveness?.answeredAt && liveness.sentAt
            ? Math.max(0, Date.parse(liveness.answeredAt) - Date.parse(liveness.sentAt))
            : null;

        const record: SessionRecord = {
          sessionId,
          studentId,
          deviceId: primaryDevice.id,
          witnessedBy: Array.from({ length: witnessCount }, (_, i) => `w${i}`),
          pulseScore: engagement,
          livenessPingSent: Boolean(liveness),
          livenessPingAnsweredMs: answeredMs,
        };

        const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
        const decision = decideEscalation(
          record,
          pairStats,
          countRecentRiskAssessments(db, studentId, weekAgo),
        );
        upsertRiskAssessment(db, {
          sessionId,
          studentId,
          riskScore: decision.riskScore,
          reasons: decision.reasons,
        });
        finish(200, { ...decision, evidence: { witnessCount, engagementScore: engagement, livenessRecorded: Boolean(liveness), pairSignals: pairStats.length } });
        return;
      }

      const dashboardMatch = path.match(/^\/sessions\/([^/]+)\/dashboard$/);
      if (method === "GET" && dashboardMatch) {
        const sessionId = dashboardMatch[1];
        const session = getSessionById(db, sessionId);
        if (!session) {
          finish(404, { error: "session_not_found", requestId: id });
          return;
        }
        if (session.instructor_id !== authed.sub) {
          finish(403, { error: "not_your_session", requestId: id });
          return;
        }

        const witnessSummary = getSessionWitnessSummary(db, sessionId);
        const riskRows = getSessionRiskAssessments(db, sessionId);
        const riskByStudent = new Map(riskRows.map((r) => [r.student_id, r]));

        const students = witnessSummary.map((w) => {
          const present = w.witness_count >= QUORUM_MIN_WITNESSES;
          const device = getDevice(db, w.observed_device_id);
          const risk = device ? riskByStudent.get(device.user_id) : undefined;
          return {
            deviceId: w.observed_device_id,
            witnessCount: w.witness_count,
            outcome: present ? "present" : "absent",
            riskScore: risk?.risk_score ?? null,
            riskReasons: risk ? (JSON.parse(risk.reasons_json) as string[]) : [],
          };
        });

        finish(200, {
          session,
          generatedAt: new Date().toISOString(),
          presentCount: students.filter((s) => s.outcome === "present").length,
          absentCount: students.filter((s) => s.outcome === "absent").length,
          students,
        });
        return;
      }

      finish(404, { error: "not_found", requestId: id });
    } catch (error) {
      const safe = errorResponse(error);
      logEvent({
        requestId: id,
        method,
        path,
        status: safe.status,
        error: error instanceof Error ? error.message : "unknown_error",
        durationMs: Date.now() - started,
      });
      finish(safe.status, { error: safe.error, requestId: id });
    }
  });
}

const RED = "\x1b[31m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

function printBanner(port: number): void {
  console.log(`
${RED}${BOLD}   _____ __  __ ___ __  ______
  / ___// / / /   /  |/  /  _/ / __ \\
  \\__ \\/ /_/ / /| / /|_/ // /  / / / /
 ___/ / __  / ___ / /  / // /__/ /_/ /
/____/_/ /_/_/  |/_/  /_/___/_____/${RESET}
${DIM}       [ R E D   H A T   E D I T I O N ]${RESET}

${RED}◆${RESET} witness quorum ......... armed
${RED}◆${RESET} server-owned evidence .. enforced
${RED}◆${RESET} refresh rotation ........ armed
${DIM}  hunting for impersonation —
  every risk flag remains a review signal, not a verdict.${RESET}

  ${BOLD}http://localhost:${port}${RESET}
`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const port = Number(process.env.PORT ?? 3000);
  const server = createShahidServer(process.env.SHAHID_DB_PATH ?? ":memory:");
  server.listen(port, () => printBanner(port));
  const shutdown = () => {
    server.close(() => {
      closeDb();
      process.exit(0);
    });
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
