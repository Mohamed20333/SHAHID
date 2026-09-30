import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { getDb } from "./shahid-db";
import { hashPassword, verifyPassword, signJwt, verifyJwt } from "./shahid-auth";
import { hasQuorum, decideEscalation, type SessionRecord, type HistoricalPairStats } from "./shahid-escalation-logic";
import { insertUser, findUserByEmail, insertSession, insertWitnessObservation, countIndependentWitnesses, upsertRiskAssessment, ensureDevice, getSessionWitnessSummary, getSessionRiskAssessments, getSessionById } from "./shahid-db";

const JWT_SECRET =
  process.env.SHAHID_JWT_SECRET ??
  (process.env.NODE_ENV === "production"
    ? (() => { throw new Error("SHAHID_JWT_SECRET must be set in production"); })()
    : "local-development-secret-change-me");
const QUORUM_MIN_WITNESSES = 4;

function readJsonBody(req: IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      if (!raw) return resolve({});
      try { resolve(JSON.parse(raw)); } catch { reject(new Error("invalid_json_body")); }
    });
  });
}

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json", ...CORS_HEADERS });
  res.end(JSON.stringify(body));
}

interface AuthedUser { sub: string; role: string; }

function requireAuth(req: IncomingMessage): AuthedUser | null {
  const header = req.headers["authorization"];
  if (!header || !header.startsWith("Bearer ")) return null;
  const payload = verifyJwt(header.slice("Bearer ".length), JWT_SECRET);
  return payload ? { sub: payload.sub, role: payload.role } : null;
}

const rateBuckets = new Map<string, { count: number; windowStart: number }>();
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 120;

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const bucket = rateBuckets.get(ip);
  if (!bucket || now - bucket.windowStart > RATE_LIMIT_WINDOW_MS) {
    rateBuckets.set(ip, { count: 1, windowStart: now });
    return false;
  }
  bucket.count += 1;
  return bucket.count > RATE_LIMIT_MAX;
}

function log(method: string, path: string, status: number, ms: number): void {
  console.log(JSON.stringify({ ts: new Date().toISOString(), method, path, status, ms }));
}

export function createShahidServer(dbPath: string = ":memory:") {
  const db = getDb(dbPath);

  return createServer(async (req, res) => {
    const start = Date.now();
    const ip = req.socket.remoteAddress ?? "unknown";
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const method = req.method ?? "GET";
    const finish = (status: number, body: unknown) => {
      sendJson(res, status, body);
      log(method, path, status, Date.now() - start);
    };

    if (method === "OPTIONS") {
      res.writeHead(204, CORS_HEADERS);
      res.end();
      return;
    }
    if (isRateLimited(ip)) return finish(429, { error: "rate_limited" });

    try {
      if (method === "POST" && path === "/auth/register") {
        const body = await readJsonBody(req);
        const { role, fullName, email, password } = body;
        if (!role || !fullName || !email || !password) return finish(400, { error: "missing_fields", required: ["role", "fullName", "email", "password"] });
        if (findUserByEmail(db, email)) return finish(409, { error: "email_already_registered" });
        const user = insertUser(db, { role, fullName, email, passwordHash: hashPassword(password) });
        return finish(201, { id: user.id, role: user.role, email: user.email });
      }

      if (method === "POST" && path === "/auth/login") {
        const body = await readJsonBody(req);
        const user = findUserByEmail(db, body.email);
        if (!user || !verifyPassword(body.password, user.password_hash)) return finish(401, { error: "invalid_credentials" });
        const accessToken = signJwt({ sub: user.id, role: user.role }, JWT_SECRET, 15 * 60);
        const refreshToken = signJwt({ sub: user.id, role: user.role, type: "refresh" }, JWT_SECRET, 7 * 24 * 60 * 60);
        return finish(200, { accessToken, refreshToken, role: user.role });
      }

      const authed = requireAuth(req);
      if (!authed) return finish(401, { error: "unauthenticated" });

      if (method === "POST" && path === "/devices/enroll") {
        const body = await readJsonBody(req);
        if (!body.hardwareAttestationId) return finish(400, { error: "missing_hardwareAttestationId" });
        return finish(200, { deviceId: ensureDevice(db, authed.sub, body.hardwareAttestationId) });
      }

      if (method === "POST" && path === "/sessions") {
        if (authed.role !== "professor") return finish(403, { error: "forbidden_role" });
        return finish(201, insertSession(db, authed.sub));
      }

      const witnessMatch = path.match(/^\/sessions\/([^/]+)\/witnesses$/);
      if (method === "POST" && witnessMatch) {
        const sessionId = witnessMatch[1];
        const body = await readJsonBody(req);
        if (!body.observerDeviceId || !body.observedDeviceId || typeof body.rssi !== "number") return finish(400, { error: "missing_fields", required: ["observerDeviceId", "observedDeviceId", "rssi"] });
        if (body.observerDeviceId === body.observedDeviceId) return finish(400, { error: "device_cannot_witness_itself" });
        insertWitnessObservation(db, { sessionId, observerDeviceId: body.observerDeviceId, observedDeviceId: body.observedDeviceId, rssi: body.rssi });
        return finish(201, { recorded: true });
      }

      const attendanceMatch = path.match(/^\/sessions\/([^/]+)\/attendance\/([^/]+)$/);
      if (method === "GET" && attendanceMatch) {
        const [, sessionId, deviceId] = attendanceMatch;
        const witnessCount = countIndependentWitnesses(db, sessionId, deviceId);
        const record: SessionRecord = { sessionId, studentId: deviceId, deviceId, witnessedBy: Array.from({ length: witnessCount }, (_, i) => `w${i}`), pulseScore: null, livenessPingSent: false, livenessPingAnsweredMs: null };
        return finish(200, { sessionId, deviceId, witnessCount, outcome: hasQuorum(record) && witnessCount >= QUORUM_MIN_WITNESSES ? "present" : "absent" });
      }

      const riskMatch = path.match(/^\/sessions\/([^/]+)\/risk\/([^/]+)$/);
      if (method === "POST" && riskMatch) {
        const [, sessionId, studentId] = riskMatch;
        const body = await readJsonBody(req);
        const witnessCount = countIndependentWitnesses(db, sessionId, body.deviceId ?? "");
        const record: SessionRecord = { sessionId, studentId, deviceId: body.deviceId ?? "", witnessedBy: Array.from({ length: witnessCount }, (_, i) => `w${i}`), pulseScore: body.pulseScore ?? null, livenessPingSent: body.livenessPingSent ?? false, livenessPingAnsweredMs: body.livenessPingAnsweredMs ?? null };
        const decision = decideEscalation(record, (body.pairStats ?? []) as HistoricalPairStats[], body.escalationsThisWeek ?? 0);
        upsertRiskAssessment(db, { sessionId, studentId, riskScore: decision.riskScore, reasons: decision.reasons });
        return finish(200, decision);
      }

      const dashboardMatch = path.match(/^\/sessions\/([^/]+)\/dashboard$/);
      if (method === "GET" && dashboardMatch) {
        const sessionId = dashboardMatch[1];
        const session = getSessionById(db, sessionId);
        if (!session) return finish(404, { error: "session_not_found" });
        if (session.instructor_id !== authed.sub) return finish(403, { error: "not_your_session" });
        const witnessSummary = getSessionWitnessSummary(db, sessionId);
        const riskRows = getSessionRiskAssessments(db, sessionId);
        const riskByStudent = new Map(riskRows.map((r) => [r.student_id, r]));
        const students = witnessSummary.map((w) => {
          const present = w.witness_count >= QUORUM_MIN_WITNESSES;
          const risk = riskByStudent.get(w.observed_device_id);
          return { deviceId: w.observed_device_id, witnessCount: w.witness_count, outcome: present ? "present" : "absent", riskScore: risk ? risk.risk_score : null, riskReasons: risk ? (JSON.parse(risk.reasons_json) as string[]) : [] };
        });
        return finish(200, { session, generatedAt: new Date().toISOString(), presentCount: students.filter((s) => s.outcome === "present").length, absentCount: students.filter((s) => s.outcome === "absent").length, students });
      }

      return finish(404, { error: "not_found" });
    } catch (err) {
      return finish(500, { error: "internal_error", message: err instanceof Error ? err.message : "unknown_error" });
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
${RED}◆${RESET} knowledge pulse ........ armed
${RED}◆${RESET} risk scoring ............ live
${DIM}  hunting for impersonation, not students —
  every flag is a pattern, not a verdict.${RESET}

  ${BOLD}http://localhost:${port}${RESET}
`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const port = Number(process.env.PORT ?? 3000);
  createShahidServer(process.env.SHAHID_DB_PATH ?? ":memory:").listen(port, () => printBanner(port));
}