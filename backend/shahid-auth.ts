/**
 * SHAHID — Authentication primitives.
 *
 * Security properties:
 * - Passwords use salted scrypt.
 * - Access JWTs are short-lived and explicitly typed as "access".
 * - Refresh credentials are opaque, random, one-time-use tokens stored only
 *   as SHA-256 hashes in the database. This avoids long-lived bearer JWTs.
 * - JWT verification is fixed to HS256; issuer and audience are validated.
 */

import {
  createHash,
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";

const SCRYPT_KEYLEN = 64;
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };
const JWT_ISSUER = "shahid";
const JWT_AUDIENCE = "shahid-api";

export interface JwtPayload {
  sub: string;
  role: string;
  typ: "access";
  iss: string;
  aud: string;
  exp: number;
  iat: number;
  jti: string;
  [key: string]: unknown;
}

export function hashPassword(plain: string): string {
  if (plain.length < 12 || plain.length > 128) {
    throw new Error("password_policy_violation");
  }
  const salt = randomBytes(16);
  const derived = scryptSync(plain, salt, SCRYPT_KEYLEN, SCRYPT_OPTIONS);
  return `${salt.toString("hex")}:${derived.toString("hex")}`;
}

export function verifyPassword(plain: string, stored: string): boolean {
  try {
    const [saltHex, hashHex] = stored.split(":");
    if (!saltHex || !hashHex || saltHex.length !== 32 || hashHex.length !== 128) return false;
    const salt = Buffer.from(saltHex, "hex");
    const expected = Buffer.from(hashHex, "hex");
    const actual = scryptSync(plain, salt, SCRYPT_KEYLEN);
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

export function signAccessJwt(
  payload: { sub: string; role: string },
  secret: string,
  expiresInSeconds = 15 * 60,
): string {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "HS256", typ: "JWT" };
  const fullPayload: JwtPayload = {
    ...payload,
    typ: "access",
    iss: JWT_ISSUER,
    aud: JWT_AUDIENCE,
    iat: now,
    exp: now + expiresInSeconds,
    jti: randomBytes(16).toString("hex"),
  };
  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(fullPayload));
  const signature = createHmac("sha256", secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest("base64url");
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

export function verifyAccessJwt(token: string, secret: string): JwtPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [encodedHeader, encodedPayload, signature] = parts;
    const expectedSig = createHmac("sha256", secret)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest("base64url");
    const sigBuf = Buffer.from(signature);
    const expectedBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) return null;

    const header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString()) as { alg?: string; typ?: string };
    const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString()) as JwtPayload;

    const now = Math.floor(Date.now() / 1000);
    if (header.alg !== "HS256" || header.typ !== "JWT") return null;
    if (payload.typ !== "access" || payload.iss !== JWT_ISSUER || payload.aud !== JWT_AUDIENCE) return null;
    if (typeof payload.sub !== "string" || typeof payload.role !== "string") return null;
    if (!Number.isInteger(payload.exp) || payload.exp <= now) return null;
    if (!Number.isInteger(payload.iat) || payload.iat > now + 30) return null;
    if (typeof payload.jti !== "string" || payload.jti.length < 16) return null;

    return payload;
  } catch {
    return null;
  }
}

export function createRefreshToken(): { token: string; hash: string } {
  const token = randomBytes(48).toString("base64url");
  return { token, hash: hashRefreshToken(token) };
}

export function hashRefreshToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}
