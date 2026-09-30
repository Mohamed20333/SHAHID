/**
 * Shahid — Auth primitives (password hashing + JWT)
 * -----------------------------------------------------
 * HONESTY NOTE, read before reusing this in real deployment:
 * This sandbox has no outbound network access, so `npm install jsonwebtoken
 * bcryptjs` etc. is not possible here (verified — registry requests return
 * 403). Everything below is built ONLY on Node's built-in `crypto` module,
 * which ships with Node itself and needed no install. It is real,
 * cryptographically sound code — not a mock — but hand-rolling JWT is
 * something you should STOP doing the moment you're in an environment
 * where `npm install jsonwebtoken` actually works. Swap it in then; keep
 * this version only for environments (like this one) where it's the only
 * option. The `signJwt`/`verifyJwt` pair below is deliberately minimal
 * (HS256 only, no algorithm negotiation) specifically to avoid the classic
 * "alg:none" / algorithm-confusion attack class that hand-rolled or
 * poorly-configured JWT libraries are historically vulnerable to.
 */

import { randomBytes, scryptSync, timingSafeEqual, createHmac } from "node:crypto";

const SCRYPT_KEYLEN = 64;

export function hashPassword(plain: string): string {
  const salt = randomBytes(16);
  const derived = scryptSync(plain, salt, SCRYPT_KEYLEN);
  return `${salt.toString("hex")}:${derived.toString("hex")}`;
}

export function verifyPassword(plain: string, stored: string): boolean {
  const [saltHex, hashHex] = stored.split(":");
  if (!saltHex || !hashHex) return false;
  const salt = Buffer.from(saltHex, "hex");
  const expected = Buffer.from(hashHex, "hex");
  const actual = scryptSync(plain, salt, SCRYPT_KEYLEN);
  if (actual.length !== expected.length) return false;
  return timingSafeEqual(actual, expected);
}

export interface JwtPayload {
  sub: string;
  role: string;
  exp: number;
  [key: string]: unknown;
}

function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

export function signJwt(
  payload: { sub: string; role: string; [key: string]: unknown },
  secret: string,
  expiresInSeconds: number
): string {
  const header = { alg: "HS256", typ: "JWT" };
  const fullPayload: JwtPayload = { ...payload, exp: Math.floor(Date.now() / 1000) + expiresInSeconds };
  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(fullPayload));
  const signature = createHmac("sha256", secret).update(`${encodedHeader}.${encodedPayload}`).digest("base64url");
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

export function verifyJwt(token: string, secret: string): JwtPayload | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [encodedHeader, encodedPayload, signature] = parts;

  const expectedSig = createHmac("sha256", secret).update(`${encodedHeader}.${encodedPayload}`).digest("base64url");
  const sigBuf = Buffer.from(signature);
  const expectedBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) {
    return null;
  }

  let header: { alg?: string };
  let payload: JwtPayload;
  try {
    header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString());
    payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString());
  } catch {
    return null;
  }

  if (header.alg !== "HS256") return null;
  if (typeof payload.exp !== "number" || payload.exp < Math.floor(Date.now() / 1000)) return null;

  return payload;
}