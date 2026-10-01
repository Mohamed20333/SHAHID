import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";

export function normalizePublicKey(input: string): string {
  if (typeof input !== "string" || input.length > 4096) throw new Error("invalid_public_key");
  const key = createPublicKey(input);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("unsupported_device_key");
  return key.export({ type: "spki", format: "pem" }).toString();
}

export function verifyDeviceSignature(publicKey: string, message: string, signatureBase64Url: string): boolean {
  try {
    const key = createPublicKey(publicKey);
    if (key.asymmetricKeyType !== "ed25519") return false;
    const signature = Buffer.from(signatureBase64Url, "base64url");
    if (signature.length !== 64) return false;
    return verify(null, Buffer.from(message, "utf8"), key, signature);
  } catch {
    return false;
  }
}

export function canonicalProof(fields: Record<string, string | number | null>): string {
  return Object.keys(fields).sort().map((key) => {
    const value = fields[key];
    return `${key}=${value === null ? "" : String(value)}`;
  }).join("&");
}

export function makeNonce(): string {
  return randomBytes(32).toString("base64url");
}

export function keyFingerprint(publicKey: string): string {
  return createHash("sha256").update(normalizePublicKey(publicKey)).digest("hex").slice(0, 32);
}

export function isFreshIsoTimestamp(value: unknown, maxAgeMs = 90_000): boolean {
  if (typeof value !== "string") return false;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return false;
  return Math.abs(Date.now() - parsed) <= maxAgeMs;
}
