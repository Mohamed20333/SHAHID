import { generateKeyPairSync, sign } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalProof, keyFingerprint, normalizePublicKey, verifyDeviceSignature } from "./shahid-device-crypto";

test("Ed25519 canonical proof verifies and tampering fails",()=>{
 const {publicKey,privateKey}=generateKeyPairSync("ed25519");
 const pem=publicKey.export({type:"spki",format:"pem"}).toString();
 const message=canonicalProof({sessionId:"s1",deviceId:"d1",nonce:"n1",timestamp:"2026-10-01T10:00:00.000Z"});
 const sig=sign(null,Buffer.from(message),privateKey).toString("base64url");
 assert.equal(verifyDeviceSignature(pem,message,sig),true);
 assert.equal(verifyDeviceSignature(pem,message+"&tampered=1",sig),false);
 assert.equal(normalizePublicKey(pem).includes("BEGIN PUBLIC KEY"),true);
 assert.equal(keyFingerprint(pem).length,32);
});
