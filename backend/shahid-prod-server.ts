import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Pool } from "pg";
import { createClient } from "redis";
import {
  createRefreshToken,
  hashPassword,
  hashRefreshToken,
  signAccessJwt,
  verifyAccessJwt,
  verifyPassword,
} from "./shahid-auth";
import { canonicalProof, isFreshIsoTimestamp, keyFingerprint, normalizePublicKey, verifyDeviceSignature } from "./shahid-device-crypto";
import { assessRisk } from "./shahid-risk";

const PORT = Number(process.env.PORT ?? 8080);
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.SHAHID_JWT_SECRET ?? "";
if (!DATABASE_URL) throw new Error("DATABASE_URL is required");
if (!JWT_SECRET) throw new Error("SHAHID_JWT_SECRET is required");

const pool = new Pool({ connectionString: DATABASE_URL, max: Number(process.env.DB_POOL_MAX ?? 20) });
const redis = process.env.REDIS_URL ? createClient({ url: process.env.REDIS_URL }) : null;
const origins = new Set((process.env.SHAHID_ALLOWED_ORIGINS ?? "").split(",").map(x => x.trim()).filter(Boolean));
const ACCESS_SECONDS = 15 * 60;
const REFRESH_DAYS = 7;
const MAX_BODY = 64 * 1024;

type User = { id:string; role:string; full_name:string; email:string; password_hash:string; university_id:string };

async function init() {
  if (redis) { try { await redis.connect(); } catch { console.warn("Redis unavailable; refusing distributed rate-limit claims"); } }
  await pool.query("SELECT 1");
}

function headers(req: IncomingMessage) {
  const origin = req.headers.origin;
  const h: Record<string,string> = {
    "Content-Type":"application/json; charset=utf-8",
    "Cache-Control":"no-store",
    "X-Content-Type-Options":"nosniff",
    "Referrer-Policy":"no-referrer",
    "X-Frame-Options":"DENY",
    "Content-Security-Policy":"default-src 'none'; frame-ancestors 'none'",
    "Permissions-Policy":"geolocation=(), microphone=(), camera=()",
    "Access-Control-Allow-Methods":"GET,POST,OPTIONS",
    "Access-Control-Allow-Headers":"Content-Type,Authorization,X-Device-ID",
    "Access-Control-Allow-Credentials":"true",
    "Vary":"Origin",
  };
  if (origin && origins.has(origin)) h["Access-Control-Allow-Origin"]=origin;
  return h;
}
function send(res:ServerResponse, req:IncomingMessage, status:number, body:unknown, extra:Record<string,string>={}) {
  res.writeHead(status,{...headers(req),...extra}); res.end(status===204 ? undefined : JSON.stringify(body));
}
async function body(req:IncomingMessage):Promise<any> {
  const ct=String(req.headers["content-type"]??"").split(";")[0].trim();
  if(ct!=="application/json") throw new Error("unsupported_media_type");
  return await new Promise((resolve,reject)=>{
    let raw="", n=0, done=false;
    const fail=(e:Error)=>{if(done)return;done=true;reject(e);};
    req.on("data",(chunk:Buffer)=>{n+=chunk.length;if(n>MAX_BODY)return fail(new Error("payload_too_large"));raw+=chunk.toString("utf8");});
    req.on("end",()=>{if(done)return;done=true;try{const v=JSON.parse(raw||"{}");if(!v||typeof v!=="object"||Array.isArray(v))throw 0;resolve(v);}catch{reject(new Error("invalid_json_body"));}});
    req.on("error",()=>fail(new Error("request_error")));
  });
}
function cookie(name:string,value:string,maxAge:number){return `${name}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Strict`;}
function parseCookies(req:IncomingMessage){return Object.fromEntries(String(req.headers.cookie??"").split(";").map(x=>x.trim().split("=")).filter(x=>x.length===2));}
function auth(req:IncomingMessage){const h=req.headers.authorization;if(!h?.startsWith("Bearer "))return null;const p=verifyAccessJwt(h.slice(7),JWT_SECRET);return p?{id:p.sub,role:p.role}:null;}
async function limited(key:string,max:number,windowSec=60){
  if(redis?.isReady){const k=`rl:${key}`;const n=await redis.incr(k);if(n===1)await redis.expire(k,windowSec);return n>max;}
  return false;
}
function failCode(e:unknown):[number,string]{const m=e instanceof Error?e.message:"";if(m==="payload_too_large")return[413,"payload_too_large"];if(m==="unsupported_media_type")return[415,m];if(m==="invalid_json_body")return[400,m];return[500,"internal_error"];}
async function audit(actorId:string|null,action:string,targetTable:string,targetId:string,reason:string,metadata={}) {
  await pool.query("INSERT INTO audit_log(university_id,actor_id,action,target_table,target_id,reason_code,metadata) VALUES((SELECT university_id FROM users WHERE id=$1),$1,$2,$3,$4,$5,$6)",[actorId,action,targetTable,targetId,reason,metadata]);
}
function requireRole(u:{role:string},...roles:string[]){return roles.includes(u.role);}

const server=createServer(async(req,res)=>{
  const requestId=randomUUID();
  try{
    if(req.method==="OPTIONS"){send(res,req,204,null);return;}
    const url=new URL(req.url??"/","http://localhost");
    const path=url.pathname, method=req.method??"GET";
    if(await limited(`ip:${req.socket.remoteAddress??"unknown"}`,120)){send(res,req,429,{error:"rate_limited",requestId});return;}

    if(method==="GET"&&path==="/health"){const r=await pool.query("SELECT 1 AS ok");send(res,req,200,{status:"ok",database:r.rows[0].ok===1,requestId});return;}

    if(method==="POST"&&path==="/auth/register"){
      if(await limited(`register:${req.socket.remoteAddress??"unknown"}`,5)){send(res,req,429,{error:"rate_limited",requestId});return;}
      const b=await body(req);
      if(typeof b.fullName!=="string"||typeof b.email!=="string"||typeof b.password!=="string"||b.password.length<12||b.password.length>128||b.role&&b.role!=="student"||typeof b.universityId!=="string"){send(res,req,400,{error:"invalid_registration",requestId});return;}
      const exists=await pool.query("SELECT 1 FROM users WHERE university_id=$1 AND email=$2",[b.universityId,b.email.trim().toLowerCase()]);
      if(exists.rowCount){send(res,req,409,{error:"email_already_registered",requestId});return;}
      const id=randomUUID(); await pool.query("INSERT INTO users(id,university_id,role,full_name,email,password_hash) VALUES($1,$2,'student',$3,$4,$5)",[id,b.universityId,b.fullName.trim(),b.email.trim().toLowerCase(),hashPassword(b.password)]);
      send(res,req,201,{id,role:"student"});return;
    }

    if(method==="POST"&&path==="/auth/login"){
      if(await limited(`login:${req.socket.remoteAddress??"unknown"}`,10)){send(res,req,429,{error:"rate_limited",requestId});return;}
      const b=await body(req); if(typeof b.email!=="string"||typeof b.password!=="string"){send(res,req,401,{error:"invalid_credentials",requestId});return;}
      const q=await pool.query<User>("SELECT id,role,full_name,email,password_hash,university_id FROM users WHERE email=$1 LIMIT 1",[b.email.trim().toLowerCase()]);
      const u=q.rows[0]; if(!u||!verifyPassword(b.password,u.password_hash)){send(res,req,401,{error:"invalid_credentials",requestId});return;}
      const accessToken=signAccessJwt({sub:u.id,role:u.role},JWT_SECRET,ACCESS_SECONDS); const refresh=createRefreshToken();
      const family=randomUUID(); await pool.query("INSERT INTO refresh_tokens(id,user_id,token_hash,family_id,created_at,expires_at) VALUES($1,$2,$3,$4,now(),now()+interval '7 days')",[randomUUID(),u.id,refresh.hash,family]);
      send(res,req,200,{accessToken,expiresIn:ACCESS_SECONDS,role:u.role}, {"Set-Cookie":cookie("shahid_refresh",refresh.token,REFRESH_DAYS*86400)});return;
    }

    if(method==="POST"&&path==="/auth/refresh"){
      const b=await body(req); const token=typeof b.refreshToken==="string"?b.refreshToken:parseCookies(req).shahid_refresh;
      if(!token){send(res,req,401,{error:"invalid_refresh_token",requestId});return;}
      const q=await pool.query<any>("SELECT * FROM refresh_tokens WHERE token_hash=$1 LIMIT 1",[hashRefreshToken(token)]);const old=q.rows[0];
      if(!old||old.revoked_at||new Date(old.expires_at)<=new Date()){if(old)await pool.query("UPDATE refresh_tokens SET revoked_at=now() WHERE family_id=$1",[old.family_id]);send(res,req,401,{error:"invalid_refresh_token",requestId});return;}
      const u=(await pool.query<User>("SELECT id,role,full_name,email,password_hash,university_id FROM users WHERE id=$1",[old.user_id])).rows[0];
      if(!u){send(res,req,401,{error:"invalid_refresh_token",requestId});return;}
      const next=createRefreshToken(), nextId=randomUUID(); await pool.query("BEGIN"); try{
        await pool.query("INSERT INTO refresh_tokens(id,user_id,token_hash,family_id,created_at,expires_at) VALUES($1,$2,$3,$4,now(),now()+interval '7 days')",[nextId,u.id,next.hash,old.family_id]);
        await pool.query("UPDATE refresh_tokens SET revoked_at=now(),replaced_by=$1 WHERE id=$2 AND revoked_at IS NULL",[nextId,old.id]); await pool.query("COMMIT");
      }catch(e){await pool.query("ROLLBACK");throw e;}
      send(res,req,200,{accessToken:signAccessJwt({sub:u.id,role:u.role},JWT_SECRET,ACCESS_SECONDS),expiresIn:ACCESS_SECONDS,role:u.role},{"Set-Cookie":cookie("shahid_refresh",next.token,REFRESH_DAYS*86400)});return;
    }

    const u=auth(req); if(!u){send(res,req,401,{error:"unauthenticated",requestId});return;}

    if(method==="POST"&&path==="/auth/logout"){const b=await body(req);const t=typeof b.refreshToken==="string"?b.refreshToken:parseCookies(req).shahid_refresh;if(t)await pool.query("UPDATE refresh_tokens SET revoked_at=now() WHERE token_hash=$1",[hashRefreshToken(t)]);send(res,req,204,null,{"Set-Cookie":cookie("shahid_refresh","",0)});return;}

    if(method==="POST"&&path==="/devices/enroll/challenge"){
      const b=await body(req);if(typeof b.publicKey!=="string"||typeof b.keyId!=="string"){send(res,req,400,{error:"invalid_device_key",requestId});return;}
      const pk=normalizePublicKey(b.publicKey), challengeId=randomUUID(),nonce=randomBytes(32).toString("base64url");
      await pool.query("INSERT INTO device_challenges(id,user_id,public_key,key_id,purpose,nonce,expires_at) VALUES($1,$2,$3,$4,'device_enrollment',$5,now()+interval '2 minutes')",[challengeId,u.id,pk,b.keyId,nonce]);
      send(res,req,200,{challengeId,nonce,expiresAt:new Date(Date.now()+120000).toISOString(),keyId:b.keyId});return;
    }

    if(method==="POST"&&path==="/devices/enroll/complete"){
      const b=await body(req);const q=await pool.query<any>("SELECT * FROM device_challenges WHERE id=$1",[b.challengeId]);const c=q.rows[0];
      if(!c||c.user_id!==u.id||c.purpose!=="device_enrollment"||c.consumed_at||new Date(c.expires_at)<=new Date()||typeof b.signature!=="string"){send(res,req,401,{error:"invalid_device_proof",requestId});return;}
      const msg=canonicalProof({challengeId:c.id,nonce:c.nonce,purpose:c.purpose,keyId:c.key_id});
      if(!verifyDeviceSignature(c.public_key,msg,b.signature)){await audit(u.id,"DEVICE_SIGNATURE_INVALID","device_challenge",c.id,"enrollment_signature_failed",{requestId});send(res,req,401,{error:"invalid_device_proof",requestId});return;}
      const claimed=await pool.query("UPDATE device_challenges SET consumed_at=now() WHERE id=$1 AND consumed_at IS NULL",[c.id]);if(!claimed.rowCount){send(res,req,409,{error:"challenge_replayed",requestId});return;}
      const existing=await pool.query<any>("SELECT id,user_id FROM devices WHERE key_id=$1",[c.key_id]);if(existing.rowCount&&existing.rows[0].user_id!==u.id){send(res,req,409,{error:"device_key_conflict",requestId});return;}
      const deviceId=existing.rowCount?existing.rows[0].id:randomUUID();
      if(!existing.rowCount) await pool.query("INSERT INTO devices(id,user_id,device_enrollment_key_hash,public_key,key_id,key_algorithm,status) VALUES($1,$2,$3,$4,$5,'Ed25519','active')",[deviceId,u.id,randomUUID(),c.public_key,c.key_id]);
      send(res,req,201,{deviceId,keyId:c.key_id,algorithm:"Ed25519"});return;
    }

    const beaconMatch=path.match(/^\/sessions\/([^/]+)\/beacon$/);
    if(method==="POST"&&beaconMatch){
      if(!requireRole(u,"student")){send(res,req,403,{error:"forbidden_role",requestId});return;}
      const sessionId=beaconMatch[1], b=await body(req);
      const d=(await pool.query<any>("SELECT id FROM devices WHERE id=$1 AND user_id=$2 AND status='active'",[b.deviceId,u.id])).rows[0];
      const active=(await pool.query("SELECT 1 FROM class_sessions cs JOIN enrollments e ON e.section_id=cs.section_id WHERE cs.id=$1 AND cs.status='active' AND e.student_id=$2",[sessionId,u.id])).rowCount;
      if(!d||!active){send(res,req,403,{error:"session_or_device_not_authorized",requestId});return;}
      const ephemeralId=randomBytes(16).toString("base64url");
      const hash=createHash("sha256").update(ephemeralId).digest("hex");
      await pool.query("INSERT INTO session_beacons(session_id,device_id,ephemeral_id_hash,expires_at) VALUES($1,$2,$3,now()+interval '10 minutes') ON CONFLICT(session_id,device_id) DO UPDATE SET ephemeral_id_hash=EXCLUDED.ephemeral_id_hash,created_at=now(),expires_at=EXCLUDED.expires_at",[sessionId,d.id,hash]);
      send(res,req,200,{sessionId,deviceId:d.id,ephemeralId,expiresAt:new Date(Date.now()+600000).toISOString()});return;
    }

    const witnessChallengeMatch=path.match(/^\/sessions\/([^/]+)\/witness-challenge$/);
    if(method==="POST"&&witnessChallengeMatch){
      if(!requireRole(u,"student")){send(res,req,403,{error:"forbidden_role",requestId});return;}
      const sessionId=witnessChallengeMatch[1], deviceId=String(req.headers["x-device-id"]??"");
      const d=(await pool.query<any>("SELECT id FROM devices WHERE id=$1 AND user_id=$2 AND status='active'",[deviceId,u.id])).rows[0];
      const active=(await pool.query("SELECT 1 FROM class_sessions WHERE id=$1 AND status='active'",[sessionId])).rowCount;
      if(!d||!active){send(res,req,403,{error:"observer_device_not_authorized",requestId});return;}
      const challengeId=randomUUID(),nonce=randomBytes(32).toString("base64url");
      await pool.query("INSERT INTO witness_challenges(id,session_id,observer_device_id,nonce,expires_at) VALUES($1,$2,$3,$4,now()+interval '60 seconds')",[challengeId,sessionId,d.id,nonce]);
      send(res,req,200,{challengeId,nonce,expiresAt:new Date(Date.now()+60000).toISOString()});return;
    }

    const heartbeatMatch=path.match(/^\/sessions\/([^/]+)\/heartbeat$/);
    if(method==="POST"&&heartbeatMatch){
      if(!requireRole(u,"student")){send(res,req,403,{error:"forbidden_role",requestId});return;}
      const sessionId=heartbeatMatch[1],b=await body(req),d=(await pool.query<any>("SELECT * FROM devices WHERE id=$1 AND user_id=$2 AND status='active'",[b.deviceId,u.id])).rows[0];
      if(!d||!isFreshIsoTimestamp(b.timestamp)||!Number.isInteger(b.sequence)||b.sequence<0){send(res,req,400,{error:"invalid_heartbeat",requestId});return;}
      const active=(await pool.query("SELECT 1 FROM class_sessions WHERE id=$1 AND status='active'",[sessionId])).rowCount;if(!active){send(res,req,404,{error:"session_not_found",requestId});return;}
      const msg=canonicalProof({sessionId,deviceId:d.id,sequence:b.sequence,timestamp:b.timestamp});
      if(typeof b.signature!=="string"||!verifyDeviceSignature(d.public_key,msg,b.signature)){await audit(u.id,"HEARTBEAT_SIGNATURE_INVALID","class_session",sessionId,"invalid_heartbeat_signature",{requestId});send(res,req,401,{error:"invalid_heartbeat",requestId});return;}
      try{await pool.query("INSERT INTO evidence_heartbeats(session_id,device_id,observed_at,sequence,signature) VALUES($1,$2,$3,$4,$5)",[sessionId,d.id,new Date(b.timestamp),b.sequence,b.signature]);}catch{send(res,req,409,{error:"duplicate_heartbeat",requestId});return;}
      send(res,req,201,{recorded:true});return;
    }

    const challengeMatch=path==="/devices/proof-challenge";
    if(method==="POST"&&challengeMatch){
      const b=await body(req);const q=await pool.query<any>("SELECT * FROM devices WHERE id=$1 AND user_id=$2 AND status='active'",[b.deviceId,u.id]);const d=q.rows[0];
      if(!d){send(res,req,403,{error:"device_not_authorized",requestId});return;}
      let sessionId:string|null=null; if(typeof b.sessionId==="string"){sessionId=b.sessionId;const s=await pool.query("SELECT id FROM class_sessions WHERE id=$1 AND status='active'",[sessionId]);if(!s.rowCount){send(res,req,404,{error:"session_not_found",requestId});return;}}
      const challengeId=randomUUID(),nonce=randomBytes(32).toString("base64url"),purpose=sessionId?"session_proof":"device_proof";
      await pool.query("INSERT INTO device_challenges(id,user_id,device_id,public_key,key_id,purpose,session_id,nonce,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()+interval '2 minutes')",[challengeId,u.id,d.id,d.public_key,d.key_id,purpose,sessionId,nonce]);
      send(res,req,200,{challengeId,nonce,purpose,sessionId,expiresAt:new Date(Date.now()+120000).toISOString()});return;
    }

    if(method==="POST"&&/^\/sessions\/[^/]+\/check-in$/.test(path)){
      const sessionId=path.split("/")[2],b=await body(req);const s=await pool.query<any>("SELECT cs.id,se.instructor_id FROM class_sessions cs JOIN sections se ON se.id=cs.section_id WHERE cs.id=$1 AND cs.status='active'",[sessionId]);
      if(!s.rowCount){send(res,req,404,{error:"session_not_found",requestId});return;}
      const d=(await pool.query<any>("SELECT * FROM devices WHERE id=$1 AND user_id=$2 AND status='active'",[b.deviceId,u.id])).rows[0];
      const c=(await pool.query<any>("SELECT * FROM device_challenges WHERE id=$1 AND user_id=$2 AND session_id=$3 AND purpose='session_proof'",[b.challengeId,u.id,sessionId])).rows[0];
      if(!d||!c||c.consumed_at||new Date(c.expires_at)<=new Date()||!isFreshIsoTimestamp(b.timestamp)){send(res,req,401,{error:"invalid_check_in_proof",requestId});return;}
      const msg=canonicalProof({challengeId:c.id,nonce:c.nonce,purpose:c.purpose,sessionId,deviceId:b.deviceId,timestamp:b.timestamp});
      if(typeof b.signature!=="string"||!verifyDeviceSignature(d.public_key,msg,b.signature)){await audit(u.id,"DEVICE_SIGNATURE_INVALID","class_session",sessionId,"check_in_signature_failed",{requestId});send(res,req,401,{error:"invalid_check_in_proof",requestId});return;}
      await pool.query("UPDATE device_challenges SET consumed_at=now() WHERE id=$1 AND consumed_at IS NULL",[c.id]);
      await pool.query("INSERT INTO attendance_records(id,session_id,student_id,device_id,outcome,witness_count,proof_verified) VALUES($1,$2,$3,$4,'present_pending_review',0,true) ON CONFLICT(session_id,student_id) DO UPDATE SET device_id=EXCLUDED.device_id,proof_verified=true,decided_at=now()",[randomUUID(),sessionId,u.id,b.deviceId]);
      send(res,req,201,{status:"checked_in",proofVerified:true});return;
    }

    const witnessMatch=path.match(/^\/sessions\/([^/]+)\/witnesses$/);
    if(method==="POST"&&witnessMatch){
      const sessionId=witnessMatch[1],b=await body(req),deviceId=String(req.headers["x-device-id"]??"");
      const d=(await pool.query<any>("SELECT * FROM devices WHERE id=$1 AND user_id=$2 AND status='active'",[deviceId,u.id])).rows[0];
      const challenge=(await pool.query<any>("SELECT * FROM witness_challenges WHERE id=$1 AND session_id=$2 AND observer_device_id=$3",[b.challengeId,sessionId,deviceId])).rows[0];
      const hash=typeof b.ephemeralId==="string"?createHash("sha256").update(b.ephemeralId).digest("hex"):"";
      const observed=(await pool.query<any>("SELECT d.* FROM session_beacons sb JOIN devices d ON d.id=sb.device_id WHERE sb.session_id=$1 AND sb.ephemeral_id_hash=$2 AND sb.expires_at>now() AND d.status='active'",[sessionId,hash])).rows[0];
      if(!d||!challenge||challenge.consumed_at||new Date(challenge.expires_at)<=new Date()||!observed||observed.user_id===u.id){await audit(u.id,"WITNESS_REJECTED","class_session",sessionId,"observer_challenge_or_beacon_invalid",{requestId});send(res,req,403,{error:"invalid_witness",requestId});return;}
      if(typeof b.signature!=="string"||!isFreshIsoTimestamp(b.timestamp)||typeof b.rssi!=="number"||b.rssi<-127||b.rssi>0){send(res,req,400,{error:"signed_witness_required",requestId});return;}
      const msg=canonicalProof({sessionId,observerDeviceId:d.id,ephemeralId:b.ephemeralId,rssi:b.rssi,timestamp:b.timestamp,nonce:challenge.nonce,observationType:"ble_proximity",protocolVersion:"1"});
      if(!verifyDeviceSignature(d.public_key,msg,b.signature)){await audit(u.id,"WITNESS_SIGNATURE_INVALID","class_session",sessionId,"invalid_observation_signature",{requestId});send(res,req,401,{error:"invalid_witness_signature",requestId});return;}
      const consumed=await pool.query("UPDATE witness_challenges SET consumed_at=now() WHERE id=$1 AND consumed_at IS NULL",[challenge.id]);if(!consumed.rowCount){send(res,req,409,{error:"witness_challenge_replayed",requestId});return;}
      try{await pool.query("INSERT INTO witness_observations(session_id,observer_device_id,observed_device_id,epoch_index,rssi,observed_at,signature,nonce,observation_type,protocol_version,ephemeral_id) VALUES($1,$2,$3,0,$4,$5,$6,$7,'ble_proximity','1',$8)",[sessionId,d.id,observed.id,b.rssi,new Date(b.timestamp),b.signature,challenge.nonce,b.ephemeralId]);}catch{send(res,req,409,{error:"duplicate_witness_observation",requestId});return;}
      send(res,req,201,{recorded:true,signed:true,observedDeviceId:observed.id});return;
    }

    const attMatch=path.match(/^\/sessions\/([^/]+)\/attendance\/([^/]+)$/);
    if(method==="GET"&&attMatch){
      const q=await pool.query<any>("SELECT ar.*,d.user_id,cs.id session_id,se.instructor_id FROM attendance_records ar JOIN devices d ON d.id=ar.device_id JOIN class_sessions cs ON cs.id=ar.session_id JOIN sections se ON se.id=cs.section_id WHERE ar.session_id=$1 AND ar.device_id=$2",[attMatch[1],attMatch[2]]);
      const row=q.rows[0];if(!row){send(res,req,404,{error:"not_found",requestId});return;}
      if(row.instructor_id!==u.id&&row.user_id!==u.id){await audit(u.id,"ATTENDANCE_ACCESS_DENIED","class_session",attMatch[1],"not_owner_or_subject",{requestId});send(res,req,403,{error:"forbidden",requestId});return;}
      const wc=await pool.query("SELECT COUNT(DISTINCT d.user_id)::int AS count FROM witness_observations w JOIN devices d ON d.id=w.observer_device_id WHERE w.session_id=$1 AND w.observed_device_id=$2 AND d.user_id<>$3",[attMatch[1],attMatch[2],row.user_id]);
      send(res,req,200,{sessionId:row.session_id,deviceId:attMatch[2],attendance:row.outcome,witnessCount:wc.rows[0].count,proofVerified:row.proof_verified});return;
    }

    if(method==="POST"&&/^\/sessions\/[^/]+\/end$/.test(path)){
      if(!requireRole(u,"professor","dept_admin","university_admin")){send(res,req,403,{error:"forbidden_role",requestId});return;}
      const sessionId=path.split("/")[2];
      const q=await pool.query<any>("UPDATE class_sessions cs SET status='ended',ended_at=now() FROM sections se WHERE cs.id=$1 AND cs.section_id=se.id AND se.instructor_id=$2 RETURNING cs.id,cs.status,cs.ended_at",[sessionId,u.id]);
      if(!q.rowCount){send(res,req,404,{error:"session_not_found",requestId});return;}
      await audit(u.id,"SESSION_ENDED","class_sessions",sessionId,"professor_action",{requestId});
      send(res,req,200,q.rows[0]);return;
    }

    if(method==="POST"&&/^\/sessions\/[^/]+$/.test(path)){
      if(!requireRole(u,"professor","dept_admin","university_admin")){send(res,req,403,{error:"forbidden_role",requestId});return;}
      const b=await body(req);const sectionId=String(b.sectionId??"");const s=await pool.query<any>("SELECT id,instructor_id FROM sections WHERE id=$1 AND instructor_id=$2",[sectionId,u.id]);
      if(!s.rowCount){send(res,req,403,{error:"section_not_owned",requestId});return;}
      const id=randomUUID();await pool.query("INSERT INTO class_sessions(id,section_id,status) VALUES($1,$2,'active')",[id,sectionId]);send(res,req,201,{id,status:"active"});return;
    }

    if(method==="POST"&&path==="/courses"){
      if(!requireRole(u,"professor","dept_admin","university_admin")){send(res,req,403,{error:"forbidden_role",requestId});return;}
      const b=await body(req);if(typeof b.code!=="string"||typeof b.title!=="string"){send(res,req,400,{error:"invalid_course",requestId});return;}
      const id=randomUUID();await pool.query("INSERT INTO courses(id,university_id,code,title) VALUES($1,(SELECT university_id FROM users WHERE id=$2),$3,$4)",[id,u.id,b.code.trim(),b.title.trim()]);
      send(res,req,201,{id,code:b.code.trim(),title:b.title.trim()});return;
    }

    if(method==="POST"&&path==="/sections"){
      if(!requireRole(u,"professor","dept_admin","university_admin")){send(res,req,403,{error:"forbidden_role",requestId});return;}
      const b=await body(req);if(typeof b.courseId!=="string"||typeof b.term!=="string"){send(res,req,400,{error:"invalid_section",requestId});return;}
      const id=randomUUID();const q=await pool.query("INSERT INTO sections(id,course_id,instructor_id,term) SELECT $1,id,$2,$3 FROM courses WHERE id=$4 AND university_id=(SELECT university_id FROM users WHERE id=$2) RETURNING id",[id,u.id,b.term,b.courseId]);
      if(!q.rowCount){send(res,req,404,{error:"course_not_found",requestId});return;}send(res,req,201,{id,courseId:b.courseId,term:b.term});return;
    }

    if(method==="POST"&&/^\/sections\/[^/]+\/enroll$/.test(path)){
      if(!requireRole(u,"student")){send(res,req,403,{error:"forbidden_role",requestId});return;}
      const sectionId=path.split("/")[2];const q=await pool.query("INSERT INTO enrollments(id,section_id,student_id) SELECT $1,id,$2 FROM sections WHERE id=$3 AND EXISTS(SELECT 1 FROM courses c WHERE c.id=sections.course_id AND c.university_id=(SELECT university_id FROM users WHERE id=$2)) ON CONFLICT(section_id,student_id) DO NOTHING RETURNING id",[randomUUID(),u.id,sectionId]);
      if(!q.rowCount){send(res,req,404,{error:"section_not_found",requestId});return;}send(res,req,201,{enrolled:true});return;
    }

    if(method==="GET"&&path==="/professor/sessions"){
      if(!requireRole(u,"professor","dept_admin","university_admin")){send(res,req,403,{error:"forbidden_role",requestId});return;}
      const q=await pool.query("SELECT cs.id,cs.status,cs.started_at,cs.ended_at,c.code,c.title,se.term FROM class_sessions cs JOIN sections se ON se.id=cs.section_id JOIN courses c ON c.id=se.course_id WHERE se.instructor_id=$1 ORDER BY cs.started_at DESC LIMIT 100",[u.id]);send(res,req,200,{sessions:q.rows});return;
    }

    if(method==="GET"&&/^\/sessions\/[^/]+\/evidence-graph$/.test(path)){
      const sessionId=path.split("/")[2];
      const s=(await pool.query<any>("SELECT cs.id,se.instructor_id FROM class_sessions cs JOIN sections se ON se.id=cs.section_id WHERE cs.id=$1",[sessionId])).rows[0];
      if(!s){send(res,req,404,{error:"session_not_found",requestId});return;}
      if(s.instructor_id!==u.id){send(res,req,403,{error:"forbidden",requestId});return;}
      const students=await pool.query<any>("SELECT DISTINCT ar.student_id AS id,u.full_name AS label,'student' AS type FROM attendance_records ar JOIN users u ON u.id=ar.student_id WHERE ar.session_id=$1",[sessionId]);
      const devices=await pool.query<any>("SELECT DISTINCT d.id,d.user_id AS owner_id,'device' AS type FROM devices d WHERE d.id IN (SELECT device_id FROM attendance_records WHERE session_id=$1 UNION SELECT observer_device_id FROM witness_observations WHERE session_id=$1 UNION SELECT observed_device_id FROM witness_observations WHERE session_id=$1)",[sessionId]);
      const edges=await pool.query<any>("SELECT 'check_in' AS type,ar.student_id AS source,ar.device_id AS target FROM attendance_records ar WHERE ar.session_id=$1 UNION ALL SELECT 'witness' AS type,w.observer_device_id AS source,w.observed_device_id AS target FROM witness_observations w WHERE w.session_id=$1",[sessionId]);
      send(res,req,200,{sessionId,nodes:[...students.rows,...devices.rows],edges:edges.rows});return;
    }

    if(method==="GET"&&/^\/sessions\/[^/]+\/overview$/.test(path)){
      const sessionId=path.split("/")[2];const s=(await pool.query<any>("SELECT cs.id,cs.status,cs.started_at,cs.ended_at,se.instructor_id,c.code,c.title,se.term FROM class_sessions cs JOIN sections se ON se.id=cs.section_id JOIN courses c ON c.id=se.course_id WHERE cs.id=$1",[sessionId])).rows[0];
      if(!s){send(res,req,404,{error:"session_not_found",requestId});return;}
      if(s.instructor_id!==u.id){send(res,req,403,{error:"forbidden",requestId});return;}
      const a=await pool.query("SELECT ar.student_id,u.full_name,u.email,ar.outcome,ar.proof_verified,ar.checked_in_at,COUNT(DISTINCT w.observer_device_id)::int AS witness_count,ra.risk_score,ra.reasons AS risk_reasons FROM attendance_records ar JOIN users u ON u.id=ar.student_id LEFT JOIN witness_observations w ON w.session_id=ar.session_id AND w.observed_device_id=ar.device_id LEFT JOIN risk_assessments ra ON ra.session_id=ar.session_id AND ra.student_id=ar.student_id WHERE ar.session_id=$1 GROUP BY ar.student_id,u.full_name,u.email,ar.outcome,ar.proof_verified,ar.checked_in_at,ra.risk_score,ra.reasons ORDER BY u.full_name",[sessionId]);
      send(res,req,200,{session:s,students:a.rows});return;
    }

    if(method==="GET"&&path==="/student/sessions"){
      if(!requireRole(u,"student")){send(res,req,403,{error:"forbidden_role",requestId});return;}
      const q=await pool.query("SELECT cs.id,cs.status,cs.started_at,c.code,c.title,se.term,EXISTS(SELECT 1 FROM attendance_records ar WHERE ar.session_id=cs.id AND ar.student_id=$1) AS checked_in FROM class_sessions cs JOIN sections se ON se.id=cs.section_id JOIN courses c ON c.id=se.course_id JOIN enrollments e ON e.section_id=se.id WHERE e.student_id=$1 AND cs.status='active' ORDER BY cs.started_at DESC",[u.id]);send(res,req,200,q.rows);return;
    }

    if(method==="POST"&&/^\/admin\/devices\/[^/]+\/revoke$/.test(path)){
      if(!requireRole(u,"dept_admin","university_admin","platform_admin")){send(res,req,403,{error:"forbidden_role",requestId});return;}
      const deviceId=path.split("/")[3];const q=await pool.query("UPDATE devices SET status='revoked' WHERE id=$1 AND user_id IN (SELECT id FROM users WHERE university_id=(SELECT university_id FROM users WHERE id=$2)) RETURNING id",[deviceId,u.id]);
      if(!q.rowCount){send(res,req,404,{error:"device_not_found",requestId});return;}await audit(u.id,"DEVICE_REVOKED","devices",deviceId,"administrator_action",{requestId});send(res,req,200,{revoked:true});return;
    }

    if(method==="POST"&&/^\/sessions\/[^/]+\/risk\/[^/]+$/.test(path)){
      if(!requireRole(u,"professor","dept_admin","university_admin")){send(res,req,403,{error:"forbidden_role",requestId});return;}
      const [, , sessionId, studentId]=path.split("/");
      const session=(await pool.query<any>("SELECT cs.id,se.instructor_id FROM class_sessions cs JOIN sections se ON se.id=cs.section_id WHERE cs.id=$1",[sessionId])).rows[0];
      if(!session||session.instructor_id!==u.id){send(res,req,403,{error:"forbidden",requestId});return;}
      const attendance=(await pool.query<any>("SELECT proof_verified,device_id FROM attendance_records WHERE session_id=$1 AND student_id=$2",[sessionId,studentId])).rows[0];
      if(!attendance){send(res,req,404,{error:"attendance_not_found",requestId});return;}
      const witnesses=(await pool.query<any>("SELECT COUNT(DISTINCT observer.user_id)::int AS count FROM witness_observations w JOIN devices observer ON observer.id=w.observer_device_id JOIN devices observed ON observed.id=w.observed_device_id WHERE w.session_id=$1 AND w.observed_device_id=$2 AND observer.user_id<>observed.user_id",[sessionId,attendance.device_id])).rows[0].count;
      // RSSI magnitude alone is not a contradiction signal; keep this zero until a calibrated
      // contradiction model exists rather than inventing certainty from radio noise.
      const conflicts=0;
      const replay=(await pool.query<any>("SELECT COUNT(*)::int AS count FROM audit_log WHERE target_table='class_session' AND target_id=$1 AND action IN ('WITNESS_SIGNATURE_INVALID','DEVICE_SIGNATURE_INVALID','HEARTBEAT_SIGNATURE_INVALID') AND occurred_at > now()-interval '1 hour'",[sessionId])).rows[0].count;
      const stale=(await pool.query<any>("SELECT CASE WHEN EXISTS(SELECT 1 FROM evidence_heartbeats WHERE session_id=$1 AND device_id=$2 AND observed_at>now()-interval '90 seconds') THEN 0 ELSE 1 END::int AS count",[sessionId,attendance.device_id])).rows[0].count;
      const result=assessRisk({proofVerified:attendance.proof_verified,independentWitnesses:witnesses,conflictingObservations:conflicts,staleObservations:stale,replayEvents:replay});
      await pool.query("INSERT INTO risk_assessments(id,session_id,student_id,risk_score,reasons,computed_at) VALUES($1,$2,$3,$4,$5,now()) ON CONFLICT(session_id,student_id) DO UPDATE SET risk_score=EXCLUDED.risk_score,reasons=EXCLUDED.reasons,computed_at=now()",[randomUUID(),sessionId,studentId,result.score,JSON.stringify({status:result.status,confidence:result.confidence,reasons:result.reasons})]);
      send(res,req,200,{sessionId,studentId,...result});return;
    }

    if(method==="GET"&&path==="/me"){const q=await pool.query("SELECT id,role,full_name,email,university_id FROM users WHERE id=$1",[u.id]);send(res,req,200,q.rows[0]);return;}
    send(res,req,404,{error:"not_found",requestId});
  }catch(e){
    const [status,error]=failCode(e);console.error(JSON.stringify({requestId,error:e instanceof Error?e.message:"unknown"}));send(res,req,status,{error,requestId});
  }
});

init().then(()=>server.listen(PORT,()=>console.log(`SHAHID production API listening on ${PORT}`))).catch(e=>{console.error(e);process.exit(1);});
