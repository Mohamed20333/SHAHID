import { test } from "node:test";
import assert from "node:assert/strict";
import { assessRisk } from "./shahid-risk";

test("risk engine is explainable and never emits an accusation",()=>{
 const r=assessRisk({proofVerified:false,independentWitnesses:0,conflictingObservations:0,staleObservations:0,replayEvents:0});
 assert.equal(r.status,"INSUFFICIENT_EVIDENCE");
 assert.ok(r.reasons.length>0);
 assert.ok(!r.reasons.some(x=>x.toLowerCase().includes("cheat")));
});
test("valid proof and independent witnesses reduce review risk",()=>{
 const r=assessRisk({proofVerified:true,independentWitnesses:3,conflictingObservations:0,staleObservations:0,replayEvents:0});
 assert.equal(r.status,"LOW_RISK");
});
