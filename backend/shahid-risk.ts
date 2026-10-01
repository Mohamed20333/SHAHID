export interface RiskInput {
  proofVerified: boolean;
  independentWitnesses: number;
  conflictingObservations: number;
  staleObservations: number;
  replayEvents: number;
}
export interface RiskResult { score:number; confidence:number; reasons:string[]; status:"LOW_RISK"|"REVIEW_REQUIRED"|"INSUFFICIENT_EVIDENCE"; }
export function assessRisk(input:RiskInput):RiskResult {
  const evidence = Number(input.proofVerified) * 0.45 + Math.min(input.independentWitnesses,4) / 4 * 0.35;
  const penalties = Math.min(input.conflictingObservations,4) / 4 * 0.15 + Math.min(input.staleObservations,4) / 4 * 0.05 + Math.min(input.replayEvents,3) / 3 * 0.35;
  const score=Math.max(0,Math.min(1,0.5 + penalties - evidence));
  const confidence=Math.min(1,0.35 + (input.proofVerified?0.25:0) + Math.min(input.independentWitnesses,4)*0.1);
  const reasons:string[]=[];
  if(!input.proofVerified) reasons.push("No valid cryptographic check-in proof");
  if(input.independentWitnesses<2) reasons.push("Insufficient independent witness evidence");
  if(input.conflictingObservations>0) reasons.push("Conflicting proximity observations");
  if(input.staleObservations>0) reasons.push("Stale evidence was received");
  if(input.replayEvents>0) reasons.push("Replay/security events were observed");
  const status=!input.proofVerified && input.independentWitnesses===0 ? "INSUFFICIENT_EVIDENCE" : score>=0.55 ? "REVIEW_REQUIRED" : "LOW_RISK";
  return {score,confidence,reasons,status};
}
