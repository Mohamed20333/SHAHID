/**
 * Shahid — Selfie / Liveness Escalation Trigger Logic
 * ----------------------------------------------------
 * Design principle: the selfie/liveness layer is EXPENSIVE — biometric,
 * legally sensitive (GDPR/FERPA "special category data" if mishandled),
 * and adds UX friction. It must stay an ESCALATION path triggered for a
 * small, statistically-flagged minority of sessions — never the default
 * check for every student, every class.
 *
 * Everything in this file operates on METADATA only:
 *   - witness signatures (which device heard which device), never raw
 *     BLE payloads, audio, or GPS coordinates
 *   - pulse (retrieval-practice) SCORES, never the question/answer content
 *   - liveness-ping response latency, never the response content
 *
 * No biometric data is read, stored, or transmitted by this module.
 */

export interface SessionRecord {
  sessionId: string;
  studentId: string;
  deviceId: string;
  witnessedBy: string[];
  pulseScore: number | null;
  livenessPingSent: boolean;
  livenessPingAnsweredMs: number | null;
}

export interface HistoricalPairStats {
  deviceA: string;
  deviceB: string;
  coOccurrenceRate: number;
  varianceScore: number;
  sessionsObserved: number;
}

export interface EscalationDecision {
  studentId: string;
  sessionId: string;
  escalate: boolean;
  riskScore: number;
  reasons: string[];
}

export interface NativeLivenessResult {
  passed: boolean;
  challengeType: "look_left" | "look_right" | "blink" | "smile";
  onDeviceOnly: true;
}

export const CONFIG = {
  quorumMinWitnesses: 4,
  pairSuspicionThreshold: 0.85,
  varianceFloor: 0.15,
  minSessionsForPairAnalysis: 6,
  riskEscalationThreshold: 0.6,
  maxEscalationsPerStudentPerWeek: 1,
  pulseFailureWeight: 0.35,
  pairSuspicionWeight: 0.4,
  livenessPingMissWeight: 0.25,
  lowPulseThreshold: 0.3,
} as const;

export function hasQuorum(record: SessionRecord): boolean {
  return record.witnessedBy.length >= CONFIG.quorumMinWitnesses;
}

export function isPairSuspicious(stats: HistoricalPairStats): boolean {
  if (stats.sessionsObserved < CONFIG.minSessionsForPairAnalysis) return false;
  return (
    stats.coOccurrenceRate >= CONFIG.pairSuspicionThreshold &&
    stats.varianceScore <= CONFIG.varianceFloor
  );
}

export function computeRiskScore(
  record: SessionRecord,
  pairStatsForStudent: HistoricalPairStats[]
): number {
  let risk = 0;
  if (record.pulseScore !== null && record.pulseScore < CONFIG.lowPulseThreshold) {
    risk += CONFIG.pulseFailureWeight;
  }
  if (pairStatsForStudent.some(isPairSuspicious)) {
    risk += CONFIG.pairSuspicionWeight;
  }
  if (record.livenessPingSent && record.livenessPingAnsweredMs === null) {
    risk += CONFIG.livenessPingMissWeight;
  }
  return Math.min(risk, 1);
}

export function decideEscalation(
  record: SessionRecord,
  pairStatsForStudent: HistoricalPairStats[],
  escalationsThisWeek: number
): EscalationDecision {
  if (!hasQuorum(record)) {
    return {
      studentId: record.studentId,
      sessionId: record.sessionId,
      escalate: false,
      riskScore: 0,
      reasons: ["no_quorum_not_applicable"],
    };
  }

  if (escalationsThisWeek >= CONFIG.maxEscalationsPerStudentPerWeek) {
    return {
      studentId: record.studentId,
      sessionId: record.sessionId,
      escalate: false,
      riskScore: 0,
      reasons: ["weekly_escalation_cap_reached"],
    };
  }

  const riskScore = computeRiskScore(record, pairStatsForStudent);
  const reasons: string[] = [];

  if (record.pulseScore !== null && record.pulseScore < CONFIG.lowPulseThreshold) {
    reasons.push("low_pulse_score_despite_presence");
  }
  if (pairStatsForStudent.some(isPairSuspicious)) {
    reasons.push("suspicious_pair_pattern");
  }
  if (record.livenessPingSent && record.livenessPingAnsweredMs === null) {
    reasons.push("missed_liveness_ping");
  }

  return {
    studentId: record.studentId,
    sessionId: record.sessionId,
    escalate: riskScore >= CONFIG.riskEscalationThreshold,
    riskScore,
    reasons,
  };
}

export async function requestOnDeviceLivenessCheck(
  challenge: NativeLivenessResult["challengeType"]
): Promise<NativeLivenessResult> {
  throw new Error(
    "Implement via native module bridge: must resolve to {passed, challengeType, onDeviceOnly:true} only."
  );
}