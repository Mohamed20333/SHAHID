import {
  hasQuorum,
  computeRiskScore,
  decideEscalation,
  isPairSuspicious,
  SessionRecord,
  HistoricalPairStats,
} from "./shahid-escalation-logic";

const normalStudent: SessionRecord = {
  sessionId: "sess-101",
  studentId: "student-A",
  deviceId: "device-A",
  witnessedBy: ["dev-B", "dev-C", "dev-D", "dev-E"],
  pulseScore: 0.82,
  livenessPingSent: false,
  livenessPingAnsweredMs: null,
};

const suspiciousStudent: SessionRecord = {
  sessionId: "sess-101",
  studentId: "student-B",
  deviceId: "device-B",
  witnessedBy: ["dev-A", "dev-F", "dev-G", "dev-H"],
  pulseScore: 0.1,
  livenessPingSent: true,
  livenessPingAnsweredMs: null,
};

const suspiciousPairHistory: HistoricalPairStats[] = [
  {
    deviceA: "device-B",
    deviceB: "device-X",
    coOccurrenceRate: 0.97,
    varianceScore: 0.05,
    sessionsObserved: 22,
  },
];

console.log("=== Scenario 1: normal student ===");
console.log("Quorum met?", hasQuorum(normalStudent));
console.log("Risk score:", computeRiskScore(normalStudent, []));
console.log("Decision:", decideEscalation(normalStudent, [], 0));

console.log("\n=== Scenario 2: suspicious student ===");
console.log("Quorum met?", hasQuorum(suspiciousStudent));
console.log("Pair suspicious?", isPairSuspicious(suspiciousPairHistory[0]));
console.log("Risk score:", computeRiskScore(suspiciousStudent, suspiciousPairHistory));
console.log("Decision:", decideEscalation(suspiciousStudent, suspiciousPairHistory, 0));

console.log("\n=== Scenario 3: same suspicious student, but weekly cap already hit ===");
console.log("Decision:", decideEscalation(suspiciousStudent, suspiciousPairHistory, 1));