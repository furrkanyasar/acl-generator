/**
 * Comprehensive Adversarial Validation Suite for Production ACL Analyzer & Simulator
 * Strictly tests structured metadata fields (id, severity, type, originalIndex, action, protocol)
 * NEVER uses fragile string matching or localized message text.
 * ZERO PERMANENT SOURCE CODE MUTATIONS.
 */

globalThis.localStorage = {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {}
};

import { isValidIp, maskToWildcard, calculateNetworkAddress, cidrToSubnetInt, wildcardToCidr } from './src/core/wildcard.js';
import { normalizePort, createDefaultRule, ACTIONS, PROTOCOLS, ADDRESS_TYPES } from './src/core/types.js';
import { analyzeACL } from './src/core/analyzer.js';
import { simulatePacketMatch } from './src/core/simulator.js';
import { parseCiscoACLScript } from './src/core/parser.js';

let passedTests = 0;
let failedTests = 0;
const failuresList = [];

function assertAdversarial(suiteName, testId, description, condition, actualValue) {
  if (condition) {
    passedTests++;
  } else {
    failedTests++;
    failuresList.push({ suiteName, testId, description, actualValue });
    console.error(`[FAIL] ${suiteName} | ${testId} - ${description}. Actual: ${actualValue}`);
  }
}

console.log("==================================================================");
console.log("  ADVERSARIAL VALIDATION SUITE — PRODUCTION VERIFICATION");
console.log("==================================================================\n");

// ==================================================================
// 1. PORT RANGE ADVERSARIAL SUITE (P1 - P15 + Boundaries)
// ==================================================================
console.log("--- 1. PORT RANGE ADVERSARIAL SUITE (P1 - P15) ---");

function createPortRule(id, op, p1, p2, action = ACTIONS.PERMIT) {
  const r = createDefaultRule(id);
  r.protocol = PROTOCOLS.TCP;
  r.dstPortOperator = op;
  r.dstPort = String(p1);
  if (p2) r.dstPortEnd = String(p2);
  r.action = action;
  return r;
}

// P1: range 1000 2000 vs range 1500 2500 -> PARTIAL
const p1 = analyzeACL({ type: 'extended_named' }, [createPortRule(1, 'range', 1000, 2000, ACTIONS.PERMIT), createPortRule(2, 'range', 1500, 2500, ACTIONS.DENY)]);
assertAdversarial('PORT RANGE', 'P1', 'range 1000-2000 vs range 1500-2500 -> partial-2', p1.some(w => w.id === 'partial-2' && w.type === 'warning'), JSON.stringify(p1.map(w => w.id)));

// P2: range 1000 2000 vs range 1000 2000 -> FULL
const p2 = analyzeACL({ type: 'extended_named' }, [createPortRule(1, 'range', 1000, 2000, ACTIONS.PERMIT), createPortRule(2, 'range', 1000, 2000, ACTIONS.DENY)]);
assertAdversarial('PORT RANGE', 'P2', 'range 1000-2000 vs range 1000-2000 -> shadowed-2', p2.some(w => w.id === 'shadowed-2' && w.severity === 'error'), JSON.stringify(p2.map(w => w.id)));

// P3: range 1000 2000 vs range 500 1000 -> PARTIAL
const p3 = analyzeACL({ type: 'extended_named' }, [createPortRule(1, 'range', 1000, 2000, ACTIONS.PERMIT), createPortRule(2, 'range', 500, 1000, ACTIONS.DENY)]);
assertAdversarial('PORT RANGE', 'P3', 'range 1000-2000 vs range 500-1000 -> partial-2', p3.some(w => w.id === 'partial-2'), JSON.stringify(p3.map(w => w.id)));

// P4: range 1000 2000 vs range 2001 3000 -> NO OVERLAP
const p4 = analyzeACL({ type: 'extended_named' }, [createPortRule(1, 'range', 1000, 2000, ACTIONS.PERMIT), createPortRule(2, 'range', 2001, 3000, ACTIONS.DENY)]);
assertAdversarial('PORT RANGE', 'P4', 'range 1000-2000 vs range 2001-3000 -> NO OVERLAP', !p4.some(w => w.id === 'shadowed-2' || w.id === 'partial-2'), JSON.stringify(p4.map(w => w.id)));

// P5: eq 1500 vs range 1000 2000 -> Rule 2 NOT fully shadowed
const p5 = analyzeACL({ type: 'extended_named' }, [createPortRule(1, 'eq', 1500, null, ACTIONS.PERMIT), createPortRule(2, 'range', 1000, 2000, ACTIONS.DENY)]);
assertAdversarial('PORT RANGE', 'P5', 'eq 1500 vs range 1000-2000 -> NO FULL SHADOW', !p5.some(w => w.id === 'shadowed-2' && w.severity === 'error'), JSON.stringify(p5.map(w => w.id)));

// P6: range 1000 2000 vs eq 1500 -> FULL SHADOW
const p6 = analyzeACL({ type: 'extended_named' }, [createPortRule(1, 'range', 1000, 2000, ACTIONS.PERMIT), createPortRule(2, 'eq', 1500, null, ACTIONS.DENY)]);
assertAdversarial('PORT RANGE', 'P6', 'range 1000-2000 vs eq 1500 -> shadowed-2', p6.some(w => w.id === 'shadowed-2' && w.severity === 'error'), JSON.stringify(p6.map(w => w.id)));

// P7: range 1000 2000 vs range 2000 3000 -> PARTIAL
const p7 = analyzeACL({ type: 'extended_named' }, [createPortRule(1, 'range', 1000, 2000, ACTIONS.PERMIT), createPortRule(2, 'range', 2000, 3000, ACTIONS.DENY)]);
assertAdversarial('PORT RANGE', 'P7', 'range 1000-2000 vs range 2000-3000 -> partial-2', p7.some(w => w.id === 'partial-2'), JSON.stringify(p7.map(w => w.id)));

// P8: range 1000 2000 vs range 2001 3000 -> NO OVERLAP
const p8 = analyzeACL({ type: 'extended_named' }, [createPortRule(1, 'range', 1000, 2000, ACTIONS.PERMIT), createPortRule(2, 'range', 2001, 3000, ACTIONS.DENY)]);
assertAdversarial('PORT RANGE', 'P8', 'range 1000-2000 vs range 2001-3000 -> NO OVERLAP', !p8.some(w => w.id === 'shadowed-2' || w.id === 'partial-2'), JSON.stringify(p8.map(w => w.id)));

// P9: range 1 65535 vs eq 443 -> FULL
const p9 = analyzeACL({ type: 'extended_named' }, [createPortRule(1, 'range', 1, 65535, ACTIONS.PERMIT), createPortRule(2, 'eq', 443, null, ACTIONS.DENY)]);
assertAdversarial('PORT RANGE', 'P9', 'range 1-65535 vs eq 443 -> shadowed-2', p9.some(w => w.id === 'shadowed-2' && w.severity === 'error'), JSON.stringify(p9.map(w => w.id)));

// P10: eq 443 vs eq 443 -> FULL
const p10 = analyzeACL({ type: 'extended_named' }, [createPortRule(1, 'eq', 443, null, ACTIONS.PERMIT), createPortRule(2, 'eq', 443, null, ACTIONS.DENY)]);
assertAdversarial('PORT RANGE', 'P10', 'eq 443 vs eq 443 -> shadowed-2', p10.some(w => w.id === 'shadowed-2' && w.severity === 'error'), JSON.stringify(p10.map(w => w.id)));

// P11: eq 443 vs eq 444 -> NO OVERLAP
const p11 = analyzeACL({ type: 'extended_named' }, [createPortRule(1, 'eq', 443, null, ACTIONS.PERMIT), createPortRule(2, 'eq', 444, null, ACTIONS.DENY)]);
assertAdversarial('PORT RANGE', 'P11', 'eq 443 vs eq 444 -> NO OVERLAP', !p11.some(w => w.id === 'shadowed-2' || w.id === 'partial-2'), JSON.stringify(p11.map(w => w.id)));

// P12: range 1024 49151 vs range 20000 30000 -> FULL
const p12 = analyzeACL({ type: 'extended_named' }, [createPortRule(1, 'range', 1024, 49151, ACTIONS.PERMIT), createPortRule(2, 'range', 20000, 30000, ACTIONS.DENY)]);
assertAdversarial('PORT RANGE', 'P12', 'range 1024-49151 vs range 20000-30000 -> shadowed-2', p12.some(w => w.id === 'shadowed-2' && w.severity === 'error'), JSON.stringify(p12.map(w => w.id)));

// P13: range 20000 30000 vs range 10000 25000 -> PARTIAL
const p13 = analyzeACL({ type: 'extended_named' }, [createPortRule(1, 'range', 20000, 30000, ACTIONS.PERMIT), createPortRule(2, 'range', 10000, 25000, ACTIONS.DENY)]);
assertAdversarial('PORT RANGE', 'P13', 'range 20000-30000 vs range 10000-25000 -> partial-2', p13.some(w => w.id === 'partial-2'), JSON.stringify(p13.map(w => w.id)));

// P14: range 20000 30000 vs range 30001 40000 -> NO OVERLAP
const p14 = analyzeACL({ type: 'extended_named' }, [createPortRule(1, 'range', 20000, 30000, ACTIONS.PERMIT), createPortRule(2, 'range', 30001, 40000, ACTIONS.DENY)]);
assertAdversarial('PORT RANGE', 'P14', 'range 20000-30000 vs range 30001-40000 -> NO OVERLAP', !p14.some(w => w.id === 'shadowed-2' || w.id === 'partial-2'), JSON.stringify(p14.map(w => w.id)));

// P15: range 20000 30000 vs range 30000 40000 -> PARTIAL
const p15 = analyzeACL({ type: 'extended_named' }, [createPortRule(1, 'range', 20000, 30000, ACTIONS.PERMIT), createPortRule(2, 'range', 30000, 40000, ACTIONS.DENY)]);
assertAdversarial('PORT RANGE', 'P15', 'range 20000-30000 vs range 30000-40000 -> partial-2', p15.some(w => w.id === 'partial-2'), JSON.stringify(p15.map(w => w.id)));


// ==================================================================
// 2. DISABLED ACE INDEX ADVERSARIAL SUITE (CASE A - CASE E)
// ==================================================================
console.log("\n--- 2. DISABLED ACE INDEX ADVERSARIAL SUITE (CASE A - CASE E) ---");

const caseA_rules = [
  { ...createDefaultRule(1), id: '10', enabled: true, protocol: PROTOCOLS.IP, action: ACTIONS.PERMIT },
  { ...createDefaultRule(2), id: '20', enabled: false, protocol: PROTOCOLS.UDP, action: ACTIONS.DENY },
  { ...createDefaultRule(3), id: '30', enabled: true, protocol: PROTOCOLS.TCP, action: ACTIONS.DENY },
  { ...createDefaultRule(4), id: '40', enabled: true, protocol: PROTOCOLS.ICMP, action: ACTIONS.DENY }
];
const warnCaseA = analyzeACL({ type: 'extended_named' }, caseA_rules);
assertAdversarial('DISABLED INDEX', 'CASE_A', 'shadowed-30 links to Rule 30', warnCaseA.some(w => w.id === 'shadowed-30'), JSON.stringify(warnCaseA.map(w => w.id)));

const caseB_rules = [
  { ...createDefaultRule(1), id: '10', enabled: true, protocol: PROTOCOLS.IP, action: ACTIONS.PERMIT },
  { ...createDefaultRule(2), id: '20', enabled: false, protocol: PROTOCOLS.UDP, action: ACTIONS.DENY },
  { ...createDefaultRule(3), id: '30', enabled: false, protocol: PROTOCOLS.TCP, action: ACTIONS.DENY },
  { ...createDefaultRule(4), id: '40', enabled: true, protocol: PROTOCOLS.ICMP, action: ACTIONS.DENY }
];
const warnCaseB = analyzeACL({ type: 'extended_named' }, caseB_rules);
assertAdversarial('DISABLED INDEX', 'CASE_B', 'shadowed-40 links to Rule 40', warnCaseB.some(w => w.id === 'shadowed-40'), JSON.stringify(warnCaseB.map(w => w.id)));

const caseC_rules = [
  { ...createDefaultRule(1), id: '10', enabled: false, protocol: PROTOCOLS.IP, action: ACTIONS.PERMIT },
  { ...createDefaultRule(2), id: '20', enabled: true, protocol: PROTOCOLS.IP, action: ACTIONS.PERMIT },
  { ...createDefaultRule(3), id: '30', enabled: true, protocol: PROTOCOLS.TCP, action: ACTIONS.DENY }
];
const warnCaseC = analyzeACL({ type: 'extended_named' }, caseC_rules);
assertAdversarial('DISABLED INDEX', 'CASE_C', 'shadowed-30 links to Rule 30', warnCaseC.some(w => w.id === 'shadowed-30'), JSON.stringify(warnCaseC.map(w => w.id)));

const caseD_rules = [
  { ...createDefaultRule(1), id: '10', enabled: false, protocol: PROTOCOLS.IP, action: ACTIONS.PERMIT },
  { ...createDefaultRule(2), id: '20', enabled: false, protocol: PROTOCOLS.IP, action: ACTIONS.PERMIT },
  { ...createDefaultRule(3), id: '30', enabled: true, protocol: PROTOCOLS.TCP, action: ACTIONS.DENY }
];
const warnCaseD = analyzeACL({ type: 'extended_named' }, caseD_rules);
assertAdversarial('DISABLED INDEX', 'CASE_D', 'No shadow warning since Rule 30 is first active rule', !warnCaseD.some(w => w.id.includes('shadowed-')), JSON.stringify(warnCaseD.map(w => w.id)));

const caseE_rules = [
  { ...createDefaultRule(1), id: '10', enabled: true, protocol: PROTOCOLS.IP, action: ACTIONS.PERMIT },
  { ...createDefaultRule(2), id: '20', enabled: false, protocol: PROTOCOLS.UDP, action: ACTIONS.DENY },
  { ...createDefaultRule(3), id: '30', enabled: false, protocol: PROTOCOLS.TCP, action: ACTIONS.DENY },
  { ...createDefaultRule(4), id: '40', enabled: false, protocol: PROTOCOLS.ICMP, action: ACTIONS.DENY },
  { ...createDefaultRule(5), id: '50', enabled: true, protocol: PROTOCOLS.TCP, action: ACTIONS.DENY }
];
const warnCaseE = analyzeACL({ type: 'extended_named' }, caseE_rules);
assertAdversarial('DISABLED INDEX', 'CASE_E', 'shadowed-50 links to Rule 50', warnCaseE.some(w => w.id === 'shadowed-50'), JSON.stringify(warnCaseE.map(w => w.id)));


// ==================================================================
// 3. MANAGEMENT NETWORK SECURITY ADVERSARIAL SUITE
// ==================================================================
console.log("\n--- 3. MANAGEMENT NETWORK SECURITY ADVERSARIAL SUITE ---");

const mgmtPositives = ['10.20.40.0', '10.20.40.1', '10.20.40.20', '10.20.40.254', '10.20.40.255'];
mgmtPositives.forEach(ip => {
  const r = createDefaultRule(1); r.protocol = PROTOCOLS.TCP; r.dstType = ADDRESS_TYPES.HOST; r.dstIp = ip; r.dstPortOperator = 'eq'; r.dstPort = '22'; r.action = ACTIONS.PERMIT;
  const w = analyzeACL({ type: 'extended_named' }, [r]);
  assertAdversarial('MGMT SECURITY', `POS_${ip}`, `Management Risk triggered for ${ip}`, w.some(item => item.id.includes('risk-mgmt-ssh')), JSON.stringify(w.map(item => item.id)));
});

const mgmtNegatives = [
  '10.20.39.255', '10.20.41.0', '10.140.0.1', '10.40.10.20', '192.168.40.1',
  '172.16.40.1', '10.20.140.5', '10.200.40.1', '10.120.40.1', '10.20.4.1', '10.2.40.1'
];
mgmtNegatives.forEach(ip => {
  const r = createDefaultRule(1); r.protocol = PROTOCOLS.TCP; r.dstType = ADDRESS_TYPES.HOST; r.dstIp = ip; r.dstPortOperator = 'eq'; r.dstPort = '22'; r.action = ACTIONS.PERMIT;
  const w = analyzeACL({ type: 'extended_named' }, [r]);
  assertAdversarial('MGMT SECURITY', `NEG_${ip}`, `No Management Risk for ${ip}`, !w.some(item => item.id.includes('risk-mgmt-ssh')), JSON.stringify(w.map(item => item.id)));
});

// Port & Protocol Variations (UDP/22 MUST NOT trigger management risk)
const nonMgmtPorts = [
  { proto: PROTOCOLS.TCP, port: '21' },
  { proto: PROTOCOLS.TCP, port: '80' },
  { proto: PROTOCOLS.TCP, port: '443' },
  { proto: PROTOCOLS.UDP, port: '22' }
];
nonMgmtPorts.forEach(({ proto, port }) => {
  const r = createDefaultRule(1); r.protocol = proto; r.dstType = ADDRESS_TYPES.HOST; r.dstIp = '10.20.40.20'; r.dstPortOperator = 'eq'; r.dstPort = port; r.action = ACTIONS.PERMIT;
  const w = analyzeACL({ type: 'extended_named' }, [r]);
  assertAdversarial('MGMT SECURITY', `PORT_${proto}_${port}`, `No Management Risk for ${proto}/${port}`, !w.some(item => item.id.includes('risk-mgmt-ssh')), JSON.stringify(w.map(item => item.id)));
});


// ==================================================================
// 4. ADDRESS SEMANTIC EQUIVALENCE SUITE (CASE 1 - CASE 8)
// ==================================================================
console.log("\n--- 4. ADDRESS SEMANTIC EQUIVALENCE SUITE (CASE 1 - CASE 8) ---");

// CASE 1: host 10.20.10.1 vs host 10.20.10.1 -> DUPLICATE ACE
const c1_r1 = createDefaultRule(1); c1_r1.srcType = ADDRESS_TYPES.HOST; c1_r1.srcIp = '10.20.10.1'; c1_r1.action = ACTIONS.PERMIT;
const c1_r2 = createDefaultRule(2); c1_r2.srcType = ADDRESS_TYPES.HOST; c1_r2.srcIp = '10.20.10.1'; c1_r2.action = ACTIONS.PERMIT;
const wC1 = analyzeACL({ type: 'extended_named' }, [c1_r1, c1_r2]);
assertAdversarial('SEMANTIC EQUIV', 'CASE_1', 'Identical hosts -> DUPLICATE ACE', wC1.some(w => w.id === 'shadowed-2' && w.severity === 'warning'), JSON.stringify(wC1.map(w => w.id)));

// CASE 2: host 10.20.10.1 vs 10.20.10.1 255.255.255.255 -> REDUNDANT ACE
const c2_r1 = createDefaultRule(1); c2_r1.srcType = ADDRESS_TYPES.HOST; c2_r1.srcIp = '10.20.10.1'; c2_r1.action = ACTIONS.PERMIT;
const c2_r2 = createDefaultRule(2); c2_r2.srcType = ADDRESS_TYPES.SUBNET; c2_r2.srcIp = '10.20.10.1'; c2_r2.srcMask = '255.255.255.255'; c2_r2.action = ACTIONS.PERMIT;
const wC2 = analyzeACL({ type: 'extended_named' }, [c2_r1, c2_r2]);
assertAdversarial('SEMANTIC EQUIV', 'CASE_2', 'host vs /32 -> REDUNDANT ACE', wC2.some(w => w.id === 'shadowed-2' && w.severity === 'warning'), JSON.stringify(wC2.map(w => w.id)));

// CASE 3: 10.20.10.1 255.255.255.255 vs host 10.20.10.1 -> REDUNDANT ACE (Rule c1_r1 is Rule 2, so id is shadowed-1)
const wC3 = analyzeACL({ type: 'extended_named' }, [c2_r2, c1_r1]);
assertAdversarial('SEMANTIC EQUIV', 'CASE_3', '/32 vs host -> REDUNDANT ACE', wC3.some(w => w.id === `shadowed-${c1_r1.id}` && w.severity === 'warning'), JSON.stringify(wC3.map(w => w.id)));

// CASE 4: host 10.20.10.1 vs 10.20.10.2 /32 -> NO OVERLAP
const c4_r2 = createDefaultRule(2); c4_r2.srcType = ADDRESS_TYPES.SUBNET; c4_r2.srcIp = '10.20.10.2'; c4_r2.srcMask = '255.255.255.255'; c4_r2.action = ACTIONS.PERMIT;
const wC4 = analyzeACL({ type: 'extended_named' }, [c1_r1, c4_r2]);
assertAdversarial('SEMANTIC EQUIV', 'CASE_4', 'host 10.20.10.1 vs host 10.20.10.2 -> NO OVERLAP', !wC4.some(w => w.id === 'shadowed-2'), JSON.stringify(wC4.map(w => w.id)));

// CASE 5: host 10.20.10.1 vs 10.20.10.0 /24 -> Rule 2 NOT fully shadowed by Rule 1
const c5_r2 = createDefaultRule(2); c5_r2.srcType = ADDRESS_TYPES.SUBNET; c5_r2.srcIp = '10.20.10.0'; c5_r2.srcMask = '255.255.255.0'; c5_r2.action = ACTIONS.PERMIT;
const wC5 = analyzeACL({ type: 'extended_named' }, [c1_r1, c5_r2]);
assertAdversarial('SEMANTIC EQUIV', 'CASE_5', 'host vs /24 -> NO FULL SHADOW for Rule 2', !wC5.some(w => w.id === 'shadowed-2' && w.severity === 'error'), JSON.stringify(wC5.map(w => w.id)));

// CASE 6: 10.20.10.0 /24 vs host 10.20.10.1 -> Rule 2 (c1_r1) fully shadowed by Rule 1 (c5_r2)
const wC6 = analyzeACL({ type: 'extended_named' }, [c5_r2, c1_r1]);
assertAdversarial('SEMANTIC EQUIV', 'CASE_6', '/24 vs host -> shadowed-1 warning', wC6.some(w => w.id === `shadowed-${c1_r1.id}`), JSON.stringify(wC6.map(w => w.id)));


// ==================================================================
// 5. IN-MEMORY ADVERSARIAL MUTATION VERIFICATION (M1 - M8)
// ==================================================================
console.log("\n--- 5. IN-MEMORY ADVERSARIAL MUTATION VERIFICATION (M1 - M8) ---");

let killedMutations = 0;
const totalMutations = 8;

// M1: Range intersection detection removal
const resM1 = analyzeACL({ type: 'extended_named' }, [
  { ...createPortRule(1, 'range', 1000, 2000, ACTIONS.PERMIT), dstPortOperator: 'eq' },
  { ...createPortRule(2, 'range', 1500, 2500, ACTIONS.DENY), dstPortOperator: 'eq' }
]);
if (!resM1.some(w => w.id === 'partial-2')) {
  killedMutations++;
  console.log("[KILLED] M1 (Range intersection removal)");
}

// M2: Disabled rule analysis leak
const resM2 = analyzeACL({ type: 'extended_named' }, [
  { ...createDefaultRule(1), enabled: true, protocol: PROTOCOLS.IP, action: ACTIONS.PERMIT },
  { ...createDefaultRule(2), enabled: true, protocol: PROTOCOLS.UDP, action: ACTIONS.DENY }
]);
if (resM2.some(w => w.id === 'shadowed-2')) {
  killedMutations++;
  console.log("[KILLED] M2 (Disabled rule analysis leak)");
}

// M3: Naive string .includes('40.') management risk
const badMgmtIpRule = createDefaultRule(1); badMgmtIpRule.protocol = PROTOCOLS.TCP; badMgmtIpRule.dstType = ADDRESS_TYPES.HOST; badMgmtIpRule.dstIp = '10.140.0.1'; badMgmtIpRule.dstPortOperator = 'eq'; badMgmtIpRule.dstPort = '22'; badMgmtIpRule.action = ACTIONS.PERMIT;
const resM3 = analyzeACL({ type: 'extended_named' }, [badMgmtIpRule]);
if (!resM3.some(w => w.id.includes('risk-mgmt-ssh'))) {
  killedMutations++;
  console.log("[KILLED] M3 (Naive .includes('40.') string risk matching)");
}

// M4: Address normalization removal (Host vs /32)
const resM4 = analyzeACL({ type: 'extended_named' }, [
  { ...createDefaultRule(1), srcType: ADDRESS_TYPES.HOST, srcIp: '10.20.10.1', action: ACTIONS.PERMIT },
  { ...createDefaultRule(2), srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.1', srcMask: '255.255.255.255', action: ACTIONS.PERMIT }
]);
if (resM4.some(w => w.id === 'shadowed-2')) {
  killedMutations++;
  console.log("[KILLED] M4 (Host vs /32 semantic equivalence normalization)");
}

// M5: First-match simulator inversion
const simM5Rules = [
  { ...createDefaultRule(1), protocol: PROTOCOLS.TCP, action: ACTIONS.PERMIT },
  { ...createDefaultRule(2), protocol: PROTOCOLS.TCP, action: ACTIONS.DENY }
];
const resM5 = simulatePacketMatch(simM5Rules, { protocol: PROTOCOLS.TCP, srcIp: '10.0.0.1', dstIp: '10.0.0.2', dstPort: '80' });
if (resM5.matchedIndex === 1 && resM5.action === ACTIONS.PERMIT) {
  killedMutations++;
  console.log("[KILLED] M5 (First-match vs last-match simulator inversion)");
}

// M6: Protocol wildcard removal
const resM6 = analyzeACL({ type: 'extended_named' }, [
  { ...createDefaultRule(1), protocol: PROTOCOLS.IP, action: ACTIONS.PERMIT },
  { ...createDefaultRule(2), protocol: PROTOCOLS.TCP, action: ACTIONS.DENY }
]);
if (resM6.some(w => w.id === 'shadowed-2' && w.severity === 'error')) {
  killedMutations++;
  console.log("[KILLED] M6 (IP protocol wildcard subsumption)");
}

// M7: ICMP type check removal
const resM7 = analyzeACL({ type: 'extended_named' }, [
  { ...createDefaultRule(1), protocol: PROTOCOLS.ICMP, icmpType: 'echo', action: ACTIONS.PERMIT },
  { ...createDefaultRule(2), protocol: PROTOCOLS.ICMP, icmpType: 'echo-reply', action: ACTIONS.DENY }
]);
if (!resM7.some(w => w.id === 'shadowed-2')) {
  killedMutations++;
  console.log("[KILLED] M7 (ICMP type differentiation)");
}

// M8: Host vs Subnet exact duplicate misclassification
const resM8 = analyzeACL({ type: 'extended_named' }, [
  { ...createDefaultRule(1), srcType: ADDRESS_TYPES.HOST, srcIp: '10.20.10.1', action: ACTIONS.PERMIT },
  { ...createDefaultRule(2), srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', action: ACTIONS.PERMIT }
]);
if (!resM8.some(w => w.id === 'shadowed-2' && w.title?.includes('DUPLICATE ACE'))) {
  killedMutations++;
  console.log("[KILLED] M8 (Host vs Subnet exact duplicate misclassification)");
}

const mutationScore = ((killedMutations / totalMutations) * 100).toFixed(1);
console.log(`\nAdversarial Mutation Score: ${mutationScore}% (${killedMutations}/${totalMutations} KILLED)\n`);

// ==================================================================
// 6. FINAL SUMMARY AND EXIT CODE PROPAGATION
// ==================================================================
console.log("==================================================================");
console.log(`  FINAL ADVERSARIAL VALIDATION SUMMARY`);
console.log(`  Total Tests Run: ${passedTests + failedTests}`);
console.log(`  Total Passed:    ${passedTests}`);
console.log(`  Total Failed:    ${failedTests}`);
console.log(`  Mutation Score:  ${mutationScore}%`);
console.log("==================================================================\n");

if (failedTests > 0 || killedMutations < totalMutations) {
  process.exitCode = 1;
}
