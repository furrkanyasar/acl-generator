/**
 * Evidence Audit Script
 * Runs T09, T15, T16, T23, N15 individually and extracts exact raw outputs & witness packets
 */

globalThis.localStorage = {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {}
};

import { isValidIp, maskToWildcard, calculateNetworkAddress } from './src/core/wildcard.js';
import { normalizePort, createDefaultRule, ACTIONS, PROTOCOLS, ADDRESS_TYPES } from './src/core/types.js';
import { analyzeACL } from './src/core/analyzer.js';
import { simulatePacketMatch } from './src/core/simulator.js';
import { parseCiscoACLScript } from './src/core/parser.js';

console.log("==================================================================");
console.log("  EVIDENCE AUDIT: 5 FAILED INTEGRATION TESTS (T09, T15, T16, T23, N15)");
console.log("==================================================================\n");

// --- 1. T09: PARTIAL PORT OVERLAP ---
console.log("--- 1. AUDITING T09 (Partial Port Overlap) ---");
const rT09_1 = createDefaultRule(1); rT09_1.protocol = PROTOCOLS.TCP; rT09_1.dstPortOperator = 'range'; rT09_1.dstPort = '1000'; rT09_1.dstPortEnd = '2000'; rT09_1.action = ACTIONS.PERMIT;
const rT09_2 = createDefaultRule(2); rT09_2.protocol = PROTOCOLS.TCP; rT09_2.dstPortOperator = 'range'; rT09_2.dstPort = '1500'; rT09_2.dstPortEnd = '2500'; rT09_2.action = ACTIONS.DENY;
const warnT09 = analyzeACL({ type: 'extended_named' }, [rT09_1, rT09_2]);
console.log("T09 Input: ACE #1 PERMIT range 1000-2000 vs ACE #2 DENY range 1500-2500");
console.log("T09 Raw Analyzer Warnings Output:", JSON.stringify(warnT09, null, 2));

// Witness Packets for T09
const pktT09_1600 = { protocol: PROTOCOLS.TCP, srcIp: '10.0.0.1', dstIp: '10.0.0.2', dstPort: '1600' };
const pktT09_2200 = { protocol: PROTOCOLS.TCP, srcIp: '10.0.0.1', dstIp: '10.0.0.2', dstPort: '2200' };
const resT09_1600 = simulatePacketMatch([rT09_1, rT09_2], pktT09_1600);
const resT09_2200 = simulatePacketMatch([rT09_1, rT09_2], pktT09_2200);
console.log(`Witness Packet 1600 match result: Matched Line #${resT09_1600.matchedIndex} (${resT09_1600.action.toUpperCase()})`);
console.log(`Witness Packet 2200 match result: Matched Line #${resT09_2200.matchedIndex} (${resT09_2200.action.toUpperCase()})\n`);

// --- 2. T15: DISABLED ACE INDEX ---
console.log("--- 2. AUDITING T15 (Disabled ACE Index) ---");
const rT15_1 = createDefaultRule(1); rT15_1.protocol = PROTOCOLS.IP; rT15_1.action = ACTIONS.PERMIT;
const rT15_2 = createDefaultRule(2); rT15_2.enabled = false; rT15_2.protocol = PROTOCOLS.UDP; rT15_2.action = ACTIONS.DENY;
const rT15_3 = createDefaultRule(3); rT15_3.protocol = PROTOCOLS.TCP; rT15_3.action = ACTIONS.DENY;
const warnT15 = analyzeACL({ type: 'extended_named' }, [rT15_1, rT15_2, rT15_3]);
console.log("T15 Input: ACE #1 (enabled), ACE #2 (disabled), ACE #3 (enabled, shadowed)");
console.log("T15 Raw Analyzer Warnings Output:", JSON.stringify(warnT15, null, 2));

// --- 3. T16: MANAGEMENT NETWORK RISK ---
console.log("--- 3. AUDITING T16 (Management Network Risk IPs) ---");
const mgmtIps = ['10.20.40.1', '10.20.40.20', '10.140.0.1', '10.40.10.20', '192.168.40.1', '10.20.140.5', '10.20.41.1'];
mgmtIps.forEach(ip => {
  const r = createDefaultRule(1);
  r.protocol = PROTOCOLS.TCP; r.srcType = ADDRESS_TYPES.SUBNET; r.srcIp = '10.20.10.0'; r.srcMask = '255.255.255.0';
  r.dstType = ADDRESS_TYPES.HOST; r.dstIp = ip; r.dstPortOperator = 'eq'; r.dstPort = '22'; r.action = ACTIONS.PERMIT;
  const w = analyzeACL({ type: 'extended_named' }, [r]);
  const hasRisk = w.some(item => item.id.includes('risk-mgmt-ssh'));
  console.log(`IP: ${ip.padEnd(15)} -> Mgmt Risk Warning Triggered: ${hasRisk}`);
});
console.log("\n");

// --- 4. T23: HOST VS /32 REPRESENTATION ---
console.log("--- 4. AUDITING T23 (Host vs /32 Representation) ---");
const rT23_1 = createDefaultRule(1); rT23_1.srcType = ADDRESS_TYPES.HOST; rT23_1.srcIp = '10.20.10.1'; rT23_1.action = ACTIONS.PERMIT;
const rT23_2 = createDefaultRule(2); rT23_2.srcType = ADDRESS_TYPES.SUBNET; rT23_2.srcIp = '10.20.10.1'; rT23_2.srcMask = '255.255.255.255'; rT23_2.action = ACTIONS.PERMIT;
const warnT23 = analyzeACL({ type: 'extended_named' }, [rT23_1, rT23_2]);
console.log("T23 Raw Analyzer Warnings Output:", JSON.stringify(warnT23, null, 2));
const pktT23 = { protocol: PROTOCOLS.IP, srcIp: '10.20.10.1', dstIp: '10.0.0.1' };
const resT23 = simulatePacketMatch([rT23_1, rT23_2], pktT23);
console.log(`Witness Packet 10.20.10.1 match result: Matched Line #${resT23.matchedIndex} (${resT23.action.toUpperCase()})\n`);

// --- 5. N15: SEQUENCE / IDENTITY INDEXING ---
console.log("--- 5. AUDITING N15 (Sequence / Identity Indexing) ---");
const rN15_1 = createDefaultRule(10); rN15_1.id = '10'; rN15_1.protocol = PROTOCOLS.IP; rN15_1.action = ACTIONS.PERMIT;
const rN15_2 = createDefaultRule(20); rN15_2.id = '20'; rN15_2.protocol = PROTOCOLS.TCP; rN15_2.action = ACTIONS.DENY;
const warnN15 = analyzeACL({ type: 'extended_named' }, [rN15_1, rN15_2]);
console.log("N15 Raw Analyzer Warnings Output:", JSON.stringify(warnN15, null, 2));
