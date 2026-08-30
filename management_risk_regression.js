/**
 * Regression Test Suite R1 - R8 for Management Network SSH/Telnet Risk Detection
 * Tests TCP vs UDP protocol isolation and CIDR subnet membership for Port 22/23
 */

globalThis.localStorage = {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {}
};

import { analyzeACL } from './src/core/analyzer.js';
import { createDefaultRule, ACTIONS, PROTOCOLS, ADDRESS_TYPES } from './src/core/types.js';

let passed = 0;
let failed = 0;

function runRTest(id, proto, dstIp, dstPort, expectedExists) {
  const r = createDefaultRule(1);
  r.protocol = proto;
  r.dstType = ADDRESS_TYPES.HOST;
  r.dstIp = dstIp;
  r.dstPortOperator = 'eq';
  r.dstPort = dstPort;
  r.action = ACTIONS.PERMIT;

  const warnings = analyzeACL({ type: 'extended_named' }, [r]);
  const hasMgmtRisk = warnings.some(w => w.id.includes('risk-mgmt-ssh'));

  if (hasMgmtRisk === expectedExists) {
    passed++;
    console.log(`[PASS] ${id}: ${proto.toUpperCase()}/${dstPort} -> ${dstIp} (Expected risk: ${expectedExists}, Actual: ${hasMgmtRisk})`);
  } else {
    failed++;
    console.error(`[FAIL] ${id}: ${proto.toUpperCase()}/${dstPort} -> ${dstIp} (Expected risk: ${expectedExists}, Actual: ${hasMgmtRisk})`);
  }
}

console.log("==================================================================");
console.log("  MANAGEMENT RISK REGRESSION SUITE (R1 - R8)");
console.log("==================================================================\n");

runRTest('R1', PROTOCOLS.TCP, '10.20.40.20', '22', true);
runRTest('R2', PROTOCOLS.TCP, '10.20.40.20', '23', true);
runRTest('R3', PROTOCOLS.UDP, '10.20.40.20', '22', false);
runRTest('R4', PROTOCOLS.UDP, '10.20.40.20', '23', false);
runRTest('R5', PROTOCOLS.TCP, '10.140.0.1',  '22', false);
runRTest('R6', PROTOCOLS.UDP, '10.140.0.1',  '22', false);
runRTest('R7', PROTOCOLS.TCP, '10.20.40.20', '80', false);
runRTest('R8', PROTOCOLS.UDP, '10.20.40.20', '80', false);

console.log("\n==================================================================");
console.log(`  REGRESSION RESULTS: ${passed} PASSED / ${failed} FAILED`);
console.log("==================================================================\n");

if (failed > 0) {
  process.exitCode = 1;
}
