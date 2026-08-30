/**
 * Generative Property-Based Interval Math Verification
 * Runs 100 randomized interval overlap iterations to verify interval algebra correctness
 */

globalThis.localStorage = {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {}
};

import { analyzeACL } from './src/core/analyzer.js';
import { createDefaultRule, ACTIONS, PROTOCOLS } from './src/core/types.js';

let passed = 0;
let failed = 0;

for (let i = 0; i < 100; i++) {
  const startA = Math.floor(Math.random() * 5000) + 1;
  const rangeLenA = Math.floor(Math.random() * 5000);
  const endA = startA + rangeLenA;

  const startB = Math.floor(Math.random() * 5000) + 1;
  const rangeLenB = Math.floor(Math.random() * 5000);
  const endB = startB + rangeLenB;

  const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.TCP; r1.dstPortOperator = 'range'; r1.dstPort = String(startA); r1.dstPortEnd = String(endA); r1.action = ACTIONS.PERMIT;
  const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.TCP; r2.dstPortOperator = 'range'; r2.dstPort = String(startB); r2.dstPortEnd = String(endB); r2.action = ACTIONS.DENY;

  const warnings = analyzeACL({ type: 'extended_named' }, [r1, r2]);

  const maxStart = Math.max(startA, startB);
  const minEnd = Math.min(endA, endB);
  const expectedOverlap = maxStart <= minEnd;
  const expectedFullSubsume = startA <= startB && endA >= endB;

  const hasFullWarn = warnings.some(w => w.id === 'shadowed-2' && w.title.includes('FULLY SHADOWED'));
  const hasPartialWarn = warnings.some(w => w.id === 'partial-2' || (w.title && w.title.includes('PARTIAL')));

  if (expectedFullSubsume) {
    if (hasFullWarn) passed++; else failed++;
  } else if (expectedOverlap) {
    if (hasPartialWarn) passed++; else failed++;
  } else {
    if (!hasFullWarn && !hasPartialWarn) passed++; else failed++;
  }
}

console.log("==================================================================");
console.log(`  PROPERTY-BASED INTERVAL TESTS: ${passed} PASSED / ${failed} FAILED (100 Iterations)`);
console.log("==================================================================\n");
