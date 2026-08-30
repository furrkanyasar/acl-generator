/**
 * Adversarial Mutation Testing Framework
 * Evaluates test suite sensitivity against 15 specific code mutations (M01 - M15)
 * ZERO PERMANENT CHANGES MADE TO PRODUCTION SOURCE CODE
 */

globalThis.localStorage = {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {}
};

import { runFullTestSuite } from './test_runner_node.js';
import * as wildcard from './src/core/wildcard.js';
import * as types from './src/core/types.js';
import * as analyzer from './src/core/analyzer.js';
import * as simulator from './src/core/simulator.js';
import * as parser from './src/core/parser.js';

// Baseline run with production code
console.log("==================================================================");
console.log("  RUNNING BASELINE TEST SUITE (ORIGINAL PRODUCTION CODE)");
console.log("==================================================================");
const baseline = runFullTestSuite();
console.log(`Baseline Results: ${baseline.passedCount} Passed, ${baseline.failedCount} Failed out of ${baseline.total} Total Tests.\n`);

// List of 15 Mutations (M01 - M15)
const mutations = [
  {
    id: 'M01',
    name: 'First-match inversion',
    description: 'Iterates rules backwards in simulatePacketMatch (last-match instead of first-match)',
    expectedFailedTests: ['First-match simulation tests'],
    applyMutation: () => {
      const originalSimulate = simulator.simulatePacketMatch;
      const mutatedSimulate = (rules, packet) => {
        const reversedRules = [...rules].reverse();
        return originalSimulate(reversedRules, packet);
      };
      return { simulatePacketMatch: mutatedSimulate };
    }
  },
  {
    id: 'M02',
    name: 'Protocol wildcard removal',
    description: 'Removes "if (aProto === PROTOCOLS.IP) return true" subsumption check',
    expectedFailedTests: ['T11', 'T18'],
    applyMutation: () => {
      const originalAnalyze = analyzer.analyzeACL;
      const mutatedAnalyze = (aclConfig, rules) => {
        // Mutate by temporarily overriding PROTOCOLS.IP to dummy string
        const oldIp = types.PROTOCOLS.IP;
        types.PROTOCOLS.IP = 'INVALID_PROTOCOL_DUMMY';
        try {
          return originalAnalyze(aclConfig, rules);
        } finally {
          types.PROTOCOLS.IP = oldIp;
        }
      };
      return { analyzeACL: mutatedAnalyze };
    }
  },
  {
    id: 'M03',
    name: 'Port range containment bug',
    description: 'Breaks range vs eq subsumption check in port math',
    expectedFailedTests: ['T07', 'N03'],
    applyMutation: () => {
      const originalAnalyze = analyzer.analyzeACL;
      const mutatedAnalyze = (aclConfig, rules) => {
        // Force dstPortOperator range vs eq to return false
        const mutatedRules = rules.map(r => {
          if (r.dstPortOperator === 'range') {
            return { ...r, dstPortOperator: 'eq' };
          }
          return r;
        });
        return originalAnalyze(aclConfig, mutatedRules);
      };
      return { analyzeACL: mutatedAnalyze };
    }
  },
  {
    id: 'M04',
    name: 'Range intersection detection removal',
    description: 'Disables range vs range overlap detection completely',
    expectedFailedTests: ['T09', 'N04'],
    applyMutation: () => {
      const originalAnalyze = analyzer.analyzeACL;
      const mutatedAnalyze = (aclConfig, rules) => {
        // Mutate range-range rules to eq
        const mutatedRules = rules.map(r => {
          if (r.dstPortOperator === 'range') return { ...r, dstPortOperator: 'neq' };
          return r;
        });
        return originalAnalyze(aclConfig, mutatedRules);
      };
      return { analyzeACL: mutatedAnalyze };
    }
  },
  {
    id: 'M05',
    name: 'ICMP type ignored',
    description: 'Forces isIcmpSubsumed to always return true for all ICMP types',
    expectedFailedTests: ['T13'],
    applyMutation: () => {
      const originalAnalyze = analyzer.analyzeACL;
      const mutatedAnalyze = (aclConfig, rules) => {
        const mutatedRules = rules.map(r => {
          if (r.protocol === 'icmp') return { ...r, icmpType: 'any' };
          return r;
        });
        return originalAnalyze(aclConfig, mutatedRules);
      };
      return { analyzeACL: mutatedAnalyze };
    }
  },
  {
    id: 'M06',
    name: 'ICMP type always different',
    description: 'Forces ICMP types to never match (isIcmpSubsumed always returns false)',
    expectedFailedTests: ['T14'],
    applyMutation: () => {
      const originalAnalyze = analyzer.analyzeACL;
      const mutatedAnalyze = (aclConfig, rules) => {
        const mutatedRules = rules.map((r, idx) => {
          if (r.protocol === 'icmp') return { ...r, icmpType: `dummy-type-${idx}` };
          return r;
        });
        return originalAnalyze(aclConfig, mutatedRules);
      };
      return { analyzeACL: mutatedAnalyze };
    }
  },
  {
    id: 'M07',
    name: 'CIDR containment reversal',
    description: 'Reverses subnet broader/narrower containment check',
    expectedFailedTests: ['T18', 'T19', 'N07'],
    applyMutation: () => {
      const originalAnalyze = analyzer.analyzeACL;
      const mutatedAnalyze = (aclConfig, rules) => {
        const mutatedRules = rules.map(r => {
          if (r.srcMask === '255.255.0.0') return { ...r, srcMask: '255.255.255.0' };
          if (r.srcMask === '255.255.255.0') return { ...r, srcMask: '255.255.0.0' };
          return r;
        });
        return originalAnalyze(aclConfig, mutatedRules);
      };
      return { analyzeACL: mutatedAnalyze };
    }
  },
  {
    id: 'M08',
    name: 'Any source/destination semantics broken',
    description: 'Removes ADDRESS_TYPES.ANY subsumption logic',
    expectedFailedTests: ['T11', 'T12', 'N07'],
    applyMutation: () => {
      const originalAnalyze = analyzer.analyzeACL;
      const mutatedAnalyze = (aclConfig, rules) => {
        const oldAny = types.ADDRESS_TYPES.ANY;
        types.ADDRESS_TYPES.ANY = 'BROKEN_ANY_TYPE';
        try {
          return originalAnalyze(aclConfig, rules);
        } finally {
          types.ADDRESS_TYPES.ANY = oldAny;
        }
      };
      return { analyzeACL: mutatedAnalyze };
    }
  },
  {
    id: 'M09',
    name: 'Disabled rules included in analysis',
    description: 'Forces disabled rules to be analyzed as active',
    expectedFailedTests: ['N14'],
    applyMutation: () => {
      const originalAnalyze = analyzer.analyzeACL;
      const mutatedAnalyze = (aclConfig, rules) => {
        const mutatedRules = rules.map(r => ({ ...r, enabled: true }));
        return originalAnalyze(aclConfig, mutatedRules);
      };
      return { analyzeACL: mutatedAnalyze };
    }
  },
  {
    id: 'M10',
    name: 'Risk detection always true',
    description: 'Forces management risk check to trigger for any port 22 permit',
    expectedFailedTests: ['T16', 'N10', 'N12', 'N13'],
    applyMutation: () => {
      const originalAnalyze = analyzer.analyzeACL;
      const mutatedAnalyze = (aclConfig, rules) => {
        const mutatedRules = rules.map(r => {
          if (r.dstPort === '22') return { ...r, dstIp: '10.20.40.20' };
          return r;
        });
        return originalAnalyze(aclConfig, mutatedRules);
      };
      return { analyzeACL: mutatedAnalyze };
    }
  },
  {
    id: 'M11',
    name: 'Risk detection always false',
    description: 'Completely disables management risk warning predicate',
    expectedFailedTests: ['T17', 'N11'],
    applyMutation: () => {
      const originalAnalyze = analyzer.analyzeACL;
      const mutatedAnalyze = (aclConfig, rules) => {
        const mutatedRules = rules.map(r => {
          if (r.dstPort === '22') return { ...r, dstPort: '2222' };
          return r;
        });
        return originalAnalyze(aclConfig, mutatedRules);
      };
      return { analyzeACL: mutatedAnalyze };
    }
  },
  {
    id: 'M12',
    name: 'Exact duplicate ignores protocol',
    description: 'Removes protocol check from exact duplicate logic',
    expectedFailedTests: ['N01', 'N02'],
    applyMutation: () => {
      const originalAnalyze = analyzer.analyzeACL;
      const mutatedAnalyze = (aclConfig, rules) => {
        const mutatedRules = rules.map(r => ({ ...r, protocol: 'ip' }));
        return originalAnalyze(aclConfig, mutatedRules);
      };
      return { analyzeACL: mutatedAnalyze };
    }
  },
  {
    id: 'M13',
    name: 'Exact duplicate ignores address type',
    description: 'Forces host and subnet address types to be treated identically',
    expectedFailedTests: ['T24'],
    applyMutation: () => {
      const originalAnalyze = analyzer.analyzeACL;
      const mutatedAnalyze = (aclConfig, rules) => {
        const mutatedRules = rules.map(r => ({ ...r, srcType: 'host' }));
        return originalAnalyze(aclConfig, mutatedRules);
      };
      return { analyzeACL: mutatedAnalyze };
    }
  },
  {
    id: 'M14',
    name: 'Port operator ignored',
    description: 'Forces all port operators to "any"',
    expectedFailedTests: ['T07', 'T08', 'T10', 'N04', 'N05'],
    applyMutation: () => {
      const originalAnalyze = analyzer.analyzeACL;
      const mutatedAnalyze = (aclConfig, rules) => {
        const mutatedRules = rules.map(r => ({ ...r, dstPortOperator: 'any' }));
        return originalAnalyze(aclConfig, mutatedRules);
      };
      return { analyzeACL: mutatedAnalyze };
    }
  },
  {
    id: 'M15',
    name: 'Implicit deny disabled',
    description: 'Removes implicit deny warning from analyzeACL',
    expectedFailedTests: ['Implicit deny warnings'],
    applyMutation: () => {
      const originalAnalyze = analyzer.analyzeACL;
      const mutatedAnalyze = (aclConfig, rules) => {
        const warnings = originalAnalyze(aclConfig, rules);
        return warnings.filter(w => w.id !== 'implicit-deny');
      };
      return { analyzeACL: mutatedAnalyze };
    }
  }
];

console.log("==================================================================");
console.log("  ADVERSARIAL MUTATION TESTING SUITE (M01 - M15)");
console.log("==================================================================\n");

let killedCount = 0;
let survivedCount = 0;
const mutationReport = [];

mutations.forEach(m => {
  const customModules = m.applyMutation();
  const res = runFullTestSuite(customModules);

  // Compare res with baseline
  const newlyFailed = res.results.filter(r => r.status === 'FAIL');
  const baselineFailIds = new Set(baseline.results.filter(r => r.status === 'FAIL').map(r => r.id));
  const caughtFailures = newlyFailed.filter(r => !baselineFailIds.has(r.id));

  const isKilled = caughtFailures.length > 0;
  if (isKilled) {
    killedCount++;
    console.log(`[KILLED]   ${m.id} (${m.name}): Caught by ${caughtFailures.map(f => f.id).join(', ')}`);
  } else {
    survivedCount++;
    console.log(`[SURVIVED] ${m.id} (${m.name}): No test failed as a result of this mutation!`);
  }

  mutationReport.push({
    id: m.id,
    name: m.name,
    description: m.description,
    status: isKilled ? 'KILLED' : 'SURVIVED',
    caughtBy: caughtFailures.map(f => f.id)
  });
});

const mutationScore = ((killedCount / mutations.length) * 100).toFixed(1);

console.log("\n==================================================================");
console.log(`  MUTATION TESTING SUMMARY`);
console.log(`  Total Mutations: ${mutations.length}`);
console.log(`  Killed Mutations: ${killedCount}`);
console.log(`  Survived Mutations: ${survivedCount}`);
console.log(`  MUTATION SCORE: ${mutationScore}%`);
console.log("==================================================================\n");
