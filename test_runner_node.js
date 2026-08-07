/**
 * Hardened Production Node.js Integration Test Suite for ACL Generator & Policy Analyzer
 * Uses structured, localization-independent metadata assertions (id, severity, type, originalIndex)
 * Sets process.exitCode = 1 when any test fails.
 */

if (typeof globalThis.localStorage === 'undefined') {
  globalThis.localStorage = {
    getItem: () => null,
    setItem: () => {},
    removeItem: () => {}
  };
}

import { isValidIp, maskToWildcard, calculateNetworkAddress } from './src/core/wildcard.js';
import { normalizePort, createDefaultRule, ACTIONS, PROTOCOLS, ADDRESS_TYPES } from './src/core/types.js';
import { analyzeACL } from './src/core/analyzer.js';
import { simulatePacketMatch } from './src/core/simulator.js';
import { parseCiscoACLScript } from './src/core/parser.js';

export function runFullTestSuite(customModules = {}) {
  const _isValidIp = customModules.isValidIp || isValidIp;
  const _maskToWildcard = customModules.maskToWildcard || maskToWildcard;
  const _calculateNetworkAddress = customModules.calculateNetworkAddress || calculateNetworkAddress;
  const _analyzeACL = customModules.analyzeACL || analyzeACL;
  const _simulatePacketMatch = customModules.simulatePacketMatch || simulatePacketMatch;
  const _parseCiscoACLScript = customModules.parseCiscoACLScript || parseCiscoACLScript;

  let passedCount = 0;
  let failedCount = 0;
  const results = [];

  function runTest(id, funcName, inputDesc, expectedDesc, evaluateFn) {
    try {
      const { pass, actual } = evaluateFn();
      if (pass) {
        passedCount++;
        results.push({ id, funcName, inputDesc, expectedDesc, actual: String(actual), status: 'PASS' });
      } else {
        failedCount++;
        results.push({ id, funcName, inputDesc, expectedDesc, actual: String(actual), status: 'FAIL' });
      }
    } catch (err) {
      failedCount++;
      results.push({ id, funcName, inputDesc, expectedDesc, actual: `ERROR: ${err.message}`, status: 'FAIL' });
    }
  }

  // --- WILDCARD / TYPES TESTS (T01 - T06) ---
  runTest('T01', 'maskToWildcard', '255.255.255.0', '0.0.0.255', () => {
    const actual = _maskToWildcard('255.255.255.0');
    return { pass: actual === '0.0.0.255', actual };
  });

  runTest('T02', 'maskToWildcard', '255.255.240.0', '0.0.15.255', () => {
    const actual = _maskToWildcard('255.255.240.0');
    return { pass: actual === '0.0.15.255', actual };
  });

  runTest('T03', 'maskToWildcard', '24', '0.0.0.255', () => {
    const actual = _maskToWildcard('24');
    return { pass: actual === '0.0.0.255', actual };
  });

  runTest('T04', 'isValidIp', '10.20.10.1', 'true', () => {
    const actual = _isValidIp('10.20.10.1');
    return { pass: actual === true, actual };
  });

  runTest('T05', 'isValidIp', '256.1.1.1', 'false', () => {
    const actual = _isValidIp('256.1.1.1');
    return { pass: actual === false, actual };
  });

  runTest('T06', 'isValidIp', '10.20.10.01 (Leading zero)', 'false', () => {
    const actual = _isValidIp('10.20.10.01');
    return { pass: actual === false, actual };
  });

  // --- ANALYZER TESTS (T07 - T14) STRUCTURED METADATA ASSERTIONS ---
  runTest('T07', 'analyzeACL', 'permit tcp range 1000 2000 vs deny tcp eq 1500', 'shadowed-2 warning present', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.TCP; r1.dstPortOperator = 'range'; r1.dstPort = '1000'; r1.dstPortEnd = '2000'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.TCP; r2.dstPortOperator = 'eq'; r2.dstPort = '1500'; r2.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const hasShadow = warnings.some(w => w.id === 'shadowed-2' && w.severity === 'error');
    return { pass: hasShadow, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('T08', 'analyzeACL', 'permit tcp range 1000 2000 vs deny tcp eq 3000', 'No shadow warning for ACE #2', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.TCP; r1.dstPortOperator = 'range'; r1.dstPort = '1000'; r1.dstPortEnd = '2000'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.TCP; r2.dstPortOperator = 'eq'; r2.dstPort = '3000'; r2.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const hasShadow = warnings.some(w => w.id === 'shadowed-2' || w.id === 'partial-2');
    return { pass: !hasShadow, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('T09', 'analyzeACL', 'permit tcp range 1000 2000 vs deny tcp range 1500 2500', 'partial-2 warning present', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.TCP; r1.dstPortOperator = 'range'; r1.dstPort = '1000'; r1.dstPortEnd = '2000'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.TCP; r2.dstPortOperator = 'range'; r2.dstPort = '1500'; r2.dstPortEnd = '2500'; r2.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const hasPartial = warnings.some(w => w.id === 'partial-2' && w.type === 'warning');
    return { pass: hasPartial, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('T10', 'analyzeACL', 'permit tcp eq 443 vs deny tcp eq 22', 'No overlap warning', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.TCP; r1.dstPortOperator = 'eq'; r1.dstPort = '443'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.TCP; r2.dstPortOperator = 'eq'; r2.dstPort = '22'; r2.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const hasShadow = warnings.some(w => w.id === 'shadowed-2' || w.id === 'partial-2');
    return { pass: !hasShadow, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('T11', 'analyzeACL', 'permit ip any any vs deny tcp eq 22', 'shadowed-2 warning present', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.IP; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.TCP; r2.dstPortOperator = 'eq'; r2.dstPort = '22'; r2.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const hasShadow = warnings.some(w => w.id === 'shadowed-2' && w.severity === 'error');
    return { pass: hasShadow, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('T12', 'analyzeACL', 'permit tcp eq 443 vs deny ip any any', 'ACE #2 NOT fully shadowed', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.TCP; r1.dstPortOperator = 'eq'; r1.dstPort = '443'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.IP; r2.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const hasFullShadow = warnings.some(w => w.id === 'shadowed-2' && w.severity === 'error');
    return { pass: !hasFullShadow, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('T13', 'analyzeACL', 'permit icmp echo vs deny icmp echo-reply', 'No overlap warning', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.ICMP; r1.icmpType = 'echo'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.ICMP; r2.icmpType = 'echo-reply'; r2.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const hasShadow = warnings.some(w => w.id === 'shadowed-2' || w.id === 'partial-2');
    return { pass: !hasShadow, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('T14', 'analyzeACL', 'permit icmp echo vs deny icmp echo', 'Full shadow warning', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.ICMP; r1.icmpType = 'echo'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.ICMP; r2.icmpType = 'echo'; r2.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const hasShadow = warnings.some(w => w.id === 'shadowed-2' && w.severity === 'error');
    return { pass: hasShadow, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('T15', 'analyzeACL', 'ACE #1 enabled, ACE #2 disabled, ACE #3 enabled & shadowed', 'Warning ID shadowed-3 linked to Rule 3', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.IP; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.enabled = false; r2.protocol = PROTOCOLS.UDP; r2.action = ACTIONS.DENY;
    const r3 = createDefaultRule(3); r3.protocol = PROTOCOLS.TCP; r3.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2, r3]);
    const hasShadow3 = warnings.some(w => w.id === 'shadowed-3');
    return { pass: hasShadow3, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('T16', 'analyzeACL', 'permit tcp 10.20.10.0/24 host 10.140.0.1 eq 22', 'No Management VLAN risk warning (10.140.0.1 != 10.20.40.0/24)', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.TCP; r1.srcType = ADDRESS_TYPES.SUBNET; r1.srcIp = '10.20.10.0'; r1.srcMask = '255.255.255.0'; r1.dstType = ADDRESS_TYPES.HOST; r1.dstIp = '10.140.0.1'; r1.dstPortOperator = 'eq'; r1.dstPort = '22'; r1.action = ACTIONS.PERMIT;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1]);
    const hasMgmtRisk = warnings.some(w => w.id.includes('risk-mgmt-ssh'));
    return { pass: !hasMgmtRisk, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('T17', 'analyzeACL', 'permit tcp 10.20.10.0/24 host 10.20.40.20 eq 22', 'Management VLAN risk warning triggered', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.TCP; r1.srcType = ADDRESS_TYPES.SUBNET; r1.srcIp = '10.20.10.0'; r1.srcMask = '255.255.255.0'; r1.dstType = ADDRESS_TYPES.HOST; r1.dstIp = '10.20.40.20'; r1.dstPortOperator = 'eq'; r1.dstPort = '22'; r1.action = ACTIONS.PERMIT;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1]);
    const hasMgmtRisk = warnings.some(w => w.id.includes('risk-mgmt-ssh'));
    return { pass: hasMgmtRisk, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('T18', 'analyzeACL', 'permit ip 10.20.0.0/16 any vs deny ip 10.20.10.0/24 any', 'shadowed-2 warning present', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.IP; r1.srcType = ADDRESS_TYPES.SUBNET; r1.srcIp = '10.20.0.0'; r1.srcMask = '255.255.0.0'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.IP; r2.srcType = ADDRESS_TYPES.SUBNET; r2.srcIp = '10.20.10.0'; r2.srcMask = '255.255.255.0'; r2.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const hasFullShadow = warnings.some(w => w.id === 'shadowed-2' && w.severity === 'error');
    return { pass: hasFullShadow, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('T19', 'analyzeACL', 'deny ip 10.20.10.0/24 any vs permit ip 10.20.0.0/16 any', 'ACE #2 NOT fully shadowed', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.IP; r1.srcType = ADDRESS_TYPES.SUBNET; r1.srcIp = '10.20.10.0'; r1.srcMask = '255.255.255.0'; r1.action = ACTIONS.DENY;
    const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.IP; r2.srcType = ADDRESS_TYPES.SUBNET; r2.srcIp = '10.20.0.0'; r2.srcMask = '255.255.0.0'; r2.action = ACTIONS.PERMIT;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const hasFullShadow = warnings.some(w => w.id === 'shadowed-2' && w.severity === 'error');
    return { pass: !hasFullShadow, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('T20', 'calculateNetworkAddress', 'Non-canonical subnet 10.20.10.50 /24 normalization', 'Calculates network IP 10.20.10.0', () => {
    const netIp = _calculateNetworkAddress('10.20.10.50', '24');
    return { pass: netIp === '10.20.10.0', actual: netIp };
  });

  runTest('T21', 'parseCiscoACLScript & analyzeACL', 'parse Cisco ICMP rules & analyze', 'Parser extracts icmpType; analyzer detects no shadow', () => {
    const script = `ip access-list extended TEST_ICMP\n permit icmp any any echo\n deny icmp any any echo-reply`;
    const { rules } = _parseCiscoACLScript(script);
    const r1 = rules[0]; const r2 = rules[1];
    const warnings = _analyzeACL({ type: 'extended_named' }, rules);
    const hasShadow = warnings.some(w => w.id === 'shadowed-2');
    const pass = r1.icmpType === 'echo' && r2.icmpType === 'echo-reply' && !hasShadow;
    return { pass, actual: `r1.icmpType=${r1.icmpType}, r2.icmpType=${r2.icmpType}, warnings=${JSON.stringify(warnings.map(w => w.id))}` };
  });

  runTest('T22', 'analyzeACL', 'Two identical ACEs', 'Detects DUPLICATE ACE (shadowed-2 warning)', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.TCP; r1.dstPortOperator = 'eq'; r1.dstPort = '80'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.TCP; r2.dstPortOperator = 'eq'; r2.dstPort = '80'; r2.action = ACTIONS.PERMIT;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const isDuplicate = warnings.some(w => w.id === 'shadowed-2' && w.severity === 'warning');
    return { pass: isDuplicate, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('T23', 'analyzeACL', 'host 10.20.10.1 vs subnet 10.20.10.1 0.0.0.0 representation', 'Detects REDUNDANT ACE (shadowed-2 warning)', () => {
    const r1 = createDefaultRule(1); r1.srcType = ADDRESS_TYPES.HOST; r1.srcIp = '10.20.10.1'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.srcType = ADDRESS_TYPES.SUBNET; r2.srcIp = '10.20.10.1'; r2.srcMask = '255.255.255.255'; r2.action = ACTIONS.PERMIT;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const isDup = warnings.some(w => w.id === 'shadowed-2' && w.severity === 'warning');
    return { pass: isDup, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('T24', 'analyzeACL', 'Same IP/port but different srcType (HOST vs SUBNET /24)', 'Must NOT classify as DUPLICATE if srcTypes differ', () => {
    const r1 = createDefaultRule(1); r1.srcType = ADDRESS_TYPES.HOST; r1.srcIp = '10.20.10.1'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.srcType = ADDRESS_TYPES.SUBNET; r2.srcIp = '10.20.10.0'; r2.srcMask = '255.255.255.0'; r2.action = ACTIONS.PERMIT;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const isExactDup = warnings.some(w => w.id === 'shadowed-2' && w.severity === 'warning' && w.title.includes('DUPLICATE ACE'));
    return { pass: !isExactDup, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  // --- NEGATIVE & ADVERSARIAL EDGE CASE TESTS (N01 - N17) ---
  runTest('N01', 'analyzeACL', 'tcp/443 vs udp/443', 'No overlap between TCP and UDP', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.TCP; r1.dstPortOperator = 'eq'; r1.dstPort = '443'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.UDP; r2.dstPortOperator = 'eq'; r2.dstPort = '443'; r2.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const hasShadow = warnings.some(w => w.id === 'shadowed-2' || w.id === 'partial-2');
    return { pass: !hasShadow, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('N02', 'analyzeACL', 'icmp/echo vs tcp/echo', 'No overlap between ICMP and TCP', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.ICMP; r1.icmpType = 'echo'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.TCP; r2.dstPortOperator = 'eq'; r2.dstPort = '8'; r2.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const hasShadow = warnings.some(w => w.id === 'shadowed-2' || w.id === 'partial-2');
    return { pass: !hasShadow, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('N03', 'analyzeACL', 'tcp eq 1500 vs tcp range 1000-2000', 'Rule 2 is NOT fully subsumed by Rule 1 (Rule 1 is narrower)', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.TCP; r1.dstPortOperator = 'eq'; r1.dstPort = '1500'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.TCP; r2.dstPortOperator = 'range'; r2.dstPort = '1000'; r2.dstPortEnd = '2000'; r2.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const hasFullShadow = warnings.some(w => w.id === 'shadowed-2' && w.severity === 'error');
    return { pass: !hasFullShadow, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('N04', 'analyzeACL', 'range 1000-2000 vs range 2000-3000 boundary', 'Boundary port 2000 overlaps (partial-2 warning)', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.TCP; r1.dstPortOperator = 'range'; r1.dstPort = '1000'; r1.dstPortEnd = '2000'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.TCP; r2.dstPortOperator = 'range'; r2.dstPort = '2000'; r2.dstPortEnd = '3000'; r2.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const hasPartial = warnings.some(w => w.id === 'partial-2');
    return { pass: hasPartial, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('N05', 'analyzeACL', 'range 1000-2000 vs range 2001-3000 (adjacent ranges)', 'No overlap between adjacent ranges', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.TCP; r1.dstPortOperator = 'range'; r1.dstPort = '1000'; r1.dstPortEnd = '2000'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.TCP; r2.dstPortOperator = 'range'; r2.dstPort = '2001'; r2.dstPortEnd = '3000'; r2.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const hasShadow = warnings.some(w => w.id === 'shadowed-2' || w.id === 'partial-2');
    return { pass: !hasShadow, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('N06', 'analyzeACL', '10.20.10.0/24 vs 10.20.11.0/24 (disjoint subnets)', 'No overlap between disjoint subnets', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.IP; r1.srcType = ADDRESS_TYPES.SUBNET; r1.srcIp = '10.20.10.0'; r1.srcMask = '255.255.255.0'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.IP; r2.srcType = ADDRESS_TYPES.SUBNET; r2.srcIp = '10.20.11.0'; r2.srcMask = '255.255.255.0'; r2.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const hasShadow = warnings.some(w => w.id === 'shadowed-2' || w.id === 'partial-2');
    return { pass: !hasShadow, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('N07', 'analyzeACL', '10.20.10.0/24 vs 10.20.10.128/25 (subnet containment)', 'Rule 1 (/24) fully subsumes Rule 2 (/25)', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.IP; r1.srcType = ADDRESS_TYPES.SUBNET; r1.srcIp = '10.20.10.0'; r1.srcMask = '255.255.255.0'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.IP; r2.srcType = ADDRESS_TYPES.SUBNET; r2.srcIp = '10.20.10.128'; r2.srcMask = '255.255.255.128'; r2.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const hasFullShadow = warnings.some(w => w.id === 'shadowed-2' && w.severity === 'error');
    return { pass: hasFullShadow, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('N08', 'analyzeACL', 'host 10.20.10.1 vs host 10.20.10.2', 'No overlap between different hosts', () => {
    const r1 = createDefaultRule(1); r1.srcType = ADDRESS_TYPES.HOST; r1.srcIp = '10.20.10.1'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.srcType = ADDRESS_TYPES.HOST; r2.srcIp = '10.20.10.2'; r2.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const hasShadow = warnings.some(w => w.id === 'shadowed-2' || w.id === 'partial-2');
    return { pass: !hasShadow, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('N09', 'analyzeACL', 'host 10.20.10.1 vs subnet 10.20.10.1 255.255.255.255', 'Semantic equivalence between host and /32 subnet', () => {
    const r1 = createDefaultRule(1); r1.srcType = ADDRESS_TYPES.HOST; r1.srcIp = '10.20.10.1'; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.srcType = ADDRESS_TYPES.SUBNET; r2.srcIp = '10.20.10.1'; r2.srcMask = '255.255.255.255'; r2.action = ACTIONS.PERMIT;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const isDup = warnings.some(w => w.id === 'shadowed-2');
    return { pass: isDup, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('N10', 'analyzeACL', '10.140.0.1 destination', 'No management risk warning for 10.140.0.1', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.TCP; r1.dstType = ADDRESS_TYPES.HOST; r1.dstIp = '10.140.0.1'; r1.dstPortOperator = 'eq'; r1.dstPort = '22'; r1.action = ACTIONS.PERMIT;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1]);
    const hasRisk = warnings.some(w => w.id.includes('risk-mgmt-ssh'));
    return { pass: !hasRisk, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('N11', 'analyzeACL', '10.20.40.1 destination', 'Management risk warning SHOULD trigger for 10.20.40.1', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.TCP; r1.dstType = ADDRESS_TYPES.HOST; r1.dstIp = '10.20.40.1'; r1.dstPortOperator = 'eq'; r1.dstPort = '22'; r1.action = ACTIONS.PERMIT;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1]);
    const hasRisk = warnings.some(w => w.id.includes('risk-mgmt-ssh'));
    return { pass: hasRisk, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('N12', 'analyzeACL', '192.168.40.1 destination', 'No management risk warning for 192.168.40.1', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.TCP; r1.dstType = ADDRESS_TYPES.HOST; r1.dstIp = '192.168.40.1'; r1.dstPortOperator = 'eq'; r1.dstPort = '22'; r1.action = ACTIONS.PERMIT;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1]);
    const hasRisk = warnings.some(w => w.id.includes('risk-mgmt-ssh'));
    return { pass: !hasRisk, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('N13', 'analyzeACL', '10.20.140.1 destination', 'No management risk warning for 10.20.140.1', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.TCP; r1.dstType = ADDRESS_TYPES.HOST; r1.dstIp = '10.20.140.1'; r1.dstPortOperator = 'eq'; r1.dstPort = '22'; r1.action = ACTIONS.PERMIT;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1]);
    const hasRisk = warnings.some(w => w.id.includes('risk-mgmt-ssh'));
    return { pass: !hasRisk, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('N14', 'analyzeACL', 'Disabled ACE must not shadow active ACE', 'ACE #2 disabled, ACE #3 active must NOT be shadowed by ACE #2', () => {
    const r1 = createDefaultRule(1); r1.enabled = false; r1.protocol = PROTOCOLS.IP; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.enabled = true; r2.protocol = PROTOCOLS.TCP; r2.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const hasShadow = warnings.some(w => w.id === 'shadowed-2');
    return { pass: !hasShadow, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  runTest('N15', 'analyzeACL', 'ACE sequence identity vs array index', 'Diagnostic must report correct original rule ID/index', () => {
    const r1 = createDefaultRule(10); r1.id = '10'; r1.protocol = PROTOCOLS.IP; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(20); r2.id = '20'; r2.protocol = PROTOCOLS.TCP; r2.action = ACTIONS.DENY;
    const warnings = _analyzeACL({ type: 'extended_named' }, [r1, r2]);
    const shadowWarn = warnings.find(w => w.id === 'shadowed-20');
    const reportsRule20 = shadowWarn && (shadowWarn.id === 'shadowed-20' && shadowWarn.severity === 'error');
    return { pass: Boolean(reportsRule20), actual: shadowWarn ? shadowWarn.id : 'No warning' };
  });

  // --- ADDITIONAL SIMULATOR FIRST-MATCH & IMPLICIT DENY ASSERTIONS ---
  runTest('N16', 'simulatePacketMatch', 'First match priority assertion', 'Returns matchedIndex: 1 (PERMIT) when packet fits Rule 1 & Rule 2', () => {
    const r1 = createDefaultRule(1); r1.protocol = PROTOCOLS.TCP; r1.action = ACTIONS.PERMIT;
    const r2 = createDefaultRule(2); r2.protocol = PROTOCOLS.TCP; r2.action = ACTIONS.DENY;
    const res = _simulatePacketMatch([r1, r2], { protocol: PROTOCOLS.TCP, srcIp: '10.0.0.1', dstIp: '10.0.0.2', srcPort: '1024', dstPort: '80' });
    const pass = res.matched && res.matchedIndex === 1 && res.action === ACTIONS.PERMIT;
    return { pass, actual: `matchedIndex=${res.matchedIndex}, action=${res.action}` };
  });

  runTest('N17', 'analyzeACL', 'Implicit deny warning presence', 'analyzeACL must return implicit deny warning', () => {
    const warnings = _analyzeACL({ type: 'extended_named' }, []);
    const hasImplicit = warnings.some(w => w.id === 'implicit-deny');
    return { pass: hasImplicit, actual: JSON.stringify(warnings.map(w => w.id)) };
  });

  if (failedCount > 0) {
    process.exitCode = 1;
  }

  return { passedCount, failedCount, total: passedCount + failedCount, results };
}
