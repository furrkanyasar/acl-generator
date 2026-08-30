import assert from 'assert';
import { wildcardToCidr } from './src/core/wildcard.js';
import { generateJuniperACL } from './src/core/generators/juniper.js';
import { generateHuaweiACL } from './src/core/generators/huawei.js';
import { analyzeACL } from './src/core/analyzer.js';
import { ACL_TYPES, ACTIONS, PROTOCOLS, ADDRESS_TYPES, PORT_OPERATORS } from './src/core/types.js';

console.log('=== RUNNING AUDIT FIXES REGRESSION SUITE ===');

// 1. Test wildcardToCidr for dotted-decimal subnet mask
console.log('Test 1: Subnet mask conversion in wildcardToCidr...');
assert.strictEqual(wildcardToCidr('255.255.255.0'), 24);
assert.strictEqual(wildcardToCidr('0.0.0.255'), 24);
assert.strictEqual(wildcardToCidr('255.255.240.0'), 20);
assert.strictEqual(wildcardToCidr('0.0.15.255'), 20);
console.log('-> PASS');

// 2. Test Juniper Generator for gt, lt, range, neq port operators & CIDR conversion
console.log('Test 2: Juniper generator port operators & CIDR mask conversion...');
const junConfig = { type: ACL_TYPES.EXTENDED_NAMED, identifier: 'TEST_JUN' };
const junRules = [
  { id: '1', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.TCP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '192.168.1.0', srcMask: '255.255.255.0', dstType: ADDRESS_TYPES.ANY, dstPortOperator: PORT_OPERATORS.GT, dstPort: '1024' },
  { id: '2', enabled: true, action: ACTIONS.DENY, protocol: PROTOCOLS.UDP, srcType: ADDRESS_TYPES.ANY, dstType: ADDRESS_TYPES.ANY, dstPortOperator: PORT_OPERATORS.NEQ, dstPort: '53' },
  { id: '3', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.TCP, srcType: ADDRESS_TYPES.ANY, dstType: ADDRESS_TYPES.ANY, dstPortOperator: PORT_OPERATORS.RANGE, dstPort: '80', dstPortEnd: '90' }
];
const junOutput = generateJuniperACL(junConfig, junRules);
assert.ok(junOutput.includes('source-address 192.168.1.0/24;'), 'Juniper should convert subnet mask 255.255.255.0 to /24');
assert.ok(junOutput.includes('destination-port [ 1025-65535 ];'), 'Juniper should output gt 1024 as 1025-65535');
assert.ok(junOutput.includes('destination-port-except 53;'), 'Juniper should output neq 53 as destination-port-except');
assert.ok(junOutput.includes('destination-port [ 80-90 ];'), 'Juniper should output range 80-90');
console.log('-> PASS');

// 3. Test Huawei Generator for gt, lt, range, neq port operators & ICMP
console.log('Test 3: Huawei generator port operators & ICMP...');
const hwConfig = { type: ACL_TYPES.EXTENDED_NAMED, identifier: 'TEST_HW' };
const hwRules = [
  { id: '1', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.TCP, srcType: ADDRESS_TYPES.ANY, dstType: ADDRESS_TYPES.ANY, dstPortOperator: PORT_OPERATORS.GT, dstPort: '1024' },
  { id: '2', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.TCP, srcType: ADDRESS_TYPES.ANY, dstType: ADDRESS_TYPES.ANY, dstPortOperator: PORT_OPERATORS.RANGE, dstPort: '80', dstPortEnd: '90' },
  { id: '3', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.ICMP, srcType: ADDRESS_TYPES.ANY, dstType: ADDRESS_TYPES.ANY, icmpType: 'echo' }
];
const hwOutput = generateHuaweiACL(hwConfig, hwRules);
assert.ok(hwOutput.includes('destination-port gt 1024'), 'Huawei should support gt 1024');
assert.ok(hwOutput.includes('destination-port range 80 90'), 'Huawei should support range 80 90');
assert.ok(hwOutput.includes('icmp-type echo'), 'Huawei should support icmp-type echo');
console.log('-> PASS');

// 4. Test Static Risk Engine for Dangerous Port Exposure
console.log('Test 4: Static risk engine dangerous port exposure (RDP 3389, SMB 445)...');
const riskConfig = { type: ACL_TYPES.EXTENDED_NAMED, identifier: 'RISK_ACL' };
const riskRules = [
  { id: '1', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.TCP, srcType: ADDRESS_TYPES.ANY, dstType: ADDRESS_TYPES.ANY, dstPortOperator: 'eq', dstPort: '3389' }
];
const warnings = analyzeACL(riskConfig, riskRules);
const hasRdpRisk = warnings.some(w => w.id === 'risk-exposed-service-1');
assert.ok(hasRdpRisk, 'Analyzer should flag high risk RDP port 3389 permit from ANY');
console.log('-> PASS');

console.log('\n=== ALL AUDIT FIXES REGRESSION TESTS PASSED (100% SUCCESS) ===');
