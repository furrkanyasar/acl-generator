/**
 * Reverse Cisco IOS ACL Parser Module
 */

import { ACL_TYPES, ACTIONS, PROTOCOLS, ADDRESS_TYPES, createDefaultRule } from './types.js';
import { wildcardToCidr, intToIp, cidrToSubnetInt } from './wildcard.js';

/**
 * Converts Cisco wildcard mask (e.g. '0.0.0.255') to dotted subnet mask ('255.255.255.0')
 */
function wildcardToSubnetMask(wildcardStr) {
  const cidr = wildcardToCidr(wildcardStr);
  if (cidr === null) return wildcardStr;
  const maskInt = cidrToSubnetInt(cidr);
  return maskInt !== null ? intToIp(maskInt) : wildcardStr;
}

export function parseCiscoACLScript(rawText) {
  const lines = rawText.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('!'));
  
  let config = {
    type: ACL_TYPES.EXTENDED_NAMED,
    identifier: 'PARSED_ACL',
    interfaceName: '',
    interfaceDirection: 'in'
  };

  const rules = [];
  let currentRemark = '';
  let ruleCounter = 1;
  let currentInterface = '';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Check for interface context
    if (line.toLowerCase().startsWith('interface ')) {
      currentInterface = line.split(/\s+/)[1] || '';
      continue;
    }

    if (line.toLowerCase().startsWith('ip access-group ')) {
      const parts = line.split(/\s+/);
      if (parts.length >= 3) {
        config.identifier = parts[2];
        config.interfaceDirection = parts[3] || 'in';
        if (currentInterface) config.interfaceName = currentInterface;
      }
      continue;
    }

    // Check for named ACL header: ip access-list extended MY_ACL
    if (line.toLowerCase().startsWith('ip access-list ')) {
      const parts = line.split(/\s+/);
      if (parts.length >= 4) {
        const typeKeyword = parts[2].toLowerCase();
        config.type = typeKeyword === 'extended' ? ACL_TYPES.EXTENDED_NAMED : ACL_TYPES.STANDARD_NAMED;
        config.identifier = parts[3];
      }
      continue;
    }

    // Check for remark line
    if (line.toLowerCase().includes('remark ')) {
      const remarkIndex = line.toLowerCase().indexOf('remark ');
      currentRemark = line.substring(remarkIndex + 7).trim();
      continue;
    }

    // Process Rule Line
    let tokens = line.split(/\s+/);
    if (tokens[0].toLowerCase() === 'access-list') {
      const num = parseInt(tokens[1], 10);
      if (!isNaN(num)) {
        config.identifier = tokens[1];
        if (num >= 100 && num <= 199) config.type = ACL_TYPES.EXTENDED_NUMBERED;
        else if (num >= 1 && num <= 99) config.type = ACL_TYPES.STANDARD_NUMBERED;
      }
      tokens = tokens.slice(2); // Strip 'access-list 101'
    }

    if (tokens.length === 0) continue;

    const actionCandidate = tokens[0].toLowerCase();
    if (actionCandidate !== ACTIONS.PERMIT && actionCandidate !== ACTIONS.DENY) {
      continue;
    }

    const rule = createDefaultRule(ruleCounter++);
    rule.action = actionCandidate;
    if (currentRemark) {
      rule.remark = currentRemark;
      currentRemark = '';
    }

    let idx = 1;

    // Check for log flag at the end
    if (tokens[tokens.length - 1].toLowerCase() === 'log') {
      rule.log = true;
      tokens.pop();
    }

    const isExtended = config.type.includes('extended');

    if (isExtended && idx < tokens.length) {
      const protoCandidate = tokens[idx].toLowerCase();
      if ([PROTOCOLS.IP, PROTOCOLS.TCP, PROTOCOLS.UDP, PROTOCOLS.ICMP].includes(protoCandidate)) {
        rule.protocol = protoCandidate;
        idx++;
      }
    }

    // Parse Source Address
    idx = parseAddressToken(tokens, idx, rule, 'src');

    // Parse Source Port (if TCP/UDP)
    if (isExtended && (rule.protocol === PROTOCOLS.TCP || rule.protocol === PROTOCOLS.UDP)) {
      idx = parsePortToken(tokens, idx, rule, 'src');
    }

    // Parse Destination Address (Extended Only)
    if (isExtended && idx < tokens.length) {
      idx = parseAddressToken(tokens, idx, rule, 'dst');
    }

    // Parse Destination Port (if TCP/UDP)
    if (isExtended && (rule.protocol === PROTOCOLS.TCP || rule.protocol === PROTOCOLS.UDP)) {
      idx = parsePortToken(tokens, idx, rule, 'dst');
    }

    // Parse ICMP Type (if ICMP)
    if (isExtended && rule.protocol === PROTOCOLS.ICMP && idx < tokens.length) {
      rule.icmpType = tokens[idx].toLowerCase();
      idx++;
    }

    rules.push(rule);
  }

  return { config, rules };
}

function parseAddressToken(tokens, idx, rule, prefix) {
  if (idx >= tokens.length) return idx;

  const t0 = tokens[idx].toLowerCase();
  if (t0 === 'any') {
    rule[`${prefix}Type`] = ADDRESS_TYPES.ANY;
    return idx + 1;
  }

  if (t0 === 'host' && idx + 1 < tokens.length) {
    rule[`${prefix}Type`] = ADDRESS_TYPES.HOST;
    rule[`${prefix}Ip`] = tokens[idx + 1];
    return idx + 2;
  }

  // Subnet network: <IP> <WILDCARD>
  if (idx + 1 < tokens.length) {
    rule[`${prefix}Type`] = ADDRESS_TYPES.SUBNET;
    rule[`${prefix}Ip`] = tokens[idx];
    rule[`${prefix}Wildcard`] = tokens[idx + 1];
    rule[`${prefix}Mask`] = wildcardToSubnetMask(tokens[idx + 1]);
    return idx + 2;
  }

  return idx + 1;
}

function parsePortToken(tokens, idx, rule, prefix) {
  if (idx >= tokens.length) return idx;

  const op = tokens[idx].toLowerCase();
  if (['eq', 'neq', 'gt', 'lt'].includes(op) && idx + 1 < tokens.length) {
    rule[`${prefix}PortOperator`] = op;
    rule[`${prefix}Port`] = tokens[idx + 1];
    return idx + 2;
  }

  if (op === 'range' && idx + 2 < tokens.length) {
    rule[`${prefix}PortOperator`] = 'range';
    rule[`${prefix}Port`] = tokens[idx + 1];
    rule[`${prefix}PortEnd`] = tokens[idx + 2];
    return idx + 3;
  }

  return idx;
}
