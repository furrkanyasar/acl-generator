/**
 * Traffic Packet Matcher & Simulator Engine
 */

import { ACTIONS, PROTOCOLS, ADDRESS_TYPES, normalizePort } from './types.js';
import { isValidIp, ipToInt, maskToWildcard } from './wildcard.js';

function matchIp(ruleType, ruleIp, ruleMask, ruleWildcard, packetIp) {
  if (ruleType === ADDRESS_TYPES.ANY) return true;
  if (!isValidIp(packetIp)) return false;

  if (ruleType === ADDRESS_TYPES.HOST) {
    return isValidIp(ruleIp) && ruleIp.trim() === packetIp.trim();
  }

  if (ruleType === ADDRESS_TYPES.SUBNET) {
    if (!isValidIp(ruleIp)) return false;
    let wildcard = maskToWildcard(ruleMask);
    if (!wildcard && ruleWildcard && isValidIp(ruleWildcard)) {
      wildcard = ruleWildcard;
    }
    if (!wildcard) return false;
    
    const wildInt = ipToInt(wildcard);
    const ruleNetInt = ipToInt(ruleIp);
    const pktIpInt = ipToInt(packetIp);

    return ((pktIpInt & ~wildInt) === (ruleNetInt & ~wildInt));
  }

  return false;
}

function matchPort(operator, rulePort, rulePortEnd, packetPort) {
  if (!operator || operator === 'any' || !rulePort) return true;
  const pPort = normalizePort(packetPort);
  const rPort = normalizePort(rulePort);
  if (pPort === null || rPort === null) return false;

  if (operator === 'eq') return pPort === rPort;
  if (operator === 'neq') return pPort !== rPort;
  if (operator === 'gt') return pPort > rPort;
  if (operator === 'lt') return pPort < rPort;
  if (operator === 'range' && rulePortEnd) {
    const rEnd = normalizePort(rulePortEnd);
    return rEnd !== null && pPort >= rPort && pPort <= rEnd;
  }
  return true;
}

export function simulatePacketMatch(rules, packet) {
  const activeRules = rules.filter(r => r.enabled);

  for (let i = 0; i < activeRules.length; i++) {
    const rule = activeRules[i];

    // 1. Protocol Match
    if (rule.protocol !== PROTOCOLS.IP && rule.protocol !== packet.protocol) {
      continue;
    }

    // 2. Source Address Match
    if (!matchIp(rule.srcType, rule.srcIp, rule.srcMask, rule.srcWildcard, packet.srcIp)) {
      continue;
    }

    // 3. Source Port Match (TCP/UDP)
    if ((packet.protocol === PROTOCOLS.TCP || packet.protocol === PROTOCOLS.UDP)) {
      if (!matchPort(rule.srcPortOperator, rule.srcPort, rule.srcPortEnd, packet.srcPort)) {
        continue;
      }
    }

    // 4. Destination Address Match
    if (!matchIp(rule.dstType, rule.dstIp, rule.dstMask, rule.dstWildcard, packet.dstIp)) {
      continue;
    }

    // 5. Destination Port Match (TCP/UDP)
    if ((packet.protocol === PROTOCOLS.TCP || packet.protocol === PROTOCOLS.UDP)) {
      if (!matchPort(rule.dstPortOperator, rule.dstPort, rule.dstPortEnd, packet.dstPort)) {
        continue;
      }
    }

    // 6. ICMP Type Match
    if (packet.protocol === PROTOCOLS.ICMP && rule.icmpType && rule.icmpType !== 'any') {
      if (packet.icmpType && rule.icmpType !== packet.icmpType) {
        continue;
      }
    }

    // Exact Match Found!
    return {
      matched: true,
      matchedIndex: i + 1,
      rule,
      action: rule.action
    };
  }

  // No match found -> Implicit Deny
  return {
    matched: false,
    implicitDeny: true,
    action: ACTIONS.DENY
  };
}
