/**
 * ACL Analyzer & Static Security Risk Engine (Multi-Dimensional Analysis & Risk Engine)
 */

import { ACL_TYPES, ACTIONS, PROTOCOLS, ADDRESS_TYPES, normalizePort } from './types.js';
import { isValidIp, ipToInt, maskToWildcard, cidrToSubnetInt } from './wildcard.js';
import { t } from './i18n.js';

function isIpInSubnet(ip, subnetIp, subnetMask) {
  if (!isValidIp(ip) || !isValidIp(subnetIp)) return false;
  let maskInt = null;
  const str = subnetMask ? subnetMask.toString().trim().replace(/^\//, '') : '';
  if (/^\d+$/.test(str)) {
    maskInt = cidrToSubnetInt(parseInt(str, 10));
  } else if (isValidIp(str)) {
    maskInt = ipToInt(str);
  }
  if (maskInt === null) return false;
  return ((ipToInt(ip) & maskInt) >>> 0) === ((ipToInt(subnetIp) & maskInt) >>> 0);
}

function normalizeAddress(type, ip, mask) {
  if (type === ADDRESS_TYPES.ANY) {
    return { type: ADDRESS_TYPES.ANY, ip: '', mask: '' };
  }
  if (type === ADDRESS_TYPES.HOST) {
    return { type: ADDRESS_TYPES.HOST, ip: ip ? ip.trim() : '', mask: '255.255.255.255' };
  }
  if (type === ADDRESS_TYPES.SUBNET) {
    const w = maskToWildcard(mask);
    if (w === '0.0.0.0' || mask === '255.255.255.255' || mask === '32' || mask === '/32') {
      return { type: ADDRESS_TYPES.HOST, ip: ip ? ip.trim() : '', mask: '255.255.255.255' };
    }
    return { type: ADDRESS_TYPES.SUBNET, ip: ip ? ip.trim() : '', mask: mask || '' };
  }
  return { type, ip, mask };
}

function isIpSubsumed(aType, aIp, aMask, bType, bIp, bMask) {
  const normA = normalizeAddress(aType, aIp, aMask);
  const normB = normalizeAddress(bType, bIp, bMask);

  if (normA.type === ADDRESS_TYPES.ANY) return true;

  if (normA.type === ADDRESS_TYPES.HOST && normB.type === ADDRESS_TYPES.HOST) {
    return isValidIp(normA.ip) && isValidIp(normB.ip) && normA.ip === normB.ip;
  }

  if (normA.type === ADDRESS_TYPES.SUBNET && normB.type === ADDRESS_TYPES.HOST) {
    if (!isValidIp(normA.ip) || !isValidIp(normB.ip)) return false;
    return isIpInSubnet(normB.ip, normA.ip, normA.mask);
  }

  if (normA.type === ADDRESS_TYPES.SUBNET && normB.type === ADDRESS_TYPES.SUBNET) {
    if (!isValidIp(normA.ip) || !isValidIp(normB.ip)) return false;
    const aWildcard = maskToWildcard(normA.mask);
    const bWildcard = maskToWildcard(normB.mask);
    if (!aWildcard || !bWildcard) return false;
    
    const aWildInt = ipToInt(aWildcard);
    const bWildInt = ipToInt(bWildcard);
    const aIpInt = ipToInt(normA.ip);
    const bIpInt = ipToInt(normB.ip);

    const bSubnetFitsInA = ((bIpInt & ~aWildInt) >>> 0) === ((aIpInt & ~aWildInt) >>> 0);
    const aIsBroader = ((aWildInt & bWildInt) >>> 0) === bWildInt;
    return bSubnetFitsInA && aIsBroader;
  }

  return false;
}

function checkIpOverlap(aType, aIp, aMask, bType, bIp, bMask) {
  const normA = normalizeAddress(aType, aIp, aMask);
  const normB = normalizeAddress(bType, bIp, bMask);

  if (normA.type === ADDRESS_TYPES.ANY || normB.type === ADDRESS_TYPES.ANY) return true;
  if (isIpSubsumed(normA.type, normA.ip, normA.mask, normB.type, normB.ip, normB.mask)) return true;
  if (isIpSubsumed(normB.type, normB.ip, normB.mask, normA.type, normA.ip, normA.mask)) return true;
  return false;
}

function isProtocolSubsumed(aProto, bProto) {
  if (aProto === PROTOCOLS.IP) return true;
  return aProto === bProto;
}

function checkProtocolOverlap(aProto, bProto) {
  if (aProto === PROTOCOLS.IP || bProto === PROTOCOLS.IP) return true;
  return aProto === bProto;
}

function getPortInterval(op, port, portEnd) {
  if (!op || op === 'any') return { start: 1, end: 65535 };
  const p1 = normalizePort(port);
  if (p1 === null) return { start: 1, end: 65535 };

  if (op === 'eq') return { start: p1, end: p1 };
  if (op === 'gt') return { start: Math.min(65535, p1 + 1), end: 65535 };
  if (op === 'lt') return { start: 1, end: Math.max(1, p1 - 1) };
  if (op === 'range' && portEnd) {
    const p2 = normalizePort(portEnd);
    if (p2 !== null) return { start: Math.min(p1, p2), end: Math.max(p1, p2) };
  }
  if (op === 'neq') return { start: 1, end: 65535, neq: p1 };
  return { start: p1, end: p1 };
}

function isPortSubsumed(aOp, aPort, aPortEnd, bOp, bPort, bPortEnd) {
  if (aOp === 'neq') {
    const pA = normalizePort(aPort);
    if (bOp === 'neq') return pA === normalizePort(bPort);
    const intB = getPortInterval(bOp, bPort, bPortEnd);
    return pA !== null && (pA < intB.start || pA > intB.end);
  }
  if (bOp === 'neq') return !aOp || aOp === 'any';
  const intA = getPortInterval(aOp, aPort, aPortEnd);
  const intB = getPortInterval(bOp, bPort, bPortEnd);
  return intA.start <= intB.start && intA.end >= intB.end;
}

function checkPortOverlap(aOp, aPort, aPortEnd, bOp, bPort, bPortEnd) {
  if (aOp === 'neq' || bOp === 'neq') {
    const pA = aOp === 'neq' ? normalizePort(aPort) : null;
    const pB = bOp === 'neq' ? normalizePort(bPort) : null;
    if (pA !== null && pB !== null) return true;
    if (pA !== null) {
      const intB = getPortInterval(bOp, bPort, bPortEnd);
      return intB.start !== pA || intB.end !== pA;
    }
    if (pB !== null) {
      const intA = getPortInterval(aOp, aPort, aPortEnd);
      return intA.start !== pB || intA.end !== pB;
    }
  }
  const intA = getPortInterval(aOp, aPort, aPortEnd);
  const intB = getPortInterval(bOp, bPort, bPortEnd);
  const startMax = Math.max(intA.start, intB.start);
  const endMin = Math.min(intA.end, intB.end);
  return startMax <= endMin;
}

function isIcmpSubsumed(aIcmp, bIcmp) {
  if (!aIcmp || aIcmp === 'any') return true;
  return aIcmp === bIcmp;
}

function checkIcmpOverlap(aIcmp, bIcmp) {
  if (!aIcmp || aIcmp === 'any' || !bIcmp || bIcmp === 'any') return true;
  return aIcmp === bIcmp;
}

export function analyzeACL(aclConfig, rules) {
  const warnings = [];

  // 1. Implicit Deny Warning
  warnings.push({
    id: 'implicit-deny',
    type: 'warning',
    severity: 'important',
    title: t('implicitDenyTitle'),
    message: t('implicitDenyMsg')
  });

  // 2. Best Practice Placement Advice
  const isStandard = aclConfig.type === ACL_TYPES.STANDARD_NUMBERED || aclConfig.type === ACL_TYPES.STANDARD_NAMED;
  warnings.push({
    id: 'placement-advice',
    type: 'tip',
    severity: 'info',
    title: isStandard ? t('standardPlacementTitle') : t('extendedPlacementTitle'),
    message: isStandard ? t('standardPlacementMsg') : t('extendedPlacementMsg')
  });

  // 3. Interface Direction Note
  if (aclConfig.interfaceName) {
    const dirText = aclConfig.interfaceDirection === 'in'
      ? `${t('inboundDesc')} (${aclConfig.interfaceName})`
      : `${t('outboundDesc')} (${aclConfig.interfaceName})`;
    
    warnings.push({
      id: 'interface-direction',
      type: 'info',
      severity: 'info',
      title: `${t('interfaceDirTitle')} (${aclConfig.interfaceDirection.toUpperCase()})`,
      message: dirText
    });
  }

  // Map each rule to its original 1-based ACE index in the input array
  const indexedRules = rules.map((r, index) => ({ ...r, originalIndex: index + 1 }));
  const activeRules = indexedRules.filter(r => r.enabled);

  for (let i = 0; i < activeRules.length; i++) {
    const prevRule = activeRules[i];

    // Static Security Risk Assessment
    if (prevRule.action === ACTIONS.PERMIT) {
      // High Risk: Permit IP Any Any
      if (prevRule.protocol === PROTOCOLS.IP && prevRule.srcType === ADDRESS_TYPES.ANY && prevRule.dstType === ADDRESS_TYPES.ANY) {
        warnings.push({
          id: `risk-any-any-${prevRule.id}`,
          type: 'danger',
          severity: 'error',
          title: `🔴 HIGH RISK / VERY BROAD PERMIT (ACE #${prevRule.originalIndex})`,
          message: `ACE #${prevRule.originalIndex} permits unrestricted IP traffic from ANY source to ANY destination. Review recommended.`
        });
      }

      // High Risk: Permit SSH/Telnet to Management Network (10.20.40.0/24) via TCP
      const normDstPort = normalizePort(prevRule.dstPort);
      const isMgmtPort = normDstPort === 22 || normDstPort === 23 || prevRule.dstPort === '22' || prevRule.dstPort === '23';
      if (prevRule.protocol === PROTOCOLS.TCP && isMgmtPort && prevRule.dstIp && isIpInSubnet(prevRule.dstIp, '10.20.40.0', '255.255.255.0')) {
        warnings.push({
          id: `risk-mgmt-ssh-${prevRule.id}`,
          type: 'danger',
          severity: 'error',
          title: `🔴 HIGH RISK / MANAGEMENT ACCESS PERMIT (ACE #${prevRule.originalIndex})`,
          message: `ACE #${prevRule.originalIndex} permits direct administrative access (Port ${prevRule.dstPort}) to Management VLAN.`
        });
      }

      // High Risk: Permit Sensitive Enterprise Ports (RDP, SMB, NetBIOS, Telnet, DB) from ANY
      const DANGEROUS_PORTS = [23, 135, 137, 138, 139, 445, 1433, 3306, 3389, 5432];
      if (prevRule.srcType === ADDRESS_TYPES.ANY && (prevRule.protocol === PROTOCOLS.TCP || prevRule.protocol === PROTOCOLS.UDP)) {
        if (normDstPort !== null && DANGEROUS_PORTS.includes(normDstPort)) {
          warnings.push({
            id: `risk-exposed-service-${prevRule.id}`,
            type: 'warning',
            severity: 'important',
            title: `⚠️ HIGH RISK SERVICE EXPOSURE (ACE #${prevRule.originalIndex})`,
            message: `ACE #${prevRule.originalIndex} permits high-risk service port (${normDstPort}) from ANY source address.`
          });
        }
      }
    }

    for (let j = i + 1; j < activeRules.length; j++) {
      const nextRule = activeRules[j];

      const protoSubsumed = isProtocolSubsumed(prevRule.protocol, nextRule.protocol);
      const srcSubsumed = isIpSubsumed(
        prevRule.srcType, prevRule.srcIp, prevRule.srcMask,
        nextRule.srcType, nextRule.srcIp, nextRule.srcMask
      );
      const dstSubsumed = isIpSubsumed(
        prevRule.dstType, prevRule.dstIp, prevRule.dstMask,
        nextRule.dstType, nextRule.dstIp, nextRule.dstMask
      );
      const srcPortSubsumed = isPortSubsumed(
        prevRule.srcPortOperator, prevRule.srcPort, prevRule.srcPortEnd,
        nextRule.srcPortOperator, nextRule.srcPort, nextRule.srcPortEnd
      );
      const dstPortSubsumed = isPortSubsumed(
        prevRule.dstPortOperator, prevRule.dstPort, prevRule.dstPortEnd,
        nextRule.dstPortOperator, nextRule.dstPort, nextRule.dstPortEnd
      );

      const icmpSubsumed = (prevRule.protocol === PROTOCOLS.ICMP && nextRule.protocol === PROTOCOLS.ICMP)
        ? isIcmpSubsumed(prevRule.icmpType, nextRule.icmpType)
        : true;

      const isFullShadow = protoSubsumed && srcSubsumed && dstSubsumed && srcPortSubsumed && dstPortSubsumed && icmpSubsumed;

      if (isFullShadow) {
        if (prevRule.action === nextRule.action) {
          // REDUNDANT or EXACT DUPLICATE
          const normSrcA = normalizeAddress(prevRule.srcType, prevRule.srcIp, prevRule.srcMask);
          const normSrcB = normalizeAddress(nextRule.srcType, nextRule.srcIp, nextRule.srcMask);
          const normDstA = normalizeAddress(prevRule.dstType, prevRule.dstIp, prevRule.dstMask);
          const normDstB = normalizeAddress(nextRule.dstType, nextRule.dstIp, nextRule.dstMask);

          const isExactDuplicate = prevRule.protocol === nextRule.protocol &&
            prevRule.srcType === nextRule.srcType &&
            normSrcA.ip === normSrcB.ip &&
            prevRule.dstType === nextRule.dstType &&
            normDstA.ip === normDstB.ip &&
            normalizePort(prevRule.dstPort) === normalizePort(nextRule.dstPort);

          warnings.push({
            id: `shadowed-${nextRule.id}`,
            type: 'warning',
            severity: 'warning',
            title: isExactDuplicate ? `DUPLICATE ACE (ACE #${nextRule.originalIndex})` : `REDUNDANT ACE (ACE #${nextRule.originalIndex})`,
            message: `ACE #${nextRule.originalIndex} is redundant because ACE #${prevRule.originalIndex} (${prevRule.action.toUpperCase()} ${prevRule.protocol.toUpperCase()}) already covers this traffic.`
          });
        } else {
          // FULLY SHADOWED WITH ACTION CONFLICT
          const msg = t('shadowedMsg')
            .replace('{next}', (nextRule.originalIndex).toString())
            .replace('{nextProto}', `${nextRule.action.toUpperCase()} ${nextRule.protocol}`)
            .replace('{prev}', (prevRule.originalIndex).toString())
            .replace('{prevProto}', `${prevRule.action.toUpperCase()} ${prevRule.protocol}`);

          warnings.push({
            id: `shadowed-${nextRule.id}`,
            type: 'danger',
            severity: 'error',
            title: `FULLY SHADOWED (ACE #${nextRule.originalIndex})`,
            message: `${msg} [Action Conflict: ${prevRule.action.toUpperCase()} overrides ${nextRule.action.toUpperCase()}]`
          });
        }
      } else {
        // Generic Multi-Dimensional Packet-Space Overlap Analysis
        const protoOverlap = checkProtocolOverlap(prevRule.protocol, nextRule.protocol);
        const srcOverlap = checkIpOverlap(
          prevRule.srcType, prevRule.srcIp, prevRule.srcMask,
          nextRule.srcType, nextRule.srcIp, nextRule.srcMask
        );
        const dstOverlap = checkIpOverlap(
          prevRule.dstType, prevRule.dstIp, prevRule.dstMask,
          nextRule.dstType, nextRule.dstIp, nextRule.dstMask
        );
        const srcPortOverlap = (prevRule.protocol === PROTOCOLS.TCP || prevRule.protocol === PROTOCOLS.UDP) && (nextRule.protocol === PROTOCOLS.TCP || nextRule.protocol === PROTOCOLS.UDP)
          ? checkPortOverlap(
              prevRule.srcPortOperator, prevRule.srcPort, prevRule.srcPortEnd,
              nextRule.srcPortOperator, nextRule.srcPort, nextRule.srcPortEnd
            )
          : true;
        const dstPortOverlap = (prevRule.protocol === PROTOCOLS.TCP || prevRule.protocol === PROTOCOLS.UDP) && (nextRule.protocol === PROTOCOLS.TCP || nextRule.protocol === PROTOCOLS.UDP)
          ? checkPortOverlap(
              prevRule.dstPortOperator, prevRule.dstPort, prevRule.dstPortEnd,
              nextRule.dstPortOperator, nextRule.dstPort, nextRule.dstPortEnd
            )
          : true;
        const icmpOverlap = (prevRule.protocol === PROTOCOLS.ICMP && nextRule.protocol === PROTOCOLS.ICMP)
          ? checkIcmpOverlap(prevRule.icmpType, nextRule.icmpType)
          : true;

        const hasOverlap = protoOverlap && srcOverlap && dstOverlap && srcPortOverlap && dstPortOverlap && icmpOverlap;

        if (hasOverlap && prevRule.action !== nextRule.action) {
          warnings.push({
            id: `partial-${nextRule.id}`,
            type: 'warning',
            severity: 'important',
            title: `PARTIALLY SHADOWED POLICY (ACE #${nextRule.originalIndex})`,
            message: `ACE #${nextRule.originalIndex} (${nextRule.action.toUpperCase()} ${nextRule.protocol.toUpperCase()}) is partially shadowed by ACE #${prevRule.originalIndex} (${prevRule.action.toUpperCase()}). Overlapping traffic will be ${prevRule.action.toUpperCase()}TED before reaching ACE #${nextRule.originalIndex}.`
          });
        }
      }
    }
  }

  return warnings;
}
