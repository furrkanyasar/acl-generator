/**
 * ACL Analyzer & Static Security Risk Engine (Multi-Dimensional Analysis & Risk Engine)
 */

import { ACL_TYPES, ACTIONS, PROTOCOLS, ADDRESS_TYPES, normalizePort } from './types.js';
import { isValidIp, ipToInt, maskToWildcard } from './wildcard.js';
import { t } from './i18n.js';

function isIpSubsumed(aType, aIp, aMask, bType, bIp, bMask) {
  if (aType === ADDRESS_TYPES.ANY) return true;

  if (aType === ADDRESS_TYPES.HOST && bType === ADDRESS_TYPES.HOST) {
    return isValidIp(aIp) && isValidIp(bIp) && aIp.trim() === bIp.trim();
  }

  if (aType === ADDRESS_TYPES.SUBNET && bType === ADDRESS_TYPES.HOST) {
    if (!isValidIp(aIp) || !isValidIp(bIp)) return false;
    const aWildcard = maskToWildcard(aMask);
    if (!aWildcard) return false;
    const aWildcardInt = ipToInt(aWildcard);
    const aIpInt = ipToInt(aIp);
    const bIpInt = ipToInt(bIp);
    
    return ((bIpInt & ~aWildcardInt) === (aIpInt & ~aWildcardInt));
  }

  if (aType === ADDRESS_TYPES.SUBNET && bType === ADDRESS_TYPES.SUBNET) {
    if (!isValidIp(aIp) || !isValidIp(bIp)) return false;
    const aWildcard = maskToWildcard(aMask);
    const bWildcard = maskToWildcard(bMask);
    if (!aWildcard || !bWildcard) return false;
    
    const aWildInt = ipToInt(aWildcard);
    const bWildInt = ipToInt(bWildcard);
    const aIpInt = ipToInt(aIp);
    const bIpInt = ipToInt(bIp);

    const bSubnetFitsInA = ((bIpInt & ~aWildInt) === (aIpInt & ~aWildInt));
    const aIsBroader = (aWildInt & bWildInt) === bWildInt;
    return bSubnetFitsInA && aIsBroader;
  }

  return false;
}

function isProtocolSubsumed(aProto, bProto) {
  if (aProto === PROTOCOLS.IP) return true;
  return aProto === bProto;
}

function isPortSubsumed(aOp, aPort, aPortEnd, bOp, bPort, bPortEnd) {
  if (!aOp || aOp === 'any') return true;
  const pA = normalizePort(aPort);
  const pB = normalizePort(bPort);

  if (aOp === 'eq') {
    if (bOp === 'eq') return pA !== null && pA === pB;
    return false;
  }

  if (aOp === 'range' && aPort && aPortEnd) {
    const rAStart = normalizePort(aPort);
    const rAEnd = normalizePort(aPortEnd);
    if (rAStart === null || rAEnd === null) return false;

    if (bOp === 'eq' && pB !== null) {
      return pB >= rAStart && pB <= rAEnd;
    }

    if (bOp === 'range' && bPort && bPortEnd) {
      const rBStart = normalizePort(bPort);
      const rBEnd = normalizePort(bPortEnd);
      if (rBStart === null || rBEnd === null) return false;
      return rBStart >= rAStart && rBEnd <= rAEnd;
    }
  }

  return false;
}

function isIcmpSubsumed(aIcmp, bIcmp) {
  if (!aIcmp || aIcmp === 'any') return true;
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

  // 4. Multi-Dimensional Overlap, Shadowing & Security Risk Engine
  const activeRules = rules.filter(r => r.enabled);

  for (let i = 0; i < activeRules.length; i++) {
    const prevRule = activeRules[i];

    // Static Security Risk Assessment (Professional Tone)
    if (prevRule.action === ACTIONS.PERMIT) {
      // High Risk: Permit IP Any Any
      if (prevRule.protocol === PROTOCOLS.IP && prevRule.srcType === ADDRESS_TYPES.ANY && prevRule.dstType === ADDRESS_TYPES.ANY) {
        warnings.push({
          id: `risk-any-any-${prevRule.id}`,
          type: 'danger',
          severity: 'error',
          title: `🔴 HIGH RISK / VERY BROAD PERMIT (ACE #${i + 1})`,
          message: `ACE #${i + 1} permits unrestricted IP traffic from ANY source to ANY destination. Review recommended.`
        });
      }

      // High Risk: Permit SSH/Telnet to Management Network
      if ((prevRule.dstPort === '22' || prevRule.dstPort === '23') && prevRule.dstIp && prevRule.dstIp.includes('40.')) {
        warnings.push({
          id: `risk-mgmt-ssh-${prevRule.id}`,
          type: 'danger',
          severity: 'error',
          title: `🔴 HIGH RISK / MANAGEMENT ACCESS PERMIT (ACE #${i + 1})`,
          message: `ACE #${i + 1} permits direct administrative access (Port ${prevRule.dstPort}) to Management VLAN.`
        });
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
          // REDUNDANT or DUPLICATE
          const isExactDuplicate = prevRule.protocol === nextRule.protocol &&
            prevRule.srcIp === nextRule.srcIp && prevRule.dstIp === nextRule.dstIp &&
            prevRule.dstPort === nextRule.dstPort;

          warnings.push({
            id: `shadowed-${nextRule.id}`,
            type: 'warning',
            severity: 'warning',
            title: isExactDuplicate ? `DUPLICATE ACE (ACE #${j + 1})` : `REDUNDANT ACE (ACE #${j + 1})`,
            message: `ACE #${j + 1} is redundant because ACE #${i + 1} (${prevRule.action.toUpperCase()} ${prevRule.protocol.toUpperCase()}) already covers this traffic.`
          });
        } else {
          // FULLY SHADOWED WITH ACTION CONFLICT
          const msg = t('shadowedMsg')
            .replace('{next}', (j + 1).toString())
            .replace('{nextProto}', `${nextRule.action.toUpperCase()} ${nextRule.protocol}`)
            .replace('{prev}', (i + 1).toString())
            .replace('{prevProto}', `${prevRule.action.toUpperCase()} ${prevRule.protocol}`);

          warnings.push({
            id: `shadowed-${nextRule.id}`,
            type: 'danger',
            severity: 'error',
            title: `FULLY SHADOWED (ACE #${j + 1})`,
            message: `${msg} [Action Conflict: ${prevRule.action.toUpperCase()} overrides ${nextRule.action.toUpperCase()}]`
          });
        }
      } else if (prevRule.action !== nextRule.action) {
        // Multi-Dimensional Partial Overlap with Action Conflict
        const prevDstAny = prevRule.dstType === ADDRESS_TYPES.ANY;
        const nextDstSpecific = nextRule.dstType !== ADDRESS_TYPES.ANY;
        const prevHasPort = prevRule.dstPortOperator && prevRule.dstPortOperator !== 'any';
        const nextNoPort = !nextRule.dstPortOperator || nextRule.dstPortOperator === 'any';

        if (prevDstAny && nextDstSpecific && prevHasPort && nextNoPort) {
          warnings.push({
            id: `partial-${nextRule.id}`,
            type: 'warning',
            severity: 'important',
            title: `PARTIALLY SHADOWED POLICY (ACE #${j + 1})`,
            message: `ACE #${j + 1} (${nextRule.action.toUpperCase()} ${nextRule.protocol.toUpperCase()}) is partially shadowed by ACE #${i + 1} (${prevRule.action.toUpperCase()}) on port ${prevRule.dstPort}. Traffic on Port ${prevRule.dstPort} will be ${prevRule.action.toUpperCase()}TED before reaching ACE #${j + 1}.`
          });
        }
      }
    }
  }

  return warnings;
}
