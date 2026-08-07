/**
 * ACL Analyzer & Educational Warning Engine (Localized with Partial Overlap Detection)
 */

import { ACL_TYPES, ACTIONS, PROTOCOLS, ADDRESS_TYPES } from './types.js';
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
  if (aOp === 'any') return true;
  if (aOp === 'eq' && bOp === 'eq') return aPort === bPort;
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

  // 2. Best Practice Placement Advice based on ACL Type
  const isStandard = aclConfig.type === ACL_TYPES.STANDARD_NUMBERED || aclConfig.type === ACL_TYPES.STANDARD_NAMED;
  if (isStandard) {
    warnings.push({
      id: 'placement-advice',
      type: 'tip',
      severity: 'info',
      title: t('standardPlacementTitle'),
      message: t('standardPlacementMsg')
    });
  } else {
    warnings.push({
      id: 'placement-advice',
      type: 'tip',
      severity: 'info',
      title: t('extendedPlacementTitle'),
      message: t('extendedPlacementMsg')
    });
  }

  // 3. Interface Direction Helper Note
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

  // 4. Shadowed & Redundant Rule Detection
  const activeRules = rules.filter(r => r.enabled);
  for (let i = 0; i < activeRules.length; i++) {
    const prevRule = activeRules[i];
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
        const msg = t('shadowedMsg')
          .replace('{next}', (j + 1).toString())
          .replace('{nextProto}', `${nextRule.action.toUpperCase()} ${nextRule.protocol}`)
          .replace('{prev}', (i + 1).toString())
          .replace('{prevProto}', `${prevRule.action.toUpperCase()} ${prevRule.protocol}`);

        warnings.push({
          id: `shadowed-${nextRule.id}`,
          type: 'danger',
          severity: 'error',
          title: t('shadowedTitle'),
          message: msg
        });
      } else if (prevRule.action !== nextRule.action) {
        // Partial Overlap Detection
        const prevDstAny = prevRule.dstType === ADDRESS_TYPES.ANY;
        const nextDstSpecific = nextRule.dstType !== ADDRESS_TYPES.ANY;
        const prevHasPort = prevRule.dstPortOperator && prevRule.dstPortOperator !== 'any';
        const nextNoPort = !nextRule.dstPortOperator || nextRule.dstPortOperator === 'any';

        if (prevDstAny && nextDstSpecific && prevHasPort && nextNoPort) {
          warnings.push({
            id: `partial-${nextRule.id}`,
            type: 'warning',
            severity: 'important',
            title: `Partially Overlapped Policy (ACE #${j + 1})`,
            message: `ACE #${j + 1} (${nextRule.action.toUpperCase()} ${nextRule.protocol}) is partially overlapped by ACE #${i + 1} (${prevRule.action.toUpperCase()}) on port ${prevRule.dstPort}. Traffic on port ${prevRule.dstRule || prevRule.dstPort} will pass before reaching ACE #${j + 1}.`
          });
        }
      }
    }
  }

  return warnings;
}
