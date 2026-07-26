/**
 * Network Utilities & Cisco Wildcard Mask Calculator
 */

/**
 * Validates an IPv4 address string (e.g., '192.168.1.1')
 */
export function isValidIp(ip) {
  if (typeof ip !== 'string') return false;
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return false;
  return parts.every(p => {
    if (!/^\d+$/.test(p)) return false;
    const num = parseInt(p, 10);
    return num >= 0 && num <= 255 && (p === '0' || !p.startsWith('0'));
  });
}

/**
 * Converts IP string to 32-bit unsigned integer
 */
export function ipToInt(ip) {
  const parts = ip.trim().split('.').map(p => parseInt(p, 10));
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/**
 * Converts 32-bit unsigned integer to IP string
 */
export function intToIp(intVal) {
  return [
    (intVal >>> 24) & 255,
    (intVal >>> 16) & 255,
    (intVal >>> 8) & 255,
    intVal & 255
  ].join('.');
}

/**
 * Converts CIDR prefix length (0-32) to Subnet Mask integer
 */
export function cidrToSubnetInt(cidr) {
  const prefix = parseInt(cidr, 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return null;
  if (prefix === 0) return 0;
  return (0xFFFFFFFF << (32 - prefix)) >>> 0;
}

/**
 * Converts Subnet Mask string (or CIDR number) to Wildcard Mask string.
 * Examples:
 *  - '255.255.255.0' or '24' or '/24' -> '0.0.0.255'
 *  - '255.255.240.0' or '20' -> '0.0.15.255'
 *  - '255.255.255.255' or '32' -> '0.0.0.0'
 */
export function maskToWildcard(input) {
  if (!input) return '';
  const str = input.toString().trim().replace(/^\//, '');

  // Case 1: Pure CIDR number (0 - 32)
  if (/^\d+$/.test(str)) {
    const prefix = parseInt(str, 10);
    if (prefix >= 0 && prefix <= 32) {
      const maskInt = cidrToSubnetInt(prefix);
      const wildcardInt = (~maskInt) >>> 0;
      return intToIp(wildcardInt);
    }
  }

  // Case 2: Dotted decimal Subnet Mask
  if (isValidIp(str)) {
    const maskInt = ipToInt(str);
    const wildcardInt = (~maskInt) >>> 0;
    return intToIp(wildcardInt);
  }

  return '';
}

/**
 * Calculates network address given an IP and subnet mask/CIDR
 */
export function calculateNetworkAddress(ip, maskOrCidr) {
  if (!isValidIp(ip)) return null;
  let maskInt = null;

  const str = maskOrCidr ? maskOrCidr.toString().trim().replace(/^\//, '') : '';
  if (/^\d+$/.test(str)) {
    maskInt = cidrToSubnetInt(parseInt(str, 10));
  } else if (isValidIp(str)) {
    maskInt = ipToInt(str);
  }

  if (maskInt === null) return null;
  const ipInt = ipToInt(ip);
  const netInt = (ipInt & maskInt) >>> 0;
  return intToIp(netInt);
}

/**
 * Calculates CIDR prefix from Wildcard Mask or Subnet Mask
 */
export function wildcardToCidr(wildcard) {
  if (!isValidIp(wildcard)) return null;
  const wildcardInt = ipToInt(wildcard);
  const maskInt = (~wildcardInt) >>> 0;
  
  // Count trailing zeros of wildcardInt (which are ones in maskInt)
  let count = 0;
  for (let i = 31; i >= 0; i--) {
    if ((maskInt & (1 << i)) !== 0) {
      count++;
    } else {
      break;
    }
  }
  return count;
}
