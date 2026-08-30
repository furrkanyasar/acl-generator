/**
 * Main Vendor Dispatcher Exporter
 */

import { VENDORS } from './types.js';
import { generateCiscoACL } from './generators/cisco.js';
import { generateJuniperACL } from './generators/juniper.js';
import { generateHuaweiACL } from './generators/huawei.js';

export function generateACLScript(config, rules) {
  const vendor = config.vendor || VENDORS.CISCO;

  switch (vendor) {
    case VENDORS.JUNIPER:
      return generateJuniperACL(config, rules);
    case VENDORS.HUAWEI:
      return generateHuaweiACL(config, rules);
    case VENDORS.CISCO:
    default:
      return generateCiscoACL(config, rules);
  }
}
