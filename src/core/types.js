/**
 * Core Data Models and Constants for ACL Generator
 */
import { t } from './i18n.js';

export const VENDORS = {
  CISCO: 'cisco',
  JUNIPER: 'juniper',
  HUAWEI: 'huawei'
};

export const ACL_TYPES = {
  STANDARD_NUMBERED: 'standard_numbered',
  STANDARD_NAMED: 'standard_named',
  EXTENDED_NUMBERED: 'extended_numbered',
  EXTENDED_NAMED: 'extended_named'
};

export const ACTIONS = {
  PERMIT: 'permit',
  DENY: 'deny'
};

export const PROTOCOLS = {
  IP: 'ip',
  TCP: 'tcp',
  UDP: 'udp',
  ICMP: 'icmp'
};

export const ADDRESS_TYPES = {
  ANY: 'any',
  HOST: 'host',
  SUBNET: 'subnet'
};

export const PORT_OPERATORS = {
  ANY: 'any',
  EQ: 'eq',
  NEQ: 'neq',
  GT: 'gt',
  LT: 'lt',
  RANGE: 'range'
};

export const PORT_ALIASES = {
  'domain': 53,
  'www': 80,
  'http': 80,
  'https': 443,
  'smtp': 25,
  'submission': 587,
  'pop3': 110,
  'pop3s': 995,
  'imap': 143,
  'imaps': 993,
  'ssh': 22,
  'telnet': 23,
  'ftp': 21,
  'ftp-data': 20,
  'dns': 53,
  'bootps': 67,
  'bootpc': 68,
  'dhcp': 67,
  'tftp': 69,
  'ntp': 123,
  'snmp': 161,
  'snmptrap': 162,
  'bgp': 179,
  'ldap': 389,
  'ldaps': 636,
  'microsoft-ds': 445,
  'netbios-ns': 137,
  'netbios-dgm': 138,
  'netbios-ssn': 139,
  'syslog': 514,
  'rdp': 3389
};

export function normalizePort(portValue) {
  if (portValue === null || portValue === undefined) return null;
  const str = portValue.toString().trim().toLowerCase();
  if (PORT_ALIASES[str] !== undefined) {
    return PORT_ALIASES[str];
  }
  const parsed = parseInt(str, 10);
  return isNaN(parsed) ? null : parsed;
}

export function escapeHtml(str) {
  if (typeof str !== 'string') return str;
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function getCommonPorts() {
  return [
    { name: t('ports.http'), value: 80 },
    { name: t('ports.https'), value: 443 },
    { name: t('ports.ssh'), value: 22 },
    { name: t('ports.telnet'), value: 23 },
    { name: t('ports.ftp'), value: 21 },
    { name: t('ports.dns'), value: 53 },
    { name: t('ports.dhcpServer'), value: 67 },
    { name: t('ports.dhcpClient'), value: 68 },
    { name: t('ports.ntp'), value: 123 },
    { name: t('ports.snmp'), value: 161 },
    { name: t('ports.bgp'), value: 179 },
    { name: t('ports.rdp'), value: 3389 }
  ];
}

export function getIcmpTypes() {
  return [
    { name: t('icmp.echo'), value: 'echo' },
    { name: t('icmp.echoReply'), value: 'echo-reply' },
    { name: t('icmp.unreachable'), value: 'unreachable' },
    { name: t('icmp.timeExceeded'), value: 'time-exceeded' },
    { name: t('icmp.parameterProblem'), value: 'parameter-problem' },
    { name: t('icmp.redirect'), value: 'redirect' },
    { name: t('icmp.any'), value: 'any' }
  ];
}

export function createDefaultRule(id = 1) {
  return {
    id: id.toString(),
    enabled: true,
    action: ACTIONS.PERMIT,
    protocol: PROTOCOLS.IP,
    srcType: ADDRESS_TYPES.ANY,
    srcIp: '',
    srcMask: '',
    srcWildcard: '',
    srcPortOperator: PORT_OPERATORS.ANY,
    srcPort: '',
    srcPortEnd: '',
    dstType: ADDRESS_TYPES.ANY,
    dstIp: '',
    dstMask: '',
    dstWildcard: '',
    dstPortOperator: PORT_OPERATORS.ANY,
    dstPort: '',
    dstPortEnd: '',
    icmpType: 'any',
    log: false,
    remark: ''
  };
}
