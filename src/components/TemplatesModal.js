/**
 * Starter Templates Modal Component (Enterprise No-Emoji Version)
 */

import { ACL_TYPES, ACTIONS, PROTOCOLS, ADDRESS_TYPES } from '../core/types.js';
import { t, getLanguage } from '../core/i18n.js';

export function getStarterTemplates() {
  const isTr = getLanguage() === 'tr';

  return [
    {
      name: isTr ? '[DMZ] Web Sunucusu Güvenlik Sıkılaştırması' : '[DMZ] Web Server Hardening',
      description: isTr 
        ? 'DMZ Web Sunucusuna (192.168.1.50) HTTP (80) ve HTTPS (443) ile Yönetici bilgisayarından SSH (22) erişimine izin verir.' 
        : 'Permits inbound HTTP (80) & HTTPS (443) to DMZ Web Server (192.168.1.50) and SSH (22) from Admin host.',
      config: {
        vendor: 'cisco',
        type: ACL_TYPES.EXTENDED_NAMED,
        identifier: 'WEB_DMZ_ACL',
        interfaceName: 'GigabitEthernet0/0/1',
        interfaceDirection: 'in'
      },
      rules: [
        {
          id: '1',
          enabled: true,
          action: ACTIONS.PERMIT,
          protocol: PROTOCOLS.TCP,
          srcType: ADDRESS_TYPES.ANY,
          srcIp: '',
          srcMask: '',
          srcPortOperator: 'any',
          srcPort: '',
          dstType: ADDRESS_TYPES.HOST,
          dstIp: '192.168.1.50',
          dstMask: '',
          dstPortOperator: 'eq',
          dstPort: '80',
          icmpType: 'any',
          log: false,
          remark: isTr ? 'Web Sunucusuna HTTP erişimine izin ver' : 'Allow Public HTTP traffic to Web Server'
        },
        {
          id: '2',
          enabled: true,
          action: ACTIONS.PERMIT,
          protocol: PROTOCOLS.TCP,
          srcType: ADDRESS_TYPES.ANY,
          srcIp: '',
          srcMask: '',
          srcPortOperator: 'any',
          srcPort: '',
          dstType: ADDRESS_TYPES.HOST,
          dstIp: '192.168.1.50',
          dstMask: '',
          dstPortOperator: 'eq',
          dstPort: '443',
          icmpType: 'any',
          log: false,
          remark: isTr ? 'Web Sunucusuna HTTPS erişimine izin ver' : 'Allow Public HTTPS traffic to Web Server'
        },
        {
          id: '3',
          enabled: true,
          action: ACTIONS.PERMIT,
          protocol: PROTOCOLS.TCP,
          srcType: ADDRESS_TYPES.HOST,
          srcIp: '10.0.0.100',
          srcMask: '',
          srcPortOperator: 'any',
          srcPort: '',
          dstType: ADDRESS_TYPES.HOST,
          dstIp: '192.168.1.50',
          dstMask: '',
          dstPortOperator: 'eq',
          dstPort: '22',
          icmpType: 'any',
          log: true,
          remark: isTr ? 'Yönetici Host SSH erişimi' : 'Allow Admin Host SSH access'
        },
        {
          id: '4',
          enabled: true,
          action: ACTIONS.DENY,
          protocol: PROTOCOLS.IP,
          srcType: ADDRESS_TYPES.ANY,
          srcIp: '',
          srcMask: '',
          srcPortOperator: 'any',
          srcPort: '',
          dstType: ADDRESS_TYPES.HOST,
          dstIp: '192.168.1.50',
          dstMask: '',
          dstPortOperator: 'any',
          dstPort: '',
          icmpType: 'any',
          log: true,
          remark: isTr ? 'Diğer tüm trafiği engelle ve logla' : 'Explicitly Deny and Log all other IP traffic to Web Server'
        }
      ]
    },
    {
      name: isTr ? '[VLAN-ISO] Misafir Ağ İzolasyonu' : '[VLAN-ISO] Guest Network Isolation',
      description: isTr 
        ? 'Misafir Ağının (192.168.50.0/24) İnternete çıkışına izin verir, ancak Kurumsal Ağa (10.0.0.0/8) erişimini engeller.'
        : 'Permits Guest VLAN (192.168.50.0/24) to reach Internet, but blocks access to Internal Corporate Subnet (10.0.0.0/8).',
      config: {
        vendor: 'cisco',
        type: ACL_TYPES.EXTENDED_NAMED,
        identifier: 'GUEST_ISOLATION_ACL',
        interfaceName: 'VLAN50',
        interfaceDirection: 'in'
      },
      rules: [
        {
          id: '1',
          enabled: true,
          action: ACTIONS.DENY,
          protocol: PROTOCOLS.IP,
          srcType: ADDRESS_TYPES.SUBNET,
          srcIp: '192.168.50.0',
          srcMask: '255.255.255.0',
          srcPortOperator: 'any',
          srcPort: '',
          dstType: ADDRESS_TYPES.SUBNET,
          dstIp: '10.0.0.0',
          dstMask: '255.0.0.0',
          dstPortOperator: 'any',
          dstPort: '',
          icmpType: 'any',
          log: true,
          remark: isTr ? 'Misafir Ağının Kurumsal Ağa erişimini engelle' : 'Block Guest network from accessing Corporate 10.0.0.0/8'
        },
        {
          id: '2',
          enabled: true,
          action: ACTIONS.PERMIT,
          protocol: PROTOCOLS.IP,
          srcType: ADDRESS_TYPES.SUBNET,
          srcIp: '192.168.50.0',
          srcMask: '255.255.255.0',
          srcPortOperator: 'any',
          srcPort: '',
          dstType: ADDRESS_TYPES.ANY,
          dstIp: '',
          dstMask: '',
          dstPortOperator: 'any',
          dstPort: '',
          icmpType: 'any',
          log: false,
          remark: isTr ? 'Misafir Ağının İnternete erişimine izin ver' : 'Permit Guest Subnet to Internet'
        }
      ]
    },
    {
      name: isTr ? '[SEC-ADV] Kurumsal Altyapı & Yönetim Ağı Güvenliği' : '[SEC-ADV] Enterprise Infrastructure & Management Hardening',
      description: isTr 
        ? 'Sadece yetkili Yönetim Subnetinden (10.20.10.0/24) Yönetim VLANına (10.20.40.0/24) SSH (22) ve HTTPS (443) erişimine izin verir, yetkisiz tüm yönetişim erişimini engeller ve loglar.'
        : 'Permits SSH (22) & HTTPS (443) from Authorized Admin Subnet (10.20.10.0/24) to Management VLAN (10.20.40.0/24), denying and logging all unauthorized management attempts.',
      config: {
        vendor: 'cisco',
        type: ACL_TYPES.EXTENDED_NAMED,
        identifier: 'CORP_MGMT_HARDENING_ACL',
        interfaceName: 'GigabitEthernet0/0/0',
        interfaceDirection: 'in'
      },
      rules: [
        {
          id: '1',
          enabled: true,
          action: ACTIONS.PERMIT,
          protocol: PROTOCOLS.ICMP,
          srcType: ADDRESS_TYPES.SUBNET,
          srcIp: '10.20.10.0',
          srcMask: '255.255.255.0',
          srcPortOperator: 'any',
          srcPort: '',
          dstType: ADDRESS_TYPES.SUBNET,
          dstIp: '10.20.40.0',
          dstMask: '255.255.255.0',
          dstPortOperator: 'any',
          dstPort: '',
          icmpType: 'echo',
          log: false,
          remark: isTr ? 'Ağ tanısı için ICMP Echo erişimine izin ver' : 'Permit ICMP Echo for management network diagnostics'
        },
        {
          id: '2',
          enabled: true,
          action: ACTIONS.PERMIT,
          protocol: PROTOCOLS.TCP,
          srcType: ADDRESS_TYPES.SUBNET,
          srcIp: '10.20.10.0',
          srcMask: '255.255.255.0',
          srcPortOperator: 'any',
          srcPort: '',
          dstType: ADDRESS_TYPES.SUBNET,
          dstIp: '10.20.40.0',
          dstMask: '255.255.255.0',
          dstPortOperator: 'eq',
          dstPort: '22',
          icmpType: 'any',
          log: true,
          remark: isTr ? 'Yönetici Subnetinden Yönetim VLANına Güvenli SSH İzni' : 'Permit Secure SSH Access from Admin Subnet to Management VLAN'
        },
        {
          id: '3',
          enabled: true,
          action: ACTIONS.PERMIT,
          protocol: PROTOCOLS.TCP,
          srcType: ADDRESS_TYPES.SUBNET,
          srcIp: '10.20.10.0',
          srcMask: '255.255.255.0',
          srcPortOperator: 'any',
          srcPort: '',
          dstType: ADDRESS_TYPES.SUBNET,
          dstIp: '10.20.40.0',
          dstMask: '255.255.255.0',
          dstPortOperator: 'eq',
          dstPort: '443',
          icmpType: 'any',
          log: true,
          remark: isTr ? 'Yönetici Subnetinden Yönetim VLANına Güvenli HTTPS İzni' : 'Permit Secure HTTPS Web GUI Access from Admin Subnet'
        },
        {
          id: '4',
          enabled: true,
          action: ACTIONS.DENY,
          protocol: PROTOCOLS.IP,
          srcType: ADDRESS_TYPES.ANY,
          srcIp: '',
          srcMask: '',
          srcPortOperator: 'any',
          srcPort: '',
          dstType: ADDRESS_TYPES.SUBNET,
          dstIp: '10.20.40.0',
          dstMask: '255.255.255.0',
          dstPortOperator: 'any',
          dstPort: '',
          icmpType: 'any',
          log: true,
          remark: isTr ? 'Yönetim VLANına Yetkisiz Tüm Erişimleri Engelle ve Logla' : 'Block and Log all unauthorized access to Management Subnet'
        }
      ]
    },
    {
      name: isTr ? '[CORP-VLAN] Kurumsal Kullanıcı VLAN Güvenlik Politikası (VLAN 110)' : '[CORP-VLAN] Enterprise User VLAN Security Policy (VLAN 110)',
      description: isTr 
        ? 'Kurumsal Kullanıcı Subneti (10.20.10.0/24) için DHCP, DNS, AD/Kerberos, LDAP, Web, Mail, SMB, Voice servislerine izin veren; doğrudan Internet DNS/NTP, SSH/Telnet/RDP, veritabanı ve VLANlar arası yetkisiz geçişleri engelleleyen sıfır güven (Zero-Trust) mimarili eksiksiz kurumsal politikadır.'
        : 'Zero-Trust enterprise policy for User VLAN (10.20.10.0/24) permitting DHCP, DNS, AD/Kerberos, LDAP, Web, Mail, SMB, Voice while blocking direct Internet DNS/NTP, admin access, database protocols, and inter-VLAN lateral movement.',
      config: {
        vendor: 'cisco',
        type: ACL_TYPES.EXTENDED_NAMED,
        identifier: 'USER_VLAN_IN',
        interfaceName: 'Vlan110',
        interfaceDirection: 'in'
      },
      rules: [
        { id: '1', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.UDP, srcType: ADDRESS_TYPES.ANY, srcIp: '', srcMask: '', srcPortOperator: 'eq', srcPort: '68', dstType: ADDRESS_TYPES.ANY, dstIp: '', dstMask: '', dstPortOperator: 'eq', dstPort: '67', icmpType: 'any', log: false, remark: 'DHCP Client -> Server' },
        { id: '2', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.UDP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.HOST, dstIp: '10.20.30.10', dstMask: '', dstPortOperator: 'eq', dstPort: '53', icmpType: 'any', log: false, remark: 'Corporate DNS UDP' },
        { id: '3', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.TCP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.HOST, dstIp: '10.20.30.10', dstMask: '', dstPortOperator: 'eq', dstPort: '53', icmpType: 'any', log: false, remark: 'Corporate DNS TCP' },
        { id: '4', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.UDP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.HOST, dstIp: '10.20.30.12', dstMask: '', dstPortOperator: 'eq', dstPort: '123', icmpType: 'any', log: false, remark: 'Corporate NTP' },
        { id: '5', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.TCP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.HOST, dstIp: '10.20.30.10', dstMask: '', dstPortOperator: 'eq', dstPort: '88', icmpType: 'any', log: false, remark: 'Active Directory Kerberos TCP' },
        { id: '6', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.UDP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.HOST, dstIp: '10.20.30.10', dstMask: '', dstPortOperator: 'eq', dstPort: '88', icmpType: 'any', log: false, remark: 'Active Directory Kerberos UDP' },
        { id: '7', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.TCP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.HOST, dstIp: '10.20.30.10', dstMask: '', dstPortOperator: 'eq', dstPort: '389', icmpType: 'any', log: false, remark: 'LDAP' },
        { id: '8', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.TCP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.HOST, dstIp: '10.20.30.10', dstMask: '', dstPortOperator: 'eq', dstPort: '636', icmpType: 'any', log: false, remark: 'LDAPS Secure' },
        { id: '9', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.TCP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.HOST, dstIp: '10.20.30.10', dstMask: '', dstPortOperator: 'eq', dstPort: '3268', icmpType: 'any', log: false, remark: 'Global Catalog' },
        { id: '10', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.TCP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.HOST, dstIp: '10.20.30.10', dstMask: '', dstPortOperator: 'eq', dstPort: '135', icmpType: 'any', log: false, remark: 'AD RPC Endpoint Mapper' },
        { id: '11', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.TCP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.HOST, dstIp: '10.20.30.10', dstMask: '', dstPortOperator: 'range', dstPort: '49152', dstPortEnd: '65535', icmpType: 'any', log: false, remark: 'AD RPC Dynamic Range' },
        { id: '12', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.TCP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.HOST, dstIp: '10.20.30.20', dstMask: '', dstPortOperator: 'eq', dstPort: '80', icmpType: 'any', log: false, remark: 'Internal Web App HTTP' },
        { id: '13', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.TCP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.HOST, dstIp: '10.20.30.20', dstMask: '', dstPortOperator: 'eq', dstPort: '443', icmpType: 'any', log: false, remark: 'Internal Web App HTTPS' },
        { id: '14', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.TCP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.HOST, dstIp: '10.20.30.21', dstMask: '', dstPortOperator: 'eq', dstPort: '25', icmpType: 'any', log: false, remark: 'Mail SMTP' },
        { id: '15', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.TCP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.HOST, dstIp: '10.20.30.22', dstMask: '', dstPortOperator: 'eq', dstPort: '445', icmpType: 'any', log: false, remark: 'File Server SMB' },
        { id: '16', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.UDP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.HOST, dstIp: '10.20.40.30', dstMask: '', dstPortOperator: 'eq', dstPort: '1812', icmpType: 'any', log: false, remark: 'RADIUS Authentication' },
        { id: '17', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.UDP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.SUBNET, dstIp: '10.20.20.0', dstMask: '255.255.255.0', dstPortOperator: 'eq', dstPort: '5060', icmpType: 'any', log: false, remark: 'Voice SIP Protocol' },
        { id: '18', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.UDP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.SUBNET, dstIp: '10.20.20.0', dstMask: '255.255.255.0', dstPortOperator: 'range', dstPort: '16384', dstPortEnd: '32767', icmpType: 'any', log: false, remark: 'Voice RTP Audio Range' },
        { id: '19', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.TCP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.ANY, dstIp: '', dstMask: '', dstPortOperator: 'eq', dstPort: '80', icmpType: 'any', log: false, remark: 'Internet HTTP Outbound' },
        { id: '20', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.TCP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.ANY, dstIp: '', dstMask: '', dstPortOperator: 'eq', dstPort: '443', icmpType: 'any', log: false, remark: 'Internet HTTPS Outbound' },
        { id: '21', enabled: true, action: ACTIONS.PERMIT, protocol: PROTOCOLS.ICMP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.ANY, dstIp: '', dstMask: '', dstPortOperator: 'any', dstPort: '', icmpType: 'echo', log: false, remark: 'ICMP Echo Ping Diagnostics' },
        { id: '22', enabled: true, action: ACTIONS.DENY, protocol: PROTOCOLS.UDP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.ANY, dstIp: '', dstMask: '', dstPortOperator: 'eq', dstPort: '53', icmpType: 'any', log: true, remark: 'Block Direct Internet DNS' },
        { id: '23', enabled: true, action: ACTIONS.DENY, protocol: PROTOCOLS.TCP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.ANY, dstIp: '', dstMask: '', dstPortOperator: 'eq', dstPort: '22', icmpType: 'any', log: true, remark: 'Block Admin SSH Outbound' },
        { id: '24', enabled: true, action: ACTIONS.DENY, protocol: PROTOCOLS.IP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.SUBNET, dstIp: '10.20.40.0', dstMask: '255.255.255.0', dstPortOperator: 'any', dstPort: '', icmpType: 'any', log: true, remark: 'Block Access to Management Subnet' },
        { id: '25', enabled: true, action: ACTIONS.DENY, protocol: PROTOCOLS.IP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.SUBNET, dstIp: '10.20.20.0', dstMask: '255.255.255.0', dstPortOperator: 'any', dstPort: '', icmpType: 'any', log: true, remark: 'Block Voice Subnet Lateral Movement' },
        { id: '26', enabled: true, action: ACTIONS.DENY, protocol: PROTOCOLS.IP, srcType: ADDRESS_TYPES.SUBNET, srcIp: '10.20.10.0', srcMask: '255.255.255.0', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.SUBNET, dstIp: '10.20.50.0', dstMask: '255.255.255.0', dstPortOperator: 'any', dstPort: '', icmpType: 'any', log: true, remark: 'Block Guest Subnet Access' },
        { id: '27', enabled: true, action: ACTIONS.DENY, protocol: PROTOCOLS.IP, srcType: ADDRESS_TYPES.ANY, srcIp: '', srcMask: '', srcPortOperator: 'any', srcPort: '', dstType: ADDRESS_TYPES.ANY, dstIp: '', dstMask: '', dstPortOperator: 'any', dstPort: '', icmpType: 'any', log: true, remark: 'Explicit Final Default Deny and Log' }
      ]
    }
  ];
}

export function renderTemplatesModal(container, { onSelectTemplate, onClose }) {
  const templates = getStarterTemplates();

  container.innerHTML = `
    <div class="modal-backdrop" id="modal-bg">
      <div class="modal-content">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
          <h2 style="font-size:1rem; font-weight:700; font-family:var(--font-mono);">${t('templatesModalTitle')}</h2>
          <button id="modal-close-btn" class="btn btn-sm">${t('closeBtn')}</button>
        </div>

        <div style="display:flex; flex-direction:column; gap:0.6rem;">
          ${templates.map((tmpl, idx) => `
            <div class="card" style="cursor:pointer; background:var(--bg-input);" id="template-card-${idx}">
              <div style="font-weight:700; font-size:0.88rem; margin-bottom:0.2rem; color:var(--cisco-teal); font-family:var(--font-mono);">${tmpl.name}</div>
              <div style="font-size:0.78rem; color:var(--text-muted); line-height:1.35; font-family:var(--font-mono);">${tmpl.description}</div>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
  `;

  document.getElementById('modal-close-btn').addEventListener('click', onClose);
  document.getElementById('modal-bg').addEventListener('click', (e) => {
    if (e.target.id === 'modal-bg') onClose();
  });

  templates.forEach((tmpl, idx) => {
    document.getElementById(`template-card-${idx}`).addEventListener('click', () => {
      onSelectTemplate(tmpl);
      onClose();
    });
  });
}
