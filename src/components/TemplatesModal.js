/**
 * Starter Templates Modal Component (Enterprise No-Emoji Version)
 */

import { ACL_TYPES, ACTIONS, PROTOCOLS, ADDRESS_TYPES } from '../core/types.js';
import { t, getLanguage } from '../core/i18n.js';

export function getStarterTemplates() {
  const isTr = getLanguage() === 'tr';

  return [
    {
      name: isTr ? '[DMZ] Web Sunucusu Güvenlik Sertleştirmesi' : '[DMZ] Web Server Hardening',
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
