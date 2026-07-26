/**
 * Traffic Packet Matcher & Simulator Component (Fixed Instant Evaluation & DOM Update)
 */

import { PROTOCOLS, ACTIONS } from '../core/types.js';
import { simulatePacketMatch } from '../core/simulator.js';
import { generateCiscoACL } from '../core/generators/cisco.js';
import { t } from '../core/i18n.js';

export function renderTrafficSimulator(container, { rules, currentPacket, onSimulate }) {
  const pkt = currentPacket || {
    srcIp: '192.168.1.50',
    dstIp: '10.0.0.1',
    protocol: PROTOCOLS.TCP,
    srcPort: '1024',
    dstPort: '80',
    icmpType: 'echo'
  };

  const getResultHtml = (packetData) => {
    const res = simulatePacketMatch(rules, packetData);
    if (res.matched) {
      const isPermit = res.action === ACTIONS.PERMIT;
      const ruleStr = res.rule
        ? generateCiscoACL({ type: 'extended_named', identifier: '' }, [res.rule])
            .split('\n')
            .filter(l => l.trim() && !l.startsWith('!') && !l.startsWith('ip access-list') && !l.startsWith('exit'))
            .join('')
            .trim()
        : `${res.rule.action} ${res.rule.protocol}`;

      return `
        <div class="syslog-line ${isPermit ? 'info' : 'error'}" style="margin-top:0.4rem; padding:0.55rem;">
          <span class="syslog-hdr" style="color: ${isPermit ? 'var(--badge-permit-fg)' : 'var(--badge-deny-fg)'}">
            [MATCH - ${res.action.toUpperCase()}] Matched Line #${res.matchedIndex}
          </span>
          <div style="font-family:var(--font-mono); margin-top:0.3rem; color:var(--text-main); font-size:0.85rem; font-weight:600;">
            ${ruleStr}
          </div>
        </div>
      `;
    } else {
      return `
        <div class="syslog-line important" style="margin-top:0.4rem; padding:0.55rem;">
          <span class="syslog-hdr" style="color: var(--badge-warn-fg)">
            [IMPLICIT DENY] No match found.
          </span>
          <div style="font-family:var(--font-mono); margin-top:0.3rem; color:var(--text-muted); font-size:0.82rem;">
            Packet dropped by default implicit deny rule.
          </div>
        </div>
      `;
    }
  };

  container.innerHTML = `
    <div class="card" style="flex: 1; min-height: 0; display: flex; flex-direction: column;">
      <div class="card-header">
        <div class="card-title">
          ${t('trafficSimTab')}
        </div>
      </div>

      <form id="sim-form" style="display:flex; flex-direction:column; gap:0.5rem;">
        <div class="form-grid" style="grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));">
          <div class="form-group">
            <label for="sim-src-ip">${t('simSrcIp')}</label>
            <input type="text" id="sim-src-ip" value="${pkt.srcIp}" placeholder="192.168.1.50" />
          </div>

          <div class="form-group">
            <label for="sim-dst-ip">${t('simDstIp')}</label>
            <input type="text" id="sim-dst-ip" value="${pkt.dstIp}" placeholder="10.0.0.1" />
          </div>

          <div class="form-group">
            <label for="sim-protocol">${t('protocolLabel')}</label>
            <select id="sim-protocol">
              <option value="${PROTOCOLS.TCP}" ${pkt.protocol === PROTOCOLS.TCP ? 'selected' : ''}>TCP</option>
              <option value="${PROTOCOLS.UDP}" ${pkt.protocol === PROTOCOLS.UDP ? 'selected' : ''}>UDP</option>
              <option value="${PROTOCOLS.ICMP}" ${pkt.protocol === PROTOCOLS.ICMP ? 'selected' : ''}>ICMP</option>
              <option value="${PROTOCOLS.IP}" ${pkt.protocol === PROTOCOLS.IP ? 'selected' : ''}>IP</option>
            </select>
          </div>

          ${pkt.protocol === PROTOCOLS.TCP || pkt.protocol === PROTOCOLS.UDP ? `
            <div class="form-group">
              <label for="sim-src-port">${t('simSrcPort')}</label>
              <input type="text" id="sim-src-port" value="${pkt.srcPort || '1024'}" placeholder="1024" />
            </div>

            <div class="form-group">
              <label for="sim-dst-port">${t('simDstPort')}</label>
              <input type="text" id="sim-dst-port" value="${pkt.dstPort || '80'}" placeholder="80" />
            </div>
          ` : ''}
        </div>

        <div style="display:flex; justify-content:flex-end; margin-top:0.3rem;">
          <button type="button" id="btn-run-sim" class="btn btn-primary" style="height:36px; padding:0 1rem;">
            ${t('testPacketBtn')}
          </button>
        </div>
      </form>

      <div style="margin-top:0.6rem; flex:1; overflow-y:auto;">
        <label style="font-size:0.72rem; font-weight:700; color:var(--text-muted); font-family:var(--font-mono);">
          ${t('matchResultTitle')}
        </label>
        <div id="sim-result-box">
          ${getResultHtml(pkt)}
        </div>
      </div>
    </div>
  `;

  const extractSimPacket = () => {
    return {
      srcIp: document.getElementById('sim-src-ip')?.value || '192.168.1.50',
      dstIp: document.getElementById('sim-dst-ip')?.value || '10.0.0.1',
      protocol: document.getElementById('sim-protocol')?.value || PROTOCOLS.TCP,
      srcPort: document.getElementById('sim-src-port')?.value || '1024',
      dstPort: document.getElementById('sim-dst-port')?.value || '80',
      icmpType: 'echo'
    };
  };

  const runSimulation = () => {
    const currentPkt = extractSimPacket();
    const resultBox = document.getElementById('sim-result-box');
    if (resultBox) {
      resultBox.innerHTML = getResultHtml(currentPkt);
    }
    if (onSimulate) onSimulate(currentPkt);
  };

  document.getElementById('sim-protocol')?.addEventListener('change', () => {
    const updatedPkt = extractSimPacket();
    renderTrafficSimulator(container, { rules, currentPacket: updatedPkt, onSimulate });
  });

  document.getElementById('btn-run-sim')?.addEventListener('click', (e) => {
    e.preventDefault();
    runSimulation();
  });

  document.getElementById('sim-form')?.addEventListener('submit', (e) => {
    e.preventDefault();
    runSimulation();
  });
}
