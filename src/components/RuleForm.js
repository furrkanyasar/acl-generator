/**
 * Rule Builder Form Component (Enterprise NOC Edition - Fixed Interactivity)
 */

import { ACTIONS, PROTOCOLS, ADDRESS_TYPES, normalizePort, getCommonPorts, getIcmpTypes, createDefaultRule, escapeHtml } from '../core/types.js';
import { isValidIp, maskToWildcard } from '../core/wildcard.js';
import { t } from '../core/i18n.js';

export function renderRuleForm(container, { aclType, editingRule, onSaveRule, onCancelEdit }) {
  const isExtended = aclType.includes('extended');
  const rule = editingRule || createDefaultRule();

  const isTcpOrUdp = isExtended && (rule.protocol === PROTOCOLS.TCP || rule.protocol === PROTOCOLS.UDP);
  const isIcmp = isExtended && rule.protocol === PROTOCOLS.ICMP;

  const srcWildcard = rule.srcType === ADDRESS_TYPES.SUBNET ? maskToWildcard(rule.srcMask) : '';
  const dstWildcard = rule.dstType === ADDRESS_TYPES.SUBNET ? maskToWildcard(rule.dstMask) : '';

  const commonPorts = getCommonPorts();
  const icmpTypes = getIcmpTypes();

  const safeSrcIp = escapeHtml(rule.srcIp || '');
  const safeSrcMask = escapeHtml(rule.srcMask || '');
  const safeSrcPort = escapeHtml(rule.srcPort || '');
  const safeSrcPortEnd = escapeHtml(rule.srcPortEnd || '');
  const safeDstIp = escapeHtml(rule.dstIp || '');
  const safeDstMask = escapeHtml(rule.dstMask || '');
  const safeDstPort = escapeHtml(rule.dstPort || '');
  const safeDstPortEnd = escapeHtml(rule.dstPortEnd || '');
  const safeRemark = escapeHtml(rule.remark || '');

  container.innerHTML = `
    <div class="card">
      <div class="card-header">
        <div class="card-title">
          ${editingRule ? `${t('editRuleTitle')} #${editingRule.id}` : t('constructRuleTitle')}
        </div>
      </div>

      <form id="rule-form">
        <div class="form-grid">
          <!-- Action -->
          <div class="form-group">
            <label for="rule-action">${t('actionLabel')}</label>
            <select id="rule-action">
              <option value="${ACTIONS.PERMIT}" ${rule.action === ACTIONS.PERMIT ? 'selected' : ''}>${t('permitAction')}</option>
              <option value="${ACTIONS.DENY}" ${rule.action === ACTIONS.DENY ? 'selected' : ''}>${t('denyAction')}</option>
            </select>
          </div>

          <!-- Protocol -->
          <div class="form-group">
            <label for="rule-protocol">${t('protocolLabel')} ${!isExtended ? `<span style="color:var(--status-amber);">${t('extendedOnly')}</span>` : ''}</label>
            <select id="rule-protocol" ${!isExtended ? 'disabled' : ''}>
              <option value="${PROTOCOLS.IP}" ${rule.protocol === PROTOCOLS.IP ? 'selected' : ''}>IP</option>
              <option value="${PROTOCOLS.TCP}" ${rule.protocol === PROTOCOLS.TCP ? 'selected' : ''}>TCP</option>
              <option value="${PROTOCOLS.UDP}" ${rule.protocol === PROTOCOLS.UDP ? 'selected' : ''}>UDP</option>
              <option value="${PROTOCOLS.ICMP}" ${rule.protocol === PROTOCOLS.ICMP ? 'selected' : ''}>ICMP</option>
            </select>
          </div>

          <!-- Source Selection -->
          <div class="form-group">
            <label for="rule-src-type">${t('srcAddrLabel')}</label>
            <select id="rule-src-type">
              <option value="${ADDRESS_TYPES.ANY}" ${rule.srcType === ADDRESS_TYPES.ANY ? 'selected' : ''}>${t('anyAddr')}</option>
              <option value="${ADDRESS_TYPES.HOST}" ${rule.srcType === ADDRESS_TYPES.HOST ? 'selected' : ''}>${t('singleHost')}</option>
              <option value="${ADDRESS_TYPES.SUBNET}" ${rule.srcType === ADDRESS_TYPES.SUBNET ? 'selected' : ''}>${t('subnetNet')}</option>
            </select>
          </div>

          <div class="form-group ${rule.srcType === ADDRESS_TYPES.ANY ? 'style-hidden' : ''}" id="src-ip-group">
            <label for="rule-src-ip">${rule.srcType === ADDRESS_TYPES.HOST ? t('hostIpLabel') : t('subnetIpLabel')}</label>
            <input type="text" id="rule-src-ip" value="${safeSrcIp}" placeholder="192.168.1.50" />
          </div>

          <div class="form-group ${rule.srcType !== ADDRESS_TYPES.SUBNET ? 'style-hidden' : ''}" id="src-mask-group">
            <label for="rule-src-mask">${t('maskLabel')}</label>
            <input type="text" id="rule-src-mask" value="${safeSrcMask}" placeholder="255.255.255.0 / 24" />
            <div class="helper-text" id="src-wildcard-preview">${t('wildcardPreview')}: ${srcWildcard || '0.0.0.255'}</div>
          </div>

          <!-- Source Port Fields (TCP/UDP) -->
          ${isTcpOrUdp ? `
            <div class="form-group">
              <label for="rule-src-port-op">${t('srcPortOpLabel')}</label>
              <select id="rule-src-port-op">
                <option value="any" ${rule.srcPortOperator === 'any' ? 'selected' : ''}>${t('portAny')}</option>
                <option value="eq" ${rule.srcPortOperator === 'eq' ? 'selected' : ''}>${t('portEq')}</option>
                <option value="neq" ${rule.srcPortOperator === 'neq' ? 'selected' : ''}>${t('portNeq')}</option>
                <option value="gt" ${rule.srcPortOperator === 'gt' ? 'selected' : ''}>${t('portGt')}</option>
                <option value="lt" ${rule.srcPortOperator === 'lt' ? 'selected' : ''}>${t('portLt')}</option>
                <option value="range" ${rule.srcPortOperator === 'range' ? 'selected' : ''}>${t('portRange')}</option>
              </select>
            </div>

            <div class="form-group ${rule.srcPortOperator === 'any' ? 'style-hidden' : ''}" id="src-port-group">
              <label for="rule-src-port">${t('portPresetLabel')}</label>
              ${rule.srcPortOperator === 'range' ? `
                <div style="display:flex; gap:0.3rem;">
                  <input type="text" id="rule-src-port" value="${safeSrcPort}" placeholder="${t('portStart') || 'Start'}" style="flex:1" />
                  <input type="text" id="rule-src-port-end" value="${safeSrcPortEnd}" placeholder="${t('portEnd') || 'End'}" style="flex:1" />
                </div>
              ` : `
                <div style="display:flex; gap:0.3rem;">
                  <input type="text" id="rule-src-port" value="${safeSrcPort}" placeholder="80" style="flex:1" />
                  <select id="src-port-preset" style="width:130px;">
                    <option value="">${t('presetSelect')}</option>
                    ${commonPorts.map(p => `<option value="${p.value}">${p.name}</option>`).join('')}
                  </select>
                </div>
              `}
            </div>
          ` : ''}

          <!-- Destination Selection (Extended Only) -->
          ${isExtended ? `
            <div class="form-group">
              <label for="rule-dst-type">${t('dstAddrLabel')}</label>
              <select id="rule-dst-type">
                <option value="${ADDRESS_TYPES.ANY}" ${rule.dstType === ADDRESS_TYPES.ANY ? 'selected' : ''}>${t('anyAddr')}</option>
                <option value="${ADDRESS_TYPES.HOST}" ${rule.dstType === ADDRESS_TYPES.HOST ? 'selected' : ''}>${t('singleHost')}</option>
                <option value="${ADDRESS_TYPES.SUBNET}" ${rule.dstType === ADDRESS_TYPES.SUBNET ? 'selected' : ''}>${t('subnetNet')}</option>
              </select>
            </div>

            <div class="form-group ${rule.dstType === ADDRESS_TYPES.ANY ? 'style-hidden' : ''}" id="dst-ip-group">
              <label for="rule-dst-ip">${rule.dstType === ADDRESS_TYPES.HOST ? t('hostIpLabel') : t('subnetIpLabel')}</label>
              <input type="text" id="rule-dst-ip" value="${safeDstIp}" placeholder="10.0.0.1" />
            </div>

            <div class="form-group ${rule.dstType !== ADDRESS_TYPES.SUBNET ? 'style-hidden' : ''}" id="dst-mask-group">
              <label for="rule-dst-mask">${t('maskLabel')}</label>
              <input type="text" id="rule-dst-mask" value="${safeDstMask}" placeholder="255.255.255.0 / 24" />
              <div class="helper-text" id="dst-wildcard-preview">${t('wildcardPreview')}: ${dstWildcard || '0.0.0.255'}</div>
            </div>
          ` : ''}

          <!-- Destination Port Fields (TCP/UDP) -->
          ${isTcpOrUdp ? `
            <div class="form-group">
              <label for="rule-dst-port-op">${t('dstPortOpLabel')}</label>
              <select id="rule-dst-port-op">
                <option value="any" ${rule.dstPortOperator === 'any' ? 'selected' : ''}>${t('portAny')}</option>
                <option value="eq" ${rule.dstPortOperator === 'eq' ? 'selected' : ''}>${t('portEq')}</option>
                <option value="neq" ${rule.dstPortOperator === 'neq' ? 'selected' : ''}>${t('portNeq')}</option>
                <option value="gt" ${rule.dstPortOperator === 'gt' ? 'selected' : ''}>${t('portGt')}</option>
                <option value="lt" ${rule.dstPortOperator === 'lt' ? 'selected' : ''}>${t('portLt')}</option>
                <option value="range" ${rule.dstPortOperator === 'range' ? 'selected' : ''}>${t('portRange')}</option>
              </select>
            </div>

            <div class="form-group ${rule.dstPortOperator === 'any' ? 'style-hidden' : ''}" id="dst-port-group">
              <label for="rule-dst-port">${t('portPresetLabel')}</label>
              ${rule.dstPortOperator === 'range' ? `
                <div style="display:flex; gap:0.3rem;">
                  <input type="text" id="rule-dst-port" value="${safeDstPort}" placeholder="${t('portStart') || 'Start'}" style="flex:1" />
                  <input type="text" id="rule-dst-port-end" value="${safeDstPortEnd}" placeholder="${t('portEnd') || 'End'}" style="flex:1" />
                </div>
              ` : `
                <div style="display:flex; gap:0.3rem;">
                  <input type="text" id="rule-dst-port" value="${safeDstPort}" placeholder="80" style="flex:1" />
                  <select id="dst-port-preset" style="width:130px;">
                    <option value="">${t('presetSelect')}</option>
                    ${commonPorts.map(p => `<option value="${p.value}">${p.name}</option>`).join('')}
                  </select>
                </div>
              `}
            </div>
          ` : ''}

          <!-- ICMP Type Field (ICMP) -->
          ${isIcmp ? `
            <div class="form-group">
              <label for="rule-icmp-type">${t('icmpTypeLabel')}</label>
              <select id="rule-icmp-type">
                ${icmpTypes.map(i => `<option value="${i.value}" ${rule.icmpType === i.value ? 'selected' : ''}>${i.name}</option>`).join('')}
              </select>
            </div>
          ` : ''}

          <!-- Remark & Logging Options -->
          <div class="form-group full-width" style="display:flex; gap:1rem; align-items:center;">
            <div style="flex:1">
              <label for="rule-remark">${t('remarkLabel')}</label>
              <input type="text" id="rule-remark" value="${safeRemark}" placeholder="Description / comment" />
            </div>

            <div style="margin-top:1.1rem;">
              <label style="display:inline-flex; align-items:center; gap:0.35rem; cursor:pointer; font-family:var(--font-mono); font-size:0.75rem;">
                <input type="checkbox" id="rule-log" ${rule.log ? 'checked' : ''} />
                <span>${t('logMatchesLabel')}</span>
              </label>
            </div>
          </div>
        </div>

        <div style="margin-top: 0.6rem; display: flex; gap: 0.4rem; justify-content: flex-end;">
          ${editingRule ? `<button type="button" id="btn-cancel-rule" class="btn">${t('cancelBtn')}</button>` : ''}
          <button type="submit" class="btn btn-primary">
            ${editingRule ? t('updateRuleBtn') : t('addRuleBtn')}
          </button>
        </div>
      </form>
    </div>
  `;

  // Real-time Wildcard Preview Updates
  const updateWildcardHelper = (maskInputId, previewId) => {
    const el = document.getElementById(maskInputId);
    const prev = document.getElementById(previewId);
    if (el && prev) {
      el.addEventListener('input', (e) => {
        const wc = maskToWildcard(e.target.value);
        prev.textContent = `${t('wildcardPreview')}: ${wc || '0.0.0.255'}`;
      });
    }
  };

  updateWildcardHelper('rule-src-mask', 'src-wildcard-preview');
  updateWildcardHelper('rule-dst-mask', 'dst-wildcard-preview');

  // Preset Handlers
  const bindPreset = (presetId, inputId) => {
    const presetEl = document.getElementById(presetId);
    const inputEl = document.getElementById(inputId);
    if (presetEl && inputEl) {
      presetEl.addEventListener('change', (e) => {
        if (e.target.value) inputEl.value = e.target.value;
      });
    }
  };

  bindPreset('src-port-preset', 'rule-src-port');
  bindPreset('dst-port-preset', 'rule-dst-port');

  // Reactive Re-render when Protocol, Address Type, or Port Operator changes
  const retrigger = () => {
    const currentRuleData = extractRuleData(rule.id, isExtended);
    renderRuleForm(container, { aclType, editingRule: currentRuleData, onSaveRule, onCancelEdit });
  };

  document.getElementById('rule-protocol')?.addEventListener('change', retrigger);
  document.getElementById('rule-src-type')?.addEventListener('change', retrigger);
  document.getElementById('rule-src-port-op')?.addEventListener('change', retrigger);
  document.getElementById('rule-dst-type')?.addEventListener('change', retrigger);
  document.getElementById('rule-dst-port-op')?.addEventListener('change', retrigger);

  if (document.getElementById('btn-cancel-rule')) {
    document.getElementById('btn-cancel-rule').addEventListener('click', onCancelEdit);
  }

  document.getElementById('rule-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const finalRule = extractRuleData(rule.id, isExtended);

    // Reset previous error outlines
    ['rule-src-ip', 'rule-dst-ip', 'rule-src-port', 'rule-src-port-end', 'rule-dst-port', 'rule-dst-port-end'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.borderColor = '';
    });

    let invalidFieldId = null;

    // Client-side Validation Guard
    if (finalRule.srcType === ADDRESS_TYPES.HOST || finalRule.srcType === ADDRESS_TYPES.SUBNET) {
      if (!finalRule.srcIp || !isValidIp(finalRule.srcIp)) {
        invalidFieldId = 'rule-src-ip';
      }
    }
    if (!invalidFieldId && (finalRule.dstType === ADDRESS_TYPES.HOST || finalRule.dstType === ADDRESS_TYPES.SUBNET)) {
      if (!finalRule.dstIp || !isValidIp(finalRule.dstIp)) {
        invalidFieldId = 'rule-dst-ip';
      }
    }
    if (!invalidFieldId && finalRule.srcPort && normalizePort(finalRule.srcPort) === null) {
      invalidFieldId = 'rule-src-port';
    }
    if (!invalidFieldId && finalRule.srcPortEnd && normalizePort(finalRule.srcPortEnd) === null) {
      invalidFieldId = 'rule-src-port-end';
    }
    if (!invalidFieldId && finalRule.dstPort && normalizePort(finalRule.dstPort) === null) {
      invalidFieldId = 'rule-dst-port';
    }
    if (!invalidFieldId && finalRule.dstPortEnd && normalizePort(finalRule.dstPortEnd) === null) {
      invalidFieldId = 'rule-dst-port-end';
    }

    if (invalidFieldId) {
      const el = document.getElementById(invalidFieldId);
      if (el) {
        el.style.borderColor = 'var(--status-red)';
        el.focus();
      }
      alert(t('invalidFormWarning'));
      return;
    }

    onSaveRule(finalRule);
  });
}

function extractRuleData(id, isExtended) {
  const getVal = id => document.getElementById(id)?.value || '';
  const getCheck = id => document.getElementById(id)?.checked || false;

  const srcType = getVal('rule-src-type');
  const dstType = getVal('rule-dst-type');

  return {
    id,
    enabled: true,
    action: getVal('rule-action') || ACTIONS.PERMIT,
    protocol: isExtended ? (getVal('rule-protocol') || PROTOCOLS.IP) : PROTOCOLS.IP,
    srcType: srcType || ADDRESS_TYPES.ANY,
    srcIp: getVal('rule-src-ip'),
    srcMask: getVal('rule-src-mask'),
    srcWildcard: srcType === ADDRESS_TYPES.SUBNET ? maskToWildcard(getVal('rule-src-mask')) : '',
    srcPortOperator: getVal('rule-src-port-op') || 'any',
    srcPort: getVal('rule-src-port'),
    srcPortEnd: getVal('rule-src-port-end'),
    dstType: dstType || ADDRESS_TYPES.ANY,
    dstIp: getVal('rule-dst-ip'),
    dstMask: getVal('rule-dst-mask'),
    dstWildcard: dstType === ADDRESS_TYPES.SUBNET ? maskToWildcard(getVal('rule-dst-mask')) : '',
    dstPortOperator: getVal('rule-dst-port-op') || 'any',
    dstPort: getVal('rule-dst-port'),
    dstPortEnd: getVal('rule-dst-port-end'),
    icmpType: getVal('rule-icmp-type') || 'any',
    log: getCheck('rule-log'),
    remark: getVal('rule-remark')
  };
}
