/**
 * Rule Table Component (Monospaced Buffer Table with 28px Action Icon Buttons)
 */

import { ACTIONS, ADDRESS_TYPES } from '../core/types.js';
import { maskToWildcard } from '../core/wildcard.js';
import { t } from '../core/i18n.js';

const ICON_UP = `<svg viewBox="0 0 24 24"><path d="M7 14l5-5 5 5H7z"/></svg>`;
const ICON_DOWN = `<svg viewBox="0 0 24 24"><path d="M7 10l5 5 5-5H7z"/></svg>`;
const ICON_EDIT = `<svg viewBox="0 0 24 24"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>`;
const ICON_CLONE = `<svg viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>`;
const ICON_DELETE = `<svg viewBox="0 0 24 24"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>`;

function formatAddressBadge(type, ip, mask) {
  if (type === ADDRESS_TYPES.ANY) return '<span style="color:var(--text-muted);">any</span>';
  if (type === ADDRESS_TYPES.HOST) return `<span>host <b style="color:#38bdf8;">${ip}</b></span>`;
  if (type === ADDRESS_TYPES.SUBNET) {
    const wc = maskToWildcard(mask);
    return `<span>subnet <b>${ip}</b> <small style="color:var(--text-muted)">(${wc || mask})</small></span>`;
  }
  return 'any';
}

function formatPortBadge(op, port) {
  if (!op || op === 'any' || !port) return '';
  return `<span style="font-size:0.78rem; color:var(--badge-warn-fg);">${op} ${port}</span>`;
}

export function renderRuleTable(container, { rules, warnings, onMoveUp, onMoveDown, onEdit, onDuplicate, onDelete }) {
  const shadowedRuleIds = new Set(
    warnings
      .filter(w => w.id && w.id.startsWith('shadowed-'))
      .map(w => w.id.replace('shadowed-', ''))
  );

  container.innerHTML = `
    <div class="card rule-table-card">
      <div class="card-header">
        <div class="card-title">
          ${t('activeRulesTitle')} (${rules.length})
        </div>
        <div style="font-size:0.74rem; color:var(--text-muted); font-family:var(--font-mono);">
          ${t('orderWarning')}
        </div>
      </div>

      ${rules.length === 0 ? `
        <div style="text-align:center; padding:1.2rem; color:var(--text-muted); font-family:var(--font-mono);">
          ${t('noRulesYet')}
        </div>
      ` : `
        <div class="rule-table-wrapper">
          <table class="rule-table">
            <thead>
              <tr>
                <th style="width: 30px;">#</th>
                <th style="width: 75px;">${t('colAction')}</th>
                <th style="width: 70px;">${t('colProto')}</th>
                <th>${t('colSrc')}</th>
                <th>${t('colDst')}</th>
                <th style="width: 45px;">${t('colLog')}</th>
                <th style="width: 140px; text-align:right;">${t('colActions')}</th>
              </tr>
            </thead>
            <tbody>
              ${rules.map((rule, idx) => {
                const isShadowed = shadowedRuleIds.has(rule.id);
                return `
                  <tr class="${isShadowed ? 'shadowed' : ''}">
                    <td style="font-weight:bold;">
                      ${idx + 1}
                      ${isShadowed ? '<span class="badge badge-warning" title="Shadowed Rule">[!]</span>' : ''}
                    </td>
                    <td>
                      <span class="badge ${rule.action === ACTIONS.PERMIT ? 'badge-permit' : 'badge-deny'}">
                        ${rule.action.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <span class="badge badge-protocol">
                        ${rule.protocol.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      ${formatAddressBadge(rule.srcType, rule.srcIp, rule.srcMask)}
                      ${formatPortBadge(rule.srcPortOperator, rule.srcPort)}
                    </td>
                    <td>
                      ${formatAddressBadge(rule.dstType, rule.dstIp, rule.dstMask)}
                      ${formatPortBadge(rule.dstPortOperator, rule.dstPort)}
                    </td>
                    <td style="font-size:0.78rem;">
                      ${rule.log ? '<span style="color:#38bdf8">LOG</span>' : '<span style="color:var(--text-dim)">-</span>'}
                    </td>
                    <td style="text-align:right;">
                      <div style="display:inline-flex; gap:0.2rem;">
                        <button class="btn btn-icon btn-move-up" data-idx="${idx}" ${idx === 0 ? 'disabled' : ''} title="${t('moveUp')}">${ICON_UP}</button>
                        <button class="btn btn-icon btn-move-down" data-idx="${idx}" ${idx === rules.length - 1 ? 'disabled' : ''} title="${t('moveDown')}">${ICON_DOWN}</button>
                        <button class="btn btn-icon btn-edit" data-id="${rule.id}" title="${t('editRule')}">${ICON_EDIT}</button>
                        <button class="btn btn-icon btn-dup" data-id="${rule.id}" title="${t('duplicateRule')}">${ICON_CLONE}</button>
                        <button class="btn btn-icon btn-danger btn-del" data-id="${rule.id}" title="${t('deleteRule')}">${ICON_DELETE}</button>
                      </div>
                    </td>
                  </tr>
                `;
              }).join('')}
            </tbody>
          </table>
        </div>
      `}
    </div>
  `;

  container.querySelectorAll('.btn-move-up').forEach(btn => {
    btn.addEventListener('click', () => onMoveUp(parseInt(btn.dataset.idx, 10)));
  });

  container.querySelectorAll('.btn-move-down').forEach(btn => {
    btn.addEventListener('click', () => onMoveDown(parseInt(btn.dataset.idx, 10)));
  });

  container.querySelectorAll('.btn-edit').forEach(btn => {
    btn.addEventListener('click', () => onEdit(btn.dataset.id));
  });

  container.querySelectorAll('.btn-dup').forEach(btn => {
    btn.addEventListener('click', () => onDuplicate(btn.dataset.id));
  });

  container.querySelectorAll('.btn-del').forEach(btn => {
    btn.addEventListener('click', () => onDelete(btn.dataset.id));
  });
}
