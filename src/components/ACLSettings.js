/**
 * ACL Settings Component (Ultra-Compact NOC Grid)
 */

import { ACL_TYPES, escapeHtml } from '../core/types.js';
import { t } from '../core/i18n.js';

export function renderACLSettings(container, config, onChange) {
  const safeId = escapeHtml(config.identifier || '');
  const safeIface = escapeHtml(config.interfaceName || '');

  container.innerHTML = `
    <div class="card" style="flex-shrink: 0;">
      <div class="card-header">
        <div class="card-title">
          ${t('settingsTitle')}
        </div>
      </div>

      <div class="form-grid">
        <div class="form-group">
          <label for="acl-type">${t('aclTypeLabel')}</label>
          <select id="acl-type">
            <option value="${ACL_TYPES.EXTENDED_NAMED}" ${config.type === ACL_TYPES.EXTENDED_NAMED ? 'selected' : ''}>${t('extNamed')}</option>
            <option value="${ACL_TYPES.EXTENDED_NUMBERED}" ${config.type === ACL_TYPES.EXTENDED_NUMBERED ? 'selected' : ''}>${t('extNum')}</option>
            <option value="${ACL_TYPES.STANDARD_NAMED}" ${config.type === ACL_TYPES.STANDARD_NAMED ? 'selected' : ''}>${t('stdNamed')}</option>
            <option value="${ACL_TYPES.STANDARD_NUMBERED}" ${config.type === ACL_TYPES.STANDARD_NUMBERED ? 'selected' : ''}>${t('stdNum')}</option>
          </select>
        </div>

        <div class="form-group">
          <label for="acl-identifier">${t('aclIdentifierLabel')}</label>
          <input type="text" id="acl-identifier" value="${safeId}" placeholder="MY_SECURE_ACL / 101" />
        </div>

        <div class="form-group">
          <label for="interface-name">${t('interfaceNameLabel')}</label>
          <input type="text" id="interface-name" value="${safeIface}" placeholder="GigabitEthernet0/0/1" />
        </div>

        <div class="form-group">
          <label for="interface-direction">${t('directionLabel')}</label>
          <select id="interface-direction">
            <option value="in" ${config.interfaceDirection === 'in' ? 'selected' : ''}>${t('dirInbound')}</option>
            <option value="out" ${config.interfaceDirection === 'out' ? 'selected' : ''}>${t('dirOutbound')}</option>
          </select>
        </div>
      </div>
    </div>
  `;

  const bind = (id, key) => {
    document.getElementById(id).addEventListener('input', (e) => {
      onChange({ [key]: e.target.value });
    });
  };

  bind('acl-type', 'type');
  bind('acl-identifier', 'identifier');
  bind('interface-name', 'interfaceName');
  bind('interface-direction', 'interfaceDirection');
}
