/**
 * Header Component (46px NOC Navbar with Import CLI Action)
 */

import { VENDORS } from '../core/types.js';
import { t, getLanguage } from '../core/i18n.js';

export function renderHeader(container, { vendor, onVendorChange, onLangChange, onOpenTemplates, onOpenImport, onReset }) {
  const currentLang = getLanguage();

  container.innerHTML = `
    <header class="header-bar">
      <div class="brand">
        <div class="brand-icon-box">ACL</div>
        <div>
          <span class="brand-title">${t('appName')}</span>
          <span class="brand-subtitle" style="margin-left:0.5rem;">${t('appSubtitle')}</span>
        </div>
      </div>

      <div class="header-controls">
        <div class="lang-toggle">
          <button class="lang-btn ${currentLang === 'tr' ? 'active' : ''}" id="lang-btn-tr">TR</button>
          <button class="lang-btn ${currentLang === 'en' ? 'active' : ''}" id="lang-btn-en">EN</button>
        </div>

        <div style="margin: 0; min-width: 140px;">
          <select id="vendor-select" style="height: 32px; padding: 0 0.5rem; font-size: 0.82rem;">
            <option value="${VENDORS.CISCO}" ${vendor === VENDORS.CISCO ? 'selected' : ''}>Cisco IOS</option>
            <option value="${VENDORS.JUNIPER}" ${vendor === VENDORS.JUNIPER ? 'selected' : ''}>Juniper JunOS</option>
            <option value="${VENDORS.HUAWEI}" ${vendor === VENDORS.HUAWEI ? 'selected' : ''}>Huawei VRP</option>
          </select>
        </div>

        <button id="btn-import" class="btn btn-sm">
          ${t('importCli')}
        </button>

        <button id="btn-templates" class="btn btn-sm">
          ${t('starterTemplates')}
        </button>

        <button id="btn-reset" class="btn btn-danger btn-sm">
          ${t('resetApp')}
        </button>
      </div>
    </header>
  `;

  document.getElementById('vendor-select').addEventListener('change', (e) => {
    onVendorChange(e.target.value);
  });

  document.getElementById('lang-btn-tr').addEventListener('click', () => onLangChange('tr'));
  document.getElementById('lang-btn-en').addEventListener('click', () => onLangChange('en'));

  document.getElementById('btn-import').addEventListener('click', onOpenImport);
  document.getElementById('btn-templates').addEventListener('click', onOpenTemplates);
  document.getElementById('btn-reset').addEventListener('click', onReset);
}
