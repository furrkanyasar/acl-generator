/**
 * Reverse ACL Parser Import Modal Component
 */

import { parseCiscoACLScript } from '../core/parser.js';
import { t } from '../core/i18n.js';

export function renderImportModal(container, { onImportSuccess, onClose }) {
  container.innerHTML = `
    <div class="modal-backdrop" id="import-modal-bg">
      <div class="modal-content" style="max-width: 650px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem;">
          <h2 style="font-size:0.92rem; font-weight:700; font-family:var(--font-mono);">${t('importModalTitle')}</h2>
          <button id="import-close-btn" class="btn btn-sm">${t('closeBtn')}</button>
        </div>

        <form id="import-form">
          <textarea id="raw-cli-input" style="width:100%; height:220px; font-family:var(--font-mono); font-size:0.82rem; padding:0.6rem; background:var(--bg-terminal); color:#e2e8f0; border:1px solid var(--border-input);" placeholder="${t('importPlaceholder')}"></textarea>

          <div style="margin-top:0.75rem; display:flex; justify-content:flex-end; gap:0.5rem;">
            <button type="button" id="import-cancel-btn" class="btn btn-sm">${t('cancelBtn')}</button>
            <button type="submit" class="btn btn-sm btn-primary">${t('parseBtn')}</button>
          </div>
        </form>
      </div>
    </div>
  `;

  document.getElementById('import-close-btn').addEventListener('click', onClose);
  document.getElementById('import-cancel-btn').addEventListener('click', onClose);
  document.getElementById('import-modal-bg').addEventListener('click', (e) => {
    if (e.target.id === 'import-modal-bg') onClose();
  });

  document.getElementById('import-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const text = document.getElementById('raw-cli-input').value;
    if (text.trim()) {
      const parsedData = parseCiscoACLScript(text);
      if (parsedData.rules.length > 0) {
        onImportSuccess(parsedData);
        onClose();
      } else {
        alert('No valid access-list rules found in the input text.');
      }
    }
  });
}
