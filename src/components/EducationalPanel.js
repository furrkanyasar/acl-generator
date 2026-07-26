/**
 * Educational Advice & Warning Engine Box (Structured Syslog Log Buffer Card)
 */

import { analyzeACL } from '../core/analyzer.js';
import { t } from '../core/i18n.js';

export function renderEducationalPanel(container, { config, rules }) {
  const warnings = analyzeACL(config, rules);

  container.innerHTML = `
    <div class="card syslog-card">
      <div class="card-header">
        <div class="card-title">
          ${t('proTipsTitle')}
        </div>
      </div>

      <div class="syslog-container">
        ${warnings.map(item => `
          <div class="syslog-line ${item.severity}">
            <span class="syslog-hdr">${item.title}</span>
            <span>${item.message}</span>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}
