/**
 * Live CLI Code Preview Panel (Preview Card Container with Gutter)
 */

import { generateACLScript } from '../core/exporter.js';
import { t } from '../core/i18n.js';

export function renderPreviewPanel(container, { config, rules }) {
  const rawCode = generateACLScript(config, rules);
  const lines = rawCode.split('\n');

  const lineNumbersHtml = lines.map((_, i) => (i + 1).toString().padStart(2, '0')).join('\n');

  const highlightedCode = rawCode
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/(!.*|#.*)/g, '<span class="comment">$1</span>')
    .replace(/\b(ip access-list|access-list|interface|ip access-group|firewall|filter|family|term|acl|rule|source|destination|destination-port|traffic-filter)\b/g, '<span class="keyword">$1</span>')
    .replace(/\b(permit|accept)\b/g, '<span class="action-permit">$1</span>')
    .replace(/\b(deny|discard|reject)\b/g, '<span class="action-deny">$1</span>')
    .replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g, '<span class="ip">$1</span>');

  container.innerHTML = `
    <div class="card preview-card">
      <div class="card-header">
        <div class="card-title">
          ${t('cliTitle')}
        </div>
        <div style="display:flex; gap:0.35rem;">
          <button id="btn-copy-code" class="btn btn-sm btn-primary">
            ${t('copyScript')}
          </button>
          <button id="btn-download-code" class="btn btn-sm">
            ${t('downloadScript')}
          </button>
        </div>
      </div>

      <div class="terminal-window">
        <div class="line-numbers-col">${lineNumbersHtml}</div>
        <pre class="code-preview" id="cli-code-block">${highlightedCode}</pre>
      </div>
    </div>
  `;

  document.getElementById('btn-copy-code').addEventListener('click', () => {
    const showFeedback = () => {
      const btn = document.getElementById('btn-copy-code');
      if (btn) {
        btn.textContent = t('copied');
        setTimeout(() => {
          btn.textContent = t('copyScript');
        }, 2000);
      }
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(rawCode)
        .then(showFeedback)
        .catch(() => fallbackCopy(rawCode, showFeedback));
    } else {
      fallbackCopy(rawCode, showFeedback);
    }
  });

  function fallbackCopy(text, onSuccess) {
    try {
      const textArea = document.createElement('textarea');
      textArea.value = text;
      textArea.style.position = 'fixed';
      textArea.style.left = '-999999px';
      textArea.style.top = '-999999px';
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      document.execCommand('copy');
      textArea.remove();
      if (onSuccess) onSuccess();
    } catch (e) {
      // Ignore fallback failure
    }
  }

  document.getElementById('btn-download-code').addEventListener('click', () => {
    const safeName = (config.identifier || 'acl').trim().replace(/[^a-zA-Z0-9_-]/g, '_') || 'acl';
    const blob = new Blob([rawCode], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${safeName}_script.cfg`;
    a.click();
    URL.revokeObjectURL(url);
  });
}
