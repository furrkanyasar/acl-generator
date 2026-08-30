/**
 * Main Application Controller (Full NOC Console with Reverse Parser & Traffic Simulator)
 */

import { VENDORS, ACL_TYPES, ACTIONS, PROTOCOLS, ADDRESS_TYPES } from './core/types.js';
import { setLanguage, t } from './core/i18n.js';
import { renderHeader } from './components/Header.js';
import { renderACLSettings } from './components/ACLSettings.js';
import { renderRuleForm } from './components/RuleForm.js';
import { renderRuleTable } from './components/RuleTable.js';
import { renderPreviewPanel } from './components/PreviewPanel.js';
import { renderEducationalPanel } from './components/EducationalPanel.js';
import { renderTemplatesModal } from './components/TemplatesModal.js';
import { renderImportModal } from './components/ImportModal.js';
import { renderTrafficSimulator } from './components/TrafficSimulator.js';
import { analyzeACL } from './core/analyzer.js';

const STORAGE_STATE_KEY = 'acl_gen_app_state';

const DEFAULT_STATE = {
  vendor: VENDORS.CISCO,
  config: {
    type: ACL_TYPES.EXTENDED_NAMED,
    identifier: 'MY_SECURE_ACL',
    interfaceName: 'GigabitEthernet0/1',
    interfaceDirection: 'in'
  },
  rules: [
    {
      id: '1',
      enabled: true,
      action: ACTIONS.PERMIT,
      protocol: PROTOCOLS.TCP,
      srcType: ADDRESS_TYPES.HOST,
      srcIp: '192.168.1.50',
      srcMask: '',
      srcWildcard: '',
      srcPortOperator: 'any',
      srcPort: '',
      srcPortEnd: '',
      dstType: ADDRESS_TYPES.ANY,
      dstIp: '',
      dstMask: '',
      dstWildcard: '',
      dstPortOperator: 'eq',
      dstPort: '80',
      dstPortEnd: '',
      icmpType: 'any',
      log: false,
      remark: 'Allow HTTP traffic from Host'
    },
    {
      id: '2',
      enabled: true,
      action: ACTIONS.DENY,
      protocol: PROTOCOLS.IP,
      srcType: ADDRESS_TYPES.SUBNET,
      srcIp: '192.168.1.0',
      srcMask: '255.255.255.0',
      srcWildcard: '0.0.0.255',
      srcPortOperator: 'any',
      srcPort: '',
      srcPortEnd: '',
      dstType: ADDRESS_TYPES.ANY,
      dstIp: '',
      dstMask: '',
      dstWildcard: '',
      dstPortOperator: 'any',
      dstPort: '',
      dstPortEnd: '',
      icmpType: 'any',
      log: false,
      remark: 'Block rest of subnet'
    }
  ],
  editingRuleId: null,
  isTemplatesOpen: false,
  isImportOpen: false,
  activeRightTab: 'sim',
  simPacket: {
    srcIp: '192.168.1.50',
    dstIp: '10.0.0.1',
    protocol: PROTOCOLS.TCP,
    srcPort: '1024',
    dstPort: '80',
    icmpType: 'echo'
  }
};

function loadInitialState() {
  try {
    const saved = localStorage.getItem(STORAGE_STATE_KEY);
    if (saved) {
      const parsed = JSON.parse(saved);
      if (parsed && Array.isArray(parsed.rules)) {
        return {
          ...DEFAULT_STATE,
          vendor: parsed.vendor || DEFAULT_STATE.vendor,
          config: { ...DEFAULT_STATE.config, ...(parsed.config || {}) },
          rules: parsed.rules,
          activeRightTab: parsed.activeRightTab || DEFAULT_STATE.activeRightTab,
          simPacket: { ...DEFAULT_STATE.simPacket, ...(parsed.simPacket || {}) }
        };
      }
    }
  } catch (e) {
    // Ignore storage parse error and fall back to default
  }
  return { ...DEFAULT_STATE, rules: DEFAULT_STATE.rules.map(r => ({ ...r })) };
}

function saveStateToStorage(st) {
  try {
    localStorage.setItem(STORAGE_STATE_KEY, JSON.stringify({
      vendor: st.vendor,
      config: st.config,
      rules: st.rules,
      activeRightTab: st.activeRightTab,
      simPacket: st.simPacket
    }));
  } catch (e) {
    // Ignore storage quota errors
  }
}

let state = loadInitialState();

function setState(updater) {
  if (typeof updater === 'function') {
    state = updater(state);
  } else {
    state = { ...state, ...updater };
  }
  saveStateToStorage(state);
  renderApp();
}

function renderApp() {
  const root = document.getElementById('app-container');
  if (!root) return;

  root.innerHTML = `
    <div id="header-root"></div>
    
    <div class="main-layout">
      <!-- Left Column (45% Width): Controls & Buffer Table -->
      <div class="column">
        <div id="acl-settings-root"></div>
        <div id="rule-form-root"></div>
        <div id="rule-table-root" style="flex:1; min-height:0; display:flex; flex-direction:column;"></div>
      </div>

      <!-- Right Column (55% Width): CLI Terminal, Packet Simulator, & Syslog Console -->
      <div class="column">
        <!-- Right Column Tab Bar -->
        <div style="display:flex; gap:0.3rem; background:var(--bg-panel); border:1px solid var(--border-color); border-radius:var(--radius); padding:0.25rem; flex-shrink:0;">
          <button class="btn btn-sm ${state.activeRightTab === 'cli' ? 'btn-primary' : ''}" id="tab-btn-cli">${t('cliBufferTab')}</button>
          <button class="btn btn-sm ${state.activeRightTab === 'sim' ? 'btn-primary' : ''}" id="tab-btn-sim">${t('trafficSimTab')}</button>
          <button class="btn btn-sm ${state.activeRightTab === 'syslog' ? 'btn-primary' : ''}" id="tab-btn-syslog">${t('syslogTab')}</button>
        </div>

        <div id="right-tab-content-root" style="flex:1; min-height:0; display:flex; flex-direction:column;"></div>
      </div>
    </div>

    <div id="modal-root"></div>
  `;

  // Render Header Navbar
  renderHeader(document.getElementById('header-root'), {
    vendor: state.vendor,
    onVendorChange: (newVendor) => setState({ vendor: newVendor }),
    onLangChange: (lang) => {
      setLanguage(lang);
      renderApp();
    },
    onOpenTemplates: () => setState({ isTemplatesOpen: true }),
    onOpenImport: () => setState({ isImportOpen: true }),
    onReset: () => {
      if (confirm(t('resetConfirm'))) {
        try {
          localStorage.removeItem(STORAGE_STATE_KEY);
        } catch (e) {}
        setState({
          vendor: DEFAULT_STATE.vendor,
          config: { ...DEFAULT_STATE.config },
          rules: DEFAULT_STATE.rules.map(r => ({ ...r })),
          editingRuleId: null,
          activeRightTab: 'sim'
        });
      }
    }
  });

  // Render ACL Settings
  renderACLSettings(document.getElementById('acl-settings-root'), state.config, (configUpdate) => {
    setState({ config: { ...state.config, ...configUpdate } });
  });

  // Render Rule Form
  const editingRule = state.editingRuleId ? state.rules.find(r => r.id === state.editingRuleId) : null;
  renderRuleForm(document.getElementById('rule-form-root'), {
    aclType: state.config.type,
    editingRule,
    onSaveRule: (ruleData) => {
      if (state.editingRuleId) {
        setState({
          rules: state.rules.map(r => r.id === state.editingRuleId ? ruleData : r),
          editingRuleId: null
        });
      } else {
        const nextId = (state.rules.reduce((max, r) => Math.max(max, parseInt(r.id, 10) || 0), 0) + 1).toString();
        ruleData.id = nextId;
        setState({ rules: [...state.rules, ruleData] });
      }
    },
    onCancelEdit: () => setState({ editingRuleId: null })
  });

  // Render Rule Table
  const warnings = analyzeACL(state.config, state.rules);
  renderRuleTable(document.getElementById('rule-table-root'), {
    rules: state.rules,
    warnings,
    onMoveUp: (idx) => {
      if (idx <= 0) return;
      const copy = [...state.rules];
      const temp = copy[idx - 1];
      copy[idx - 1] = copy[idx];
      copy[idx] = temp;
      setState({ rules: copy });
    },
    onMoveDown: (idx) => {
      if (idx >= state.rules.length - 1) return;
      const copy = [...state.rules];
      const temp = copy[idx + 1];
      copy[idx + 1] = copy[idx];
      copy[idx] = temp;
      setState({ rules: copy });
    },
    onEdit: (id) => setState({ editingRuleId: id }),
    onDuplicate: (id) => {
      const target = state.rules.find(r => r.id === id);
      if (target) {
        const nextId = (state.rules.reduce((max, r) => Math.max(max, parseInt(r.id, 10) || 0), 0) + 1).toString();
        const clone = { ...target, id: nextId };
        setState({ rules: [...state.rules, clone] });
      }
    },
    onDelete: (id) => {
      setState({ rules: state.rules.filter(r => r.id !== id), editingRuleId: state.editingRuleId === id ? null : state.editingRuleId });
    }
  });

  // Attach Right Column Tab Handlers
  document.getElementById('tab-btn-cli').addEventListener('click', () => setState({ activeRightTab: 'cli' }));
  document.getElementById('tab-btn-sim').addEventListener('click', () => setState({ activeRightTab: 'sim' }));
  document.getElementById('tab-btn-syslog').addEventListener('click', () => setState({ activeRightTab: 'syslog' }));

  // Render Active Right Column Content
  const tabContentRoot = document.getElementById('right-tab-content-root');

  if (state.activeRightTab === 'cli') {
    renderPreviewPanel(tabContentRoot, {
      config: { ...state.config, vendor: state.vendor },
      rules: state.rules
    });
  } else if (state.activeRightTab === 'sim') {
    renderTrafficSimulator(tabContentRoot, {
      rules: state.rules,
      currentPacket: state.simPacket,
      onSimulate: (pkt) => {
        state.simPacket = pkt;
      }
    });
  } else {
    renderEducationalPanel(tabContentRoot, {
      config: state.config,
      rules: state.rules
    });
  }

  // Render Modals if active
  const modalRoot = document.getElementById('modal-root');
  if (state.isTemplatesOpen) {
    renderTemplatesModal(modalRoot, {
      onSelectTemplate: (template) => {
        setState({
          vendor: template.config.vendor || VENDORS.CISCO,
          config: { ...template.config },
          rules: template.rules.map(r => ({ ...r })),
          editingRuleId: null
        });
      },
      onClose: () => setState({ isTemplatesOpen: false })
    });
  } else if (state.isImportOpen) {
    renderImportModal(modalRoot, {
      onImportSuccess: (parsed) => {
        setState({
          config: { ...state.config, ...parsed.config },
          rules: parsed.rules,
          editingRuleId: null
        });
      },
      onClose: () => setState({ isImportOpen: false })
    });
  }
}

document.addEventListener('DOMContentLoaded', () => {
  renderApp();
});
