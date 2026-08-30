/**
 * Internationalization (i18n) Module - TR / EN (Enterprise Features Edition)
 */

export const LANGUAGES = {
  TR: 'tr',
  EN: 'en'
};

const STORAGE_KEY = 'acl_gen_lang';

export const translations = {
  tr: {
    // Header
    appName: 'ACL Generator',
    appSubtitle: 'Ağ ACL Yapılandırma ve Analiz Konsolu',
    vendorLabel: 'Vendor',
    starterTemplates: 'Şablonlar',
    importCli: 'CLI İçe Aktar',
    resetApp: 'Sıfırla',
    resetConfirm: 'ACL yapılandırmasını sıfırlamak istediğinize emin misiniz?',

    // Settings
    settingsTitle: 'ACL VE ARABİRİM YAPILANDIRMASI',
    aclTypeLabel: 'ACL TİPİ',
    aclIdentifierLabel: 'ACL ADI / NUMARASI',
    interfaceNameLabel: 'ARABİRİM (INTERFACE)',
    directionLabel: 'TRAFİK YÖNÜ',
    dirInbound: 'INBOUND (Giriş)',
    dirOutbound: 'OUTBOUND (Çıkış)',

    // ACL Types
    extNamed: 'Extended Named',
    extNum: 'Extended Numbered',
    stdNamed: 'Standard Named',
    stdNum: 'Standard Numbered',

    // Rule Form
    constructRuleTitle: 'ERİŞİM KURALI TANIMLA (ACE)',
    editRuleTitle: 'ERİŞİM KURALINI DÜZENLE',
    actionLabel: 'İŞLEM (ACTION)',
    permitAction: 'PERMIT',
    denyAction: 'DENY',
    protocolLabel: 'PROTOKOL',
    extendedOnly: '(Sadece Extended)',
    srcAddrLabel: 'KAYNAK ADRESİ (SOURCE)',
    dstAddrLabel: 'HEDEF ADRESİ (DESTINATION)',
    anyAddr: 'ANY (0.0.0.0/0)',
    singleHost: 'HOST (Tekil IP)',
    subnetNet: 'SUBNET (Alt Ağ)',
    hostIpLabel: 'HOST IP ADRESİ',
    subnetIpLabel: 'SUBNET IP ADRESİ',
    maskLabel: 'SUBNET MASK / CIDR',
    wildcardPreview: 'WILDCARD MASK',
    srcPortOpLabel: 'KAYNAK PORT OPERATÖRÜ',
    dstPortOpLabel: 'HEDEF PORT OPERATÖRÜ',
    portAny: 'ANY',
    portEq: 'eq (Eşittir)',
    portNeq: 'neq (Eşit Değil)',
    portGt: 'gt (Büyük)',
    portLt: 'lt (Küçük)',
    portRange: 'range (Aralık)',
    portPresetLabel: 'PORT ŞABLONU',
    presetSelect: 'Seçiniz...',
    icmpTypeLabel: 'ICMP TİPİ',
    remarkLabel: 'AÇIKLAMA (REMARK)',
    logMatchesLabel: 'EŞLEŞMELERİ LOGLA',
    addRuleBtn: 'Kural Ekle',
    updateRuleBtn: 'Kuralı Güncelle',
    cancelBtn: 'İptal',

    // Rule Table
    activeRulesTitle: 'ACE KURAL LİSTESİ (BUFFER)',
    orderWarning: 'Yukarıdan aşağıya sıralı çalışma aktif',
    noRulesYet: 'Tampon bellekte tanımlı kural bulunmuyor',
    colNum: '#',
    colAction: 'İŞLEM',
    colProto: 'PROTO',
    colSrc: 'KAYNAK',
    colDst: 'HEDEF',
    colLog: 'LOG',
    colActions: 'İŞLEMLER',
    moveUp: 'Yukarı',
    moveDown: 'Aşağı',
    editRule: 'Düzenle',
    duplicateRule: 'Kopyala',
    deleteRule: 'Sil',

    // Right Column Tabs
    cliBufferTab: 'CLI TAMPONU',
    trafficSimTab: 'PAKET SİMÜLATÖRÜ',
    syslogTab: 'SYSLOG KONSOLU',

    // Preview
    cliTitle: 'CLI YAPILANDIRMA TAMPONU',
    copyScript: 'Kopyala',
    copied: 'Kopyalandı',
    downloadScript: 'İndir (.cfg)',

    // Traffic Simulator
    simSrcIp: 'KAYNAK IP',
    simDstIp: 'HEDEF IP',
    simSrcPort: 'KAYNAK PORT',
    simDstPort: 'HEDEF PORT',
    testPacketBtn: 'Paket Eşleşmesini Test Et',
    matchResultTitle: 'EŞLEŞME SONUCU',
    explainableTitle: '💡 Açıklanabilir Politika Teşhisi (Neden?)',
    laterConflictingAce: 'Sonraki Çatışan ACE:',
    decisionLogicMsg: 'ACE #{firstIndex} bu paketi ilk eşleştiren kural oldu. Cisco ACL değerlendirmesi ilk eşleşen kuralda durur, bu nedenle daha aşağıdaki ACE #{laterIndex} ({laterAction}) değerlendirilmedi.',
    shadowedPacketSpace: 'Gölgede Kalan Paket Uzayı',
    decisionLogicHeader: 'Karar Mantığı:',

    // Import Modal
    importModalTitle: 'RAW CISCO CLI İÇE AKTAR VE PARSE ET',
    parseBtn: 'İçe Aktar ve Yükle',
    importPlaceholder: 'Cisco IOS access-list komutlarını buraya yapıştırın...\nÖrnek:\nip access-list extended MY_ACL\n permit tcp host 192.168.1.50 any eq 80\n deny ip 192.168.1.0 0.0.0.255 any',

    // Educational / Syslog Buffer
    proTipsTitle: 'SYSLOG & TANI KONSOLU',
    implicitDenyTitle: '[SYS-WARN] [IMPLICIT-DENY]',
    implicitDenyMsg: 'ACL sonunda otomatik "deny ip any any" kuralı çalışır. Eşleşmeyen trafik düşürülür.',
    standardPlacementTitle: '[SYS-INFO] [STANDARD-PLACEMENT]',
    standardPlacementMsg: 'Standard ACL yalnızca Kaynak IP denetler. Erken engellemeyi önlemek için HEDEFE en yakın arabirime uygulanmalıdır.',
    extendedPlacementTitle: '[SYS-INFO] [EXTENDED-PLACEMENT]',
    extendedPlacementMsg: 'Extended ACL Kaynak, Hedef, Protokol ve Port denetler. Bant genişliğini korumak için KAYNAĞA en yakın arabirime uygulanmalıdır.',
    interfaceDirTitle: '[SYS-INFO] [INTERFACE-BINDING]',
    inboundDesc: 'INBOUND: Arabirime giren paketleri yönlendirme kararı öncesinde denetler.',
    outboundDesc: 'OUTBOUND: Arabirimden çıkan paketleri yönlendirme kararı sonrasında denetler.',
    shadowedTitle: '[SYS-ALERT] [SHADOWED-RULE]',
    shadowedMsg: 'Kural #{next} ({nextProto}), üstteki Kural #{prev} ({prevProto}) kapsama alanında kaldığı için çalışmayacaktır.',

    // Templates Modal
    templatesModalTitle: 'HAZIR ACL ŞABLONLARI',
    closeBtn: 'Kapat',

    // Port Presets
    ports: {
      http: 'HTTP (80)',
      https: 'HTTPS (443)',
      ssh: 'SSH (22)',
      telnet: 'Telnet (23)',
      ftp: 'FTP (21)',
      dns: 'DNS (53)',
      dhcpServer: 'DHCP Server (67)',
      dhcpClient: 'DHCP Client (68)',
      ntp: 'NTP (123)',
      snmp: 'SNMP (161)',
      bgp: 'BGP (179)',
      rdp: 'RDP (3389)'
    },

    // ICMP Presets
    icmp: {
      echo: 'Echo Request (8)',
      echoReply: 'Echo Reply (0)',
      unreachable: 'Unreachable (3)',
      timeExceeded: 'Time Exceeded (11)',
      parameterProblem: 'Parameter Problem (12)',
      redirect: 'Redirect (5)',
      any: 'Any ICMP'
    }
  },

  en: {
    // Header
    appName: 'ACL Generator',
    appSubtitle: 'Network ACL Console',
    vendorLabel: 'Vendor',
    starterTemplates: 'Templates',
    importCli: 'Import CLI',
    resetApp: 'Reset',
    resetConfirm: 'Are you sure you want to reset all rules and settings?',

    // Settings
    settingsTitle: 'ACL & INTERFACE CONFIGURATION',
    aclTypeLabel: 'ACL TYPE',
    aclIdentifierLabel: 'ACL NAME / NUMBER',
    interfaceNameLabel: 'INTERFACE',
    directionLabel: 'DIRECTION',
    dirInbound: 'INBOUND',
    dirOutbound: 'OUTBOUND',

    // ACL Types
    extNamed: 'Extended Named',
    extNum: 'Extended Numbered',
    stdNamed: 'Standard Named',
    stdNum: 'Standard Numbered',

    // Rule Form
    constructRuleTitle: 'CONSTRUCT ACE RULE',
    editRuleTitle: 'EDIT ACE RULE',
    actionLabel: 'ACTION',
    permitAction: 'PERMIT',
    denyAction: 'DENY',
    protocolLabel: 'PROTOCOL',
    extendedOnly: '(Extended Only)',
    srcAddrLabel: 'SOURCE ADDRESS',
    dstAddrLabel: 'DESTINATION ADDRESS',
    anyAddr: 'ANY (0.0.0.0/0)',
    singleHost: 'HOST',
    subnetNet: 'SUBNET',
    hostIpLabel: 'HOST IP',
    subnetIpLabel: 'SUBNET IP',
    maskLabel: 'SUBNET MASK / CIDR',
    wildcardPreview: 'WILDCARD MASK',
    srcPortOpLabel: 'SRC PORT OPERATOR',
    dstPortOpLabel: 'DST PORT OPERATOR',
    portAny: 'ANY',
    portEq: 'eq',
    portNeq: 'neq',
    portGt: 'gt',
    portLt: 'lt',
    portRange: 'range',
    portPresetLabel: 'PORT PRESET',
    presetSelect: 'Select...',
    icmpTypeLabel: 'ICMP TYPE',
    remarkLabel: 'REMARK',
    logMatchesLabel: 'LOG MATCHES',
    addRuleBtn: 'Add Rule',
    updateRuleBtn: 'Update Rule',
    cancelBtn: 'Cancel',

    // Rule Table
    activeRulesTitle: 'ACE RULE BUFFER',
    orderWarning: 'Top-to-bottom evaluation active',
    noRulesYet: 'No ACE rules in buffer',
    colNum: '#',
    colAction: 'ACTION',
    colProto: 'PROTO',
    colSrc: 'SOURCE',
    colDst: 'DESTINATION',
    colLog: 'LOG',
    colActions: 'ACTIONS',
    moveUp: 'Up',
    moveDown: 'Down',
    editRule: 'Edit',
    duplicateRule: 'Clone',
    deleteRule: 'Delete',

    // Right Column Tabs
    cliBufferTab: 'CLI BUFFER',
    trafficSimTab: 'TRAFFIC SIMULATOR',
    syslogTab: 'SYSLOG CONSOLE',

    // Preview
    cliTitle: 'CLI CONFIGURATION BUFFER',
    copyScript: 'Copy CLI',
    copied: 'Copied',
    downloadScript: 'Export (.cfg)',

    // Traffic Simulator
    simSrcIp: 'SOURCE IP',
    simDstIp: 'DESTINATION IP',
    simSrcPort: 'SOURCE PORT',
    simDstPort: 'DESTINATION PORT',
    testPacketBtn: 'Simulate Packet Match',
    matchResultTitle: 'SIMULATION MATCH RESULT',
    explainableTitle: '💡 Explainable Policy Diagnostics (Why?)',
    laterConflictingAce: 'Later Conflicting ACE:',
    decisionLogicMsg: 'ACE #{matchedIndex} matched this packet first. Cisco ACL evaluation halts on the first matching rule, so lower ACE #{overriddenIndex} ({action}) was not evaluated.',
    shadowedPacketSpace: 'Shadowed Packet-Space:',

    // Import Modal
    importModalTitle: 'IMPORT & PARSE RAW CISCO CLI',
    parseBtn: 'Parse & Load Rules',
    importPlaceholder: 'Paste raw Cisco IOS ACL commands here...\nExample:\nip access-list extended MY_ACL\n permit tcp host 192.168.1.50 any eq 80\n deny ip 192.168.1.0 0.0.0.255 any',

    // Educational / Syslog Buffer
    proTipsTitle: 'SYSLOG & DIAGNOSTIC CONSOLE',
    implicitDenyTitle: '[SYS-WARN] [IMPLICIT-DENY]',
    implicitDenyMsg: 'Implicit "deny ip any any" active at sequence end. Unmatched traffic will be dropped.',
    standardPlacementTitle: '[SYS-INFO] [STANDARD-PLACEMENT]',
    standardPlacementMsg: 'Standard ACL evaluates Source IP only. Apply as close to DESTINATION as possible.',
    extendedPlacementTitle: '[SYS-INFO] [EXTENDED-PLACEMENT]',
    extendedPlacementMsg: 'Extended ACL evaluates Src/Dst IP, Proto, Ports. Apply as close to SOURCE as possible.',
    interfaceDirTitle: '[SYS-INFO] [INTERFACE-BINDING]',
    inboundDesc: 'INBOUND: Evaluates traffic entering interface prior to routing lookup.',
    outboundDesc: 'OUTBOUND: Evaluates traffic exiting interface post routing decision.',
    shadowedTitle: '[SYS-ALERT] [SHADOWED-RULE]',
    shadowedMsg: 'Rule #{next} ({nextProto}) is shadowed by Rule #{prev} ({prevProto}) and will never be reached.',

    // Templates Modal
    templatesModalTitle: 'PRESET ACL TEMPLATES',
    closeBtn: 'Close',

    // Port Presets
    ports: {
      http: 'HTTP (80)',
      https: 'HTTPS (443)',
      ssh: 'SSH (22)',
      telnet: 'Telnet (23)',
      ftp: 'FTP (21)',
      dns: 'DNS (53)',
      dhcpServer: 'DHCP Server (67)',
      dhcpClient: 'DHCP Client (68)',
      ntp: 'NTP (123)',
      snmp: 'SNMP (161)',
      bgp: 'BGP (179)',
      rdp: 'RDP (3389)'
    },

    // ICMP Presets
    icmp: {
      echo: 'Echo Request (8)',
      echoReply: 'Echo Reply (0)',
      unreachable: 'Unreachable (3)',
      timeExceeded: 'Time Exceeded (11)',
      parameterProblem: 'Parameter Problem (12)',
      redirect: 'Redirect (5)',
      any: 'Any ICMP'
    }
  }
};

function safeGetStorage(key, fallback) {
  try {
    return localStorage.getItem(key) || fallback;
  } catch (e) {
    return fallback;
  }
}

function safeSetStorage(key, val) {
  try {
    localStorage.setItem(key, val);
  } catch (e) {
    // Ignore storage quota or security restriction exceptions
  }
}

let currentLang = safeGetStorage(STORAGE_KEY, LANGUAGES.TR);

export function getLanguage() {
  return currentLang;
}

export function setLanguage(lang) {
  if (translations[lang]) {
    currentLang = lang;
    safeSetStorage(STORAGE_KEY, lang);
  }
}

export function t(keyPath) {
  const parts = keyPath.split('.');
  let curr = translations[currentLang];
  for (const p of parts) {
    if (curr && curr[p] !== undefined) {
      curr = curr[p];
    } else {
      return keyPath;
    }
  }
  return curr;
}
