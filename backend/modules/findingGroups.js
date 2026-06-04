const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEVERITY_RANK = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0
};

const HARDENING_TOOLS = new Set(['headers', 'cookies', 'httpsredirect', 'tls']);
const HARDENING_TYPES = new Set([
  'missing_security_header',
  'insecure_cookie',
  'missing_https_redirect',
  'tls_certificate_issue',
  'hardening'
]);

const ATTACK_SURFACE_TYPES = new Set([
  'surface',
  'attack_surface',
  'exposed_port',
  'robots_sensitive_path',
  'historical-url'
]);

const INFO_TYPES = new Set([
  'reconocimiento',
  'informational',
  'historical-url'
]);

const NUCLEI_INFO_TEMPLATES = [
  'tech-detect',
  'waf-detect',
  'favicon',
  'cdn-detect',
  'wildcard-dns-detect',
  'http-missing-security-headers',
  'missing-security-header'
];

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function normalizeSeverity(value, fallback = 'info') {
  const lower = String(value || fallback).toLowerCase();
  const map = {
    critica: 'critical',
    critico: 'critical',
    alta: 'high',
    alto: 'high',
    media: 'medium',
    medio: 'medium',
    baja: 'low',
    bajo: 'low',
    informational: 'info'
  };
  const normalized = map[lower] || lower;
  return SEVERITY_ORDER.includes(normalized) ? normalized : 'info';
}

function normalizeConfidence(value, fallback = 'low') {
  const lower = String(value || fallback).toLowerCase();
  if (['high', 'medium', 'low'].includes(lower)) return lower;
  if (['confirmed', 'confirmada', 'confirmado'].includes(lower)) return 'high';
  if (['probable', 'possible', 'posible'].includes(lower)) return 'medium';
  return fallback;
}

function capSeverity(severity, maxSeverity) {
  const current = normalizeSeverity(severity);
  const max = normalizeSeverity(maxSeverity);
  return SEVERITY_RANK[current] > SEVERITY_RANK[max] ? max : current;
}

function canonicalToolName(tool = '') {
  const lower = String(tool || 'otra').toLowerCase();
  const names = {
    httpsredirect: 'httpsRedirect',
    robotssitemap: 'robotsSitemap',
    ferox: 'feroxbuster'
  };
  return names[lower] || lower;
}

function percentage(value, total) {
  if (!total) return 0;
  return Math.round((Number(value || 0) / total) * 100);
}

function findingText(finding = {}) {
  return [
    finding.id,
    finding.templateID,
    finding.template_id,
    finding.title,
    finding.name,
    finding.type,
    finding.category,
    finding.evidence,
    finding.raw_reference,
    finding.raw
  ].filter(Boolean).join(' ').toLowerCase();
}

function gfMaxSeverity(vulnerabilityType = '') {
  const type = String(vulnerabilityType || '').toLowerCase();
  if (['sqli', 'ssrf', 'lfi', 'rce'].includes(type)) return 'medium';
  return 'low';
}

function isNucleiInformational(finding = {}) {
  const text = findingText(finding);
  return NUCLEI_INFO_TEMPLATES.some(token => text.includes(token)) ||
    normalizeSeverity(finding.severity) === 'info';
}

function hasTechnicalEvidence(finding = {}) {
  const text = findingText(finding);
  return [
    'payload',
    'matched-at',
    'extracted-results',
    'proof',
    'poc',
    'triggered',
    'vulnerable',
    'dbms',
    'cve-'
  ].some(token => text.includes(token));
}

function sortFindings(findings = []) {
  return findings.slice().sort((a, b) => (
    SEVERITY_RANK[normalizeSeverity(b.severity)] - SEVERITY_RANK[normalizeSeverity(a.severity)] ||
    canonicalToolName(a.tool).localeCompare(canonicalToolName(b.tool)) ||
    String(a.title || '').localeCompare(String(b.title || ''))
  ));
}

function makeBase(raw = {}) {
  const tool = canonicalToolName(raw.tool || raw.herramienta || 'otra');
  const type = String(raw.type || raw.tipo || 'informational').toLowerCase().replace(/-/g, '_');

  return {
    ...raw,
    tool,
    type,
    severity: normalizeSeverity(raw.severity || raw.severidad || raw.criticidad),
    confidence: normalizeConfidence(raw.confidence || raw.confianza, 'low'),
    category: raw.category || raw.categoria || 'informational',
    isVulnerability: raw.isVulnerability === true,
    confirmed: raw.confirmed === true,
    reportable: raw.reportable === true,
    requiresManualValidation: raw.requiresManualValidation === true,
    isFalsePositiveLikely: raw.isFalsePositiveLikely === true,
    falsePositiveReason: raw.falsePositiveReason || ''
  };
}

function normalizeGfCandidate(finding) {
  const vulnerabilityType = String(finding.vulnerability_type || finding.pattern || '').toLowerCase();
  return {
    ...finding,
    type: 'gf_candidate',
    category: 'candidate',
    severity: capSeverity(finding.severity, gfMaxSeverity(vulnerabilityType)),
    confidence: 'low',
    isVulnerability: false,
    confirmed: false,
    reportable: false,
    requiresManualValidation: true,
    isFalsePositiveLikely: false,
    falsePositiveReason: 'GF prioriza candidatos por patron; no confirma explotabilidad.'
  };
}

function normalizeSqlmap(finding) {
  const sourceStatus = finding.source_status || finding.status;

  if (sourceStatus === 'confirmed_sqli' || finding.vulnerable === true) {
    return {
      ...finding,
      type: 'confirmed_vulnerability',
      category: 'vulnerability',
      severity: ['critical', 'high'].includes(normalizeSeverity(finding.severity)) ? normalizeSeverity(finding.severity) : 'critical',
      confidence: 'high',
      isVulnerability: true,
      confirmed: true,
      reportable: true,
      requiresManualValidation: false,
      isFalsePositiveLikely: false,
      falsePositiveReason: '',
      source_status: sourceStatus
    };
  }

  if (sourceStatus === 'possible_sqli') {
    return {
      ...finding,
      type: 'possible_vulnerability',
      category: 'vulnerability',
      severity: 'high',
      confidence: 'medium',
      isVulnerability: true,
      confirmed: false,
      reportable: true,
      requiresManualValidation: true,
      isFalsePositiveLikely: false,
      falsePositiveReason: '',
      source_status: sourceStatus,
      status: 'requires_manual_validation'
    };
  }

  return {
    ...finding,
    type: 'discarded',
    category: 'discarded',
    severity: 'info',
    confidence: 'low',
    isVulnerability: false,
    confirmed: false,
    reportable: false,
    requiresManualValidation: false,
    isFalsePositiveLikely: true,
    falsePositiveReason: finding.falsePositiveReason || finding.error || 'Sqlmap no confirmo inyeccion SQL.'
  };
}

function normalizeDalfox(finding) {
  const confidence = normalizeConfidence(finding.confidence);
  const confirmed = confidence === 'high' || String(finding.status || '').toLowerCase().includes('confirmed');

  if (confirmed) {
    return {
      ...finding,
      type: 'confirmed_vulnerability',
      category: 'vulnerability',
      severity: capSeverity(finding.severity || 'high', 'high'),
      confidence: 'high',
      isVulnerability: true,
      confirmed: true,
      reportable: true,
      requiresManualValidation: false,
      isFalsePositiveLikely: false,
      falsePositiveReason: ''
    };
  }

  return {
    ...finding,
    type: 'possible_vulnerability',
    category: 'vulnerability',
    severity: normalizeSeverity(finding.severity, 'medium'),
    confidence: 'medium',
    isVulnerability: true,
    confirmed: false,
    reportable: true,
    requiresManualValidation: true,
    isFalsePositiveLikely: false,
    falsePositiveReason: ''
  };
}

function normalizeNuclei(finding) {
  if (isNucleiInformational(finding)) {
    return {
      ...finding,
      type: findingText(finding).includes('missing-security-header') ? 'hardening' : 'informational',
      category: findingText(finding).includes('missing-security-header') ? 'hardening' : 'informational',
      severity: findingText(finding).includes('missing-security-header') ? 'low' : 'info',
      confidence: 'low',
      isVulnerability: false,
      confirmed: false,
      reportable: false,
      requiresManualValidation: false,
      isFalsePositiveLikely: false
    };
  }

  if (['critical', 'high'].includes(normalizeSeverity(finding.severity)) && hasTechnicalEvidence(finding)) {
    return {
      ...finding,
      type: 'confirmed_vulnerability',
      category: 'vulnerability',
      confidence: 'high',
      isVulnerability: true,
      confirmed: true,
      reportable: true,
      requiresManualValidation: false,
      isFalsePositiveLikely: false,
      falsePositiveReason: ''
    };
  }

  if (['critical', 'high', 'medium'].includes(normalizeSeverity(finding.severity))) {
    return {
      ...finding,
      type: 'possible_vulnerability',
      category: 'vulnerability',
      confidence: 'medium',
      isVulnerability: true,
      confirmed: false,
      reportable: true,
      requiresManualValidation: true,
      isFalsePositiveLikely: false,
      falsePositiveReason: ''
    };
  }

  return {
    ...finding,
    type: 'informational',
    category: 'informational',
    severity: 'info',
    confidence: 'low',
    isVulnerability: false,
    confirmed: false,
    reportable: false,
    requiresManualValidation: false,
    isFalsePositiveLikely: false
  };
}

function normalizeFindingClassification(raw = {}) {
  const finding = makeBase(raw);
  const tool = String(finding.tool || '').toLowerCase();
  const type = String(finding.type || '').toLowerCase();

  if (tool === 'gf' || type === 'gf_candidate' || type === 'gf-candidate') return normalizeGfCandidate(finding);
  if (tool === 'sqlmap') return normalizeSqlmap(finding);
  if (tool === 'dalfox') return normalizeDalfox(finding);
  if (tool === 'nuclei') return normalizeNuclei(finding);

  if (type === 'false_positive') {
    return {
      ...finding,
      type: 'false_positive',
      category: 'false_positive',
      severity: 'info',
      confidence: 'low',
      isVulnerability: false,
      confirmed: false,
      reportable: false,
      requiresManualValidation: false,
      isFalsePositiveLikely: true
    };
  }

  if (type === 'discarded' || finding.isFalsePositiveLikely) {
    return {
      ...finding,
      type: 'discarded',
      category: 'discarded',
      severity: 'info',
      confidence: 'low',
      isVulnerability: false,
      confirmed: false,
      reportable: false,
      requiresManualValidation: false,
      isFalsePositiveLikely: true
    };
  }

  if (HARDENING_TYPES.has(type) || (HARDENING_TOOLS.has(tool) && (finding.isVulnerability === true || normalizeSeverity(finding.severity) !== 'info'))) {
    return {
      ...finding,
      type: 'hardening',
      category: 'hardening',
      confidence: normalizeConfidence(finding.confidence, 'medium'),
      isVulnerability: false,
      confirmed: false,
      reportable: false,
      requiresManualValidation: false,
      isFalsePositiveLikely: false,
      falsePositiveReason: ''
    };
  }

  if (ATTACK_SURFACE_TYPES.has(type) || finding.category === 'suspicious' || finding.category === 'swagger-json') {
    return {
      ...finding,
      type: 'attack_surface',
      category: 'attack_surface',
      severity: capSeverity(finding.severity || 'low', 'low'),
      confidence: 'low',
      isVulnerability: false,
      confirmed: false,
      reportable: false,
      requiresManualValidation: false,
      isFalsePositiveLikely: false
    };
  }

  if (INFO_TYPES.has(type) || normalizeSeverity(finding.severity) === 'info' || finding.isVulnerability !== true) {
    return {
      ...finding,
      type: 'informational',
      category: 'informational',
      severity: 'info',
      confidence: 'low',
      isVulnerability: false,
      confirmed: false,
      reportable: false,
      requiresManualValidation: false,
      isFalsePositiveLikely: false
    };
  }

  if (finding.isVulnerability === true && normalizeConfidence(finding.confidence) === 'high') {
    return {
      ...finding,
      type: 'confirmed_vulnerability',
      category: 'vulnerability',
      confidence: 'high',
      confirmed: true,
      reportable: true,
      requiresManualValidation: false,
      isFalsePositiveLikely: false,
      falsePositiveReason: ''
    };
  }

  if (finding.isVulnerability === true && normalizeConfidence(finding.confidence) === 'medium') {
    return {
      ...finding,
      type: 'possible_vulnerability',
      category: 'vulnerability',
      confidence: 'medium',
      confirmed: false,
      reportable: true,
      requiresManualValidation: true,
      isFalsePositiveLikely: false,
      falsePositiveReason: ''
    };
  }

  return {
    ...finding,
    type: 'informational',
    category: 'informational',
    severity: 'info',
    confidence: 'low',
    isVulnerability: false,
    confirmed: false,
    reportable: false,
    requiresManualValidation: false,
    isFalsePositiveLikely: false
  };
}

function normalizeFindingsForReporting(findings = []) {
  return safeArray(findings).map(normalizeFindingClassification);
}

function severityDistribution(findings = []) {
  return safeArray(findings).reduce((acc, finding) => {
    const severity = normalizeSeverity(finding.severity);
    acc[severity] = (acc[severity] || 0) + 1;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 });
}

function countByTool(findings = []) {
  return safeArray(findings).reduce((acc, finding) => {
    const tool = canonicalToolName(finding.tool || 'otra');
    acc[tool] = (acc[tool] || 0) + 1;
    return acc;
  }, {});
}

function buildFindingGroups(findings = []) {
  const normalized = normalizeFindingsForReporting(findings);
  const groups = {
    confirmed: sortFindings(normalized.filter(f => f.type === 'confirmed_vulnerability')),
    possible: sortFindings(normalized.filter(f => f.type === 'possible_vulnerability')),
    gfCandidates: sortFindings(normalized.filter(f => f.type === 'gf_candidate')),
    hardening: sortFindings(normalized.filter(f => f.type === 'hardening')),
    attackSurface: sortFindings(normalized.filter(f => f.type === 'attack_surface')),
    informational: sortFindings(normalized.filter(f => f.type === 'informational')),
    discarded: sortFindings(normalized.filter(f => f.type === 'discarded')),
    falsePositives: sortFindings(normalized.filter(f => f.type === 'false_positive'))
  };

  groups.reportable = [...groups.confirmed, ...groups.possible];
  groups.severityReportable = severityDistribution(groups.reportable);
  groups.severityGlobal = severityDistribution(normalized);
  groups.severity = groups.severityReportable;

  // Alias temporales para compatibilidad con el frontend y codigo anterior.
  groups.confirmadas = groups.confirmed;
  groups.posibles = groups.possible;
  groups.gf_candidates = groups.gfCandidates;
  groups.superficie = groups.attackSurface;
  groups.surface = groups.attackSurface;
  groups.reconocimiento = groups.informational;
  groups.recon = groups.informational;
  groups.descartados = groups.discarded;
  groups.baja_confianza = groups.falsePositives;

  return groups;
}

function buildDashboardMetrics(findings = [], toolResults = {}) {
  const groups = buildFindingGroups(findings);
  const findingsByTool = countByTool(normalizeFindingsForReporting(findings));

  Object.entries(toolResults || {}).forEach(([tool, result]) => {
    const name = canonicalToolName(tool);
    const count = safeArray(result.findings).length || Number(result.parsed_count || 0);
    if (count > 0) findingsByTool[name] = Math.max(findingsByTool[name] || 0, count);
  });

  return {
    confirmedCount: groups.confirmed.length,
    possibleCount: groups.possible.length,
    gfCandidatesCount: groups.gfCandidates.length,
    hardeningCount: groups.hardening.length,
    attackSurfaceCount: groups.attackSurface.length,
    informationalCount: groups.informational.length,
    discardedCount: groups.discarded.length,
    falsePositiveCount: groups.falsePositives.length,
    reportableCount: groups.reportable.length,
    severityDistribution: {
      reportable: groups.severityReportable,
      global: groups.severityGlobal
    },
    findingsByTool
  };
}

module.exports = {
  HARDENING_TYPES,
  SEVERITY_ORDER,
  buildDashboardMetrics,
  buildFindingGroups,
  canonicalToolName,
  normalizeFindingClassification,
  normalizeFindingsForReporting,
  normalizeSeverity,
  percentage,
  safeArray,
  severityDistribution,
  sortFindings
};
