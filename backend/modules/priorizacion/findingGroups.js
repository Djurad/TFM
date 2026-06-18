const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const STATUS_ORDER = ['confirmed', 'possible', 'candidate', 'hardening', 'surface', 'informational', 'discarded'];
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

function normalizeKey(value) {
  return String(value || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[-\s]+/g, '_')
    .trim();
}

function normalizeSeverity(value, fallback = 'info') {
  if ((value === null || value === undefined || value === '') && fallback === '') return '';
  const lower = normalizeKey(value || fallback);
  const map = {
    critical: 'critical',
    critica: 'critical',
    critico: 'critical',
    criticas: 'critical',
    criticos: 'critical',
    high: 'high',
    alta: 'high',
    alto: 'high',
    altas: 'high',
    altos: 'high',
    medium: 'medium',
    media: 'medium',
    medio: 'medium',
    medias: 'medium',
    medios: 'medium',
    low: 'low',
    baja: 'low',
    bajo: 'low',
    bajas: 'low',
    bajos: 'low',
    informational: 'info',
    informativo: 'info',
    informativa: 'info',
    info: 'info'
  };
  const normalized = map[lower] || lower;
  if (SEVERITY_ORDER.includes(normalized)) return normalized;
  if (fallback && fallback !== value) return normalizeSeverity(fallback, 'info');
  return 'info';
}

function normalizeStatus(value, fallback = '') {
  const lower = normalizeKey(value || fallback);
  const map = {
    confirmed: 'confirmed',
    confirmada: 'confirmed',
    confirmado: 'confirmed',
    verified: 'confirmed',
    vulnerable: 'confirmed',
    exploitable: 'confirmed',
    confirmed_sqli: 'confirmed',
    confirmed_vulnerability: 'confirmed',
    possible: 'possible',
    posible: 'possible',
    suspicious: 'possible',
    possible_sqli: 'possible',
    possible_vulnerability: 'possible',
    requires_manual_validation: 'possible',
    candidate: 'candidate',
    candidato: 'candidate',
    candidata: 'candidate',
    gf: 'candidate',
    gf_candidate: 'candidate',
    hardening: 'hardening',
    defensive_configuration: 'hardening',
    configuracion: 'hardening',
    surface: 'surface',
    superficie: 'surface',
    attack_surface: 'surface',
    exposed_port: 'surface',
    info: 'informational',
    informational: 'informational',
    informativo: 'informational',
    informativa: 'informational',
    reconocimiento: 'informational',
    discarded: 'discarded',
    descartado: 'discarded',
    descartada: 'discarded',
    false_positive: 'discarded'
  };
  const normalized = map[lower] || lower;
  if (STATUS_ORDER.includes(normalized)) return normalized;
  if (fallback && fallback !== value) return normalizeStatus(fallback, '');
  return '';
}

function inferStatusFromFinding(finding = {}) {
  const type = normalizeKey(finding.type || finding.tipo);
  const category = normalizeKey(finding.category || finding.categoria);
  const tool = normalizeKey(finding.tool || finding.herramienta);

  if (type === 'confirmed_vulnerability') return 'confirmed';
  if (type === 'possible_vulnerability') return 'possible';
  if (type === 'gf_candidate' || category === 'candidate' || tool === 'gf') return 'candidate';
  if (type === 'hardening' || category === 'hardening' || HARDENING_TYPES.has(type) || HARDENING_TOOLS.has(tool)) return 'hardening';
  if (type === 'attack_surface' || type === 'surface' || category === 'attack_surface' || ATTACK_SURFACE_TYPES.has(type)) return 'surface';
  if (type === 'discarded' || type === 'false_positive' || category === 'discarded' || category === 'false_positive') return 'discarded';
  if (INFO_TYPES.has(type) || type === 'informational' || type === 'reconocimiento' || category === 'informational') return 'informational';
  if (finding.isVulnerability === true && normalizeConfidence(finding.confidence) === 'high') return 'confirmed';
  if (finding.isVulnerability === true) return 'possible';
  return 'informational';
}

function getFinalStatus(finding = {}) {
  const explicit = normalizeStatus(
    finding.finalStatus ||
    finding.final_status ||
    finding.technicalStatus ||
    finding.technical_status ||
    finding.status ||
    finding.estado,
    ''
  );

  return explicit || inferStatusFromFinding(finding);
}

function getFinalSeverity(finding = {}) {
  return normalizeSeverity(
    finding.finalSeverity ||
    finding.final_severity ||
    finding.aiSuggestedSeverity ||
    finding.ai_suggested_severity ||
    finding.baseSeverity ||
    finding.base_severity ||
    finding.severity ||
    finding.severidad ||
    finding.criticidad ||
    'info'
  );
}

function normalizeSentence(value = '') {
  return normalizeKey(value)
    .replace(/[^a-z0-9]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function lowerFirst(value = '') {
  const clean = String(value || '').trim();
  return clean ? clean.charAt(0).toLowerCase() + clean.slice(1) : clean;
}

function mergeWithoutDuplication(base = '', extra = '') {
  const baseText = String(base || '').trim();
  const extraText = String(extra || '').trim();
  if (!baseText) return extraText;
  if (!extraText) return baseText;

  const baseNormalized = normalizeSentence(baseText);
  const extraNormalized = normalizeSentence(extraText);
  if (!extraNormalized || baseNormalized.includes(extraNormalized)) return baseText;
  if (!baseNormalized || extraNormalized.includes(baseNormalized)) return extraText;

  const formattedExtra = /^(se\s+clasifica|la\s+criticidad|la\s+severidad|severidad|criticidad|porque|debido)/i.test(extraText)
    ? extraText
    : `Se clasifica con esta severidad porque ${lowerFirst(extraText)}`;

  return `${baseText.replace(/[.。]\s*$/, '')}. ${formattedExtra}`;
}

function buildImpactText(finding = {}) {
  const impactBase = finding.impact ||
    finding.technicalImpact ||
    finding.technical_impact ||
    finding.businessImpact ||
    finding.business_impact ||
    '';
  const severityExplanation = finding.severityReason ||
    finding.severity_reason ||
    finding.classificationReason ||
    finding.classification_reason ||
    finding.severityChangeReason ||
    finding.severity_change_reason ||
    finding.aiReasoningSummary ||
    finding.ai_reasoning_summary ||
    '';

  return mergeWithoutDuplication(impactBase, severityExplanation) ||
    'No disponible. Requiere revision tecnica segun el contexto del activo.';
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
    getFinalSeverity(finding) === 'info';
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
    SEVERITY_RANK[getFinalSeverity(b)] - SEVERITY_RANK[getFinalSeverity(a)] ||
    canonicalToolName(a.tool).localeCompare(canonicalToolName(b.tool)) ||
    String(a.title || '').localeCompare(String(b.title || ''))
  ));
}

function makeBase(raw = {}) {
  const tool = canonicalToolName(raw.tool || raw.herramienta || 'otra');
  const type = String(raw.type || raw.tipo || 'informational').toLowerCase().replace(/-/g, '_');

  return {
    ...raw,
    _hasExplicitFinalSeverity: Boolean(raw.finalSeverity || raw.final_severity),
    _hasExplicitAiSuggestedSeverity: Boolean(raw.aiSuggestedSeverity || raw.ai_suggested_severity || raw.suggestedSeverity || raw.suggested_severity),
    _hasExplicitFinalStatus: Boolean(raw.finalStatus || raw.final_status || raw.technicalStatus || raw.technical_status || raw.status || raw.estado),
    tool,
    type,
    baseSeverity: normalizeSeverity(raw.baseSeverity || raw.base_severity || raw.severity || raw.severidad || raw.criticidad),
    aiSuggestedSeverity: normalizeSeverity(raw.aiSuggestedSeverity || raw.ai_suggested_severity || raw.suggestedSeverity || raw.suggested_severity || '', ''),
    finalSeverity: getFinalSeverity(raw),
    severity: getFinalSeverity(raw),
    technicalStatus: normalizeStatus(raw.technicalStatus || raw.technical_status || raw.status || ''),
    finalStatus: getFinalStatus(raw),
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

function typeForStatus(status, finding = {}) {
  const current = normalizeKey(finding.type);
  if (current === 'false_positive') return 'false_positive';
  if (status === 'confirmed') return 'confirmed_vulnerability';
  if (status === 'possible') return 'possible_vulnerability';
  if (status === 'candidate') return 'gf_candidate';
  if (status === 'hardening') return 'hardening';
  if (status === 'surface') return 'attack_surface';
  if (status === 'discarded') return 'discarded';
  return 'informational';
}

function categoryForStatus(status) {
  return {
    confirmed: 'vulnerability',
    possible: 'vulnerability',
    candidate: 'candidate',
    hardening: 'hardening',
    surface: 'attack_surface',
    informational: 'informational',
    discarded: 'discarded'
  }[status] || 'informational';
}

function finalizeNormalizedFinding(finding = {}) {
  const {
    _hasExplicitFinalSeverity: hasExplicitFinalSeverity,
    _hasExplicitAiSuggestedSeverity: hasExplicitAiSuggestedSeverity,
    _hasExplicitFinalStatus: hasExplicitFinalStatus,
    ...publicFinding
  } = finding;
  const baseSeverity = normalizeSeverity(finding.baseSeverity || finding.base_severity || finding.severity || finding.severidad || finding.criticidad);
  const aiSuggestedRaw = hasExplicitAiSuggestedSeverity
    ? (finding.aiSuggestedSeverity || finding.ai_suggested_severity || finding.suggestedSeverity || finding.suggested_severity)
    : '';
  const aiSuggestedSeverity = aiSuggestedRaw ? normalizeSeverity(aiSuggestedRaw) : '';
  const finalSeverity = hasExplicitFinalSeverity
    ? normalizeSeverity(finding.finalSeverity || finding.final_severity)
    : (aiSuggestedSeverity || normalizeSeverity(finding.severity || baseSeverity));
  const explicitStatus = hasExplicitFinalStatus
    ? normalizeStatus(finding.finalStatus || finding.final_status || finding.technicalStatus || finding.technical_status || finding.status || finding.estado, '')
    : '';
  const finalStatus = explicitStatus || inferStatusFromFinding(finding);
  const technicalStatus = (hasExplicitFinalStatus
    ? normalizeStatus(finding.technicalStatus || finding.technical_status || finding.status || finding.estado, '')
    : '') || finalStatus;
  const isReportableVulnerability = ['confirmed', 'possible'].includes(finalStatus);
  const statusType = typeForStatus(finalStatus, finding);

  return {
    ...publicFinding,
    type: statusType,
    category: categoryForStatus(finalStatus),
    baseSeverity,
    aiSuggestedSeverity: aiSuggestedSeverity || finding.aiSuggestedSeverity || '',
    finalSeverity,
    severity: finalSeverity,
    technicalStatus,
    finalStatus,
    status: finalStatus,
    confirmed: finalStatus === 'confirmed',
    isVulnerability: isReportableVulnerability,
    reportable: isReportableVulnerability,
    requiresManualValidation: finalStatus === 'possible' || finalStatus === 'candidate' || finding.requiresManualValidation === true,
    isFalsePositiveLikely: finalStatus === 'discarded' || finding.isFalsePositiveLikely === true,
    impact: finding.impact || '',
    recommendation: finding.recommendation || ''
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
    falsePositiveReason: 'GF prioriza candidatos por patron; no confirma explotabilidad.',
    impact: 'Este candidato requiere validacion manual. GF solo indica que el patron de parametros coincide con vectores habituales. No se ha confirmado explotabilidad.',
    recommendation: 'Validar manualmente antes de tratarlo como vulnerabilidad. Confirmar con pruebas especificas o herramientas como Dalfox, SQLMap o Nuclei segun el vector.'
  };
}

function hasSqlmapEvidence(finding = {}) {
  const evidence = String(finding.evidence || finding.evidencia || '').trim();
  const weakEvidence = /possible_sqli, pero no identifico payload|possible_sqli, pero no identificó payload/i.test(evidence);
  return Boolean(
    finding.payload ||
    finding.parametro ||
    finding.parameter ||
    finding.param ||
    finding.dbms ||
    (evidence && !weakEvidence)
  );
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
    const strongEvidence = hasSqlmapEvidence(finding);
    const weakEvidenceMessage = 'SQLMap devolvio estado possible_sqli, pero no identifico payload, parametro vulnerable, DBMS ni evidencia detallada.';

    return {
      ...finding,
      type: 'possible_vulnerability',
      category: 'vulnerability',
      title: strongEvidence
        ? (finding.title || 'Posible SQL Injection detectada por SQLMap')
        : 'Posible SQL Injection no concluyente detectada por SQLMap',
      severity: strongEvidence ? 'high' : 'medium',
      confidence: strongEvidence ? 'medium' : 'low',
      isVulnerability: true,
      confirmed: false,
      reportable: true,
      requiresManualValidation: true,
      isFalsePositiveLikely: false,
      falsePositiveReason: '',
      source_status: sourceStatus,
      status: 'requires_manual_validation',
      evidence: strongEvidence ? finding.evidence : weakEvidenceMessage,
      impact: strongEvidence
        ? finding.impact
        : 'El resultado no es concluyente. Puede indicar un comportamiento que requiere revision, pero no hay evidencia suficiente para afirmar explotabilidad.',
      recommendation: strongEvidence
        ? finding.recommendation
        : 'Validar manualmente el endpoint y sus parametros. Revisar consultas parametrizadas/ORM seguro si se confirma inyeccion SQL.'
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

function normalizeFindingClassificationBase(raw = {}) {
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

  if (HARDENING_TYPES.has(type) || (HARDENING_TOOLS.has(tool) && (finding.isVulnerability === true || getFinalSeverity(finding) !== 'info'))) {
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

  if (INFO_TYPES.has(type) || getFinalSeverity(finding) === 'info' || finding.isVulnerability !== true) {
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

function normalizeFindingClassification(raw = {}) {
  return finalizeNormalizedFinding(normalizeFindingClassificationBase(raw));
}

function normalizeFindingsForReporting(findings = []) {
  return safeArray(findings).map(normalizeFindingClassification);
}

function severityDistribution(findings = []) {
  return safeArray(findings).reduce((acc, finding) => {
    const severity = getFinalSeverity(finding);
    acc[severity] = (acc[severity] || 0) + 1;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 });
}

function statusDistribution(findings = []) {
  return safeArray(findings).reduce((acc, finding) => {
    const status = getFinalStatus(finding);
    acc[status] = (acc[status] || 0) + 1;
    return acc;
  }, {
    confirmed: 0,
    possible: 0,
    candidate: 0,
    hardening: 0,
    surface: 0,
    informational: 0,
    discarded: 0
  });
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
    confirmed: sortFindings(normalized.filter(f => getFinalStatus(f) === 'confirmed')),
    possible: sortFindings(normalized.filter(f => getFinalStatus(f) === 'possible')),
    gfCandidates: sortFindings(normalized.filter(f => getFinalStatus(f) === 'candidate')),
    hardening: sortFindings(normalized.filter(f => getFinalStatus(f) === 'hardening')),
    attackSurface: sortFindings(normalized.filter(f => getFinalStatus(f) === 'surface')),
    informational: sortFindings(normalized.filter(f => getFinalStatus(f) === 'informational')),
    discarded: sortFindings(normalized.filter(f => getFinalStatus(f) === 'discarded')),
    falsePositives: sortFindings(normalized.filter(f => f.type === 'false_positive' || f.isFalsePositiveLikely === true))
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

function logReconcile(logger, label, payload) {
  const message = typeof payload === 'string' ? `${label} ${payload}` : label;
  console.log(message, payload && typeof payload === 'object' ? payload : '');
  if (logger?.variable) logger.variable(label.replace(/[\[\]\s-]+/g, '_').replace(/^_|_$/g, ''), payload || {});
}

function reconcileFindings(findings = [], options = {}) {
  logReconcile(options.logger, '[RECONCILE-START]', { count: safeArray(findings).length });
  const normalized = normalizeFindingsForReporting(findings);
  const severityCounts = severityDistribution(normalized);
  const statusCounts = statusDistribution(normalized);

  normalized.forEach(finding => {
    const legacySeverity = normalizeSeverity(finding.criticidad || finding.severidad || '', '');
    if (legacySeverity && legacySeverity !== finding.finalSeverity) {
      logReconcile(options.logger, '[RECONCILE-WARNING]', {
        findingId: finding.id || finding.title || 'sin-id',
        reason: 'legacy severity differs from finalSeverity',
        legacySeverity,
        finalSeverity: finding.finalSeverity
      });
    }
  });

  logReconcile(
    options.logger,
    '[RECONCILE-SEVERITY-COUNTS]',
    `critical=${severityCounts.critical} high=${severityCounts.high} medium=${severityCounts.medium} low=${severityCounts.low} info=${severityCounts.info}`
  );
  logReconcile(
    options.logger,
    '[RECONCILE-STATUS-COUNTS]',
    `confirmed=${statusCounts.confirmed} possible=${statusCounts.possible} candidate=${statusCounts.candidate} hardening=${statusCounts.hardening} surface=${statusCounts.surface} informational=${statusCounts.informational} discarded=${statusCounts.discarded}`
  );
  logReconcile(options.logger, '[RECONCILE-END]', { count: normalized.length });

  return {
    findings: normalized,
    severityCounts,
    statusCounts,
    groups: buildFindingGroups(normalized)
  };
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
  buildImpactText,
  canonicalToolName,
  getFinalSeverity,
  getFinalStatus,
  normalizeFindingClassification,
  normalizeFindingsForReporting,
  normalizeSeverity,
  normalizeStatus,
  percentage,
  reconcileFindings,
  safeArray,
  severityDistribution,
  statusDistribution,
  sortFindings
};
