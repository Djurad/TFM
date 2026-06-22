const crypto = require('crypto');

const {
  buildImpactText,
  buildPersonalizedImpact,
  buildPersonalizedRecommendation,
  cleanImpactLanguage,
  getFinalSeverity,
  getFinalStatus,
  normalizeFindingsForReporting,
  safeArray
} = require('../priorizacion/findingGroups');

const DEFAULT_AI_OPTIONS = {
  mode: 'complete',
  maxFindings: 0,
  maxCorrelations: 5,
  enabledForGf: true,
  enabledForSurface: true,
  enabledForLowHardening: true
};

function parseBool(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  return ['1', 'true', 'yes', 'si', 'sí', 'on'].includes(String(value).trim().toLowerCase());
}

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function parseNonNegativeInt(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function getAiOptionsFromEnv(env = process.env) {
  return {
    mode: 'complete',
    requireAllFindings: true,
    templatesDisabled: true,
    timeoutsDisabled: true,
    maxFindings: 0,
    maxCorrelations: parsePositiveInt(env.AI_MAX_CORRELATIONS, DEFAULT_AI_OPTIONS.maxCorrelations),
    enabledForGf: parseBool(env.AI_ENABLED_FOR_GF, DEFAULT_AI_OPTIONS.enabledForGf),
    enabledForSurface: parseBool(env.AI_ENABLED_FOR_SURFACE, DEFAULT_AI_OPTIONS.enabledForSurface),
    enabledForLowHardening: parseBool(env.AI_ENABLED_FOR_LOW_HARDENING, DEFAULT_AI_OPTIONS.enabledForLowHardening)
  };
}

function normalizeEndpointPattern(value = '') {
  const raw = String(value || '').trim();
  if (!raw) return '';

  try {
    const url = new URL(raw);
    const params = Array.from(url.searchParams.keys()).sort();
    return `${url.origin}${url.pathname}${params.length ? `?${params.join('&')}` : ''}`.toLowerCase();
  } catch {
    return raw
      .replace(/([?&][^=&#]+)=([^&#]*)/g, '$1=')
      .replace(/#.*$/, '')
      .toLowerCase();
  }
}

function evidenceSummary(finding = {}) {
  return [
    finding.title,
    finding.evidence,
    finding.payload,
    finding.dbms,
    finding.parameter || finding.parametro || finding.param,
    finding.impact
  ]
    .filter(Boolean)
    .join(' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 700)
    .toLowerCase();
}

function createAiCacheKey(finding = {}) {
  const normalized = {
    type: finding.type || finding.vulnerability_type || '',
    status: getFinalStatus(finding),
    severity: getFinalSeverity(finding),
    tool: String(finding.tool || '').toLowerCase(),
    endpoint: normalizeEndpointPattern(finding.affected_url || finding.affectedAsset || finding.affected_asset || ''),
    evidence: evidenceSummary(finding)
  };

  return crypto
    .createHash('sha256')
    .update(JSON.stringify(normalized))
    .digest('hex');
}

function textOfFinding(finding = {}) {
  return [
    finding.title,
    finding.type,
    finding.vulnerability_type,
    finding.tool,
    finding.category,
    finding.evidence,
    finding.impact,
    finding.affected_url,
    finding.affected_asset,
    finding.payload
  ].filter(Boolean).join(' ').toLowerCase();
}

function isSecurityType(finding = {}) {
  return /\b(xss|sqli|sql injection|rce|ssrf|lfi|rfi|redirect|secret|secreto)\b/.test(textOfFinding(finding));
}

function isSecretFinding(finding = {}) {
  return /\b(secret|secreto|token|api key|credential|credencial|password)\b/.test(textOfFinding(finding));
}

function isSensitiveSurface(finding = {}) {
  return /\b(admin|panel|login|swagger|openapi|graphql|api|8080|8443|backup|config|debug)\b/.test(textOfFinding(finding));
}

function relatedIds(correlation = {}) {
  return new Set([
    ...safeArray(correlation.related_ids),
    ...safeArray(correlation.relatedIds),
    ...safeArray(correlation.finding_ids),
    ...safeArray(correlation.findingIds)
  ].filter(Boolean));
}

function isHardeningCorrelatedWithConfirmed(finding = {}, allFindings = [], correlations = []) {
  if (getFinalStatus(finding) !== 'hardening') return false;
  const findingId = finding.id || finding.fingerprint || '';
  if (!findingId) return false;

  const confirmedIds = new Set(
    safeArray(allFindings)
      .filter(item => getFinalStatus(item) === 'confirmed')
      .map(item => item.id || item.fingerprint)
      .filter(Boolean)
  );

  return safeArray(correlations).some(correlation => {
    const ids = relatedIds(correlation);
    return ids.has(findingId) && Array.from(ids).some(id => confirmedIds.has(id));
  });
}

function priorityForFinding(finding = {}, allFindings = [], correlations = [], options = DEFAULT_AI_OPTIONS) {
  const status = getFinalStatus(finding);
  const severity = getFinalSeverity(finding);
  const tool = String(finding.tool || '').toLowerCase();

  if (status === 'discarded') {
    return { selected: false, priority: 0, reason: 'Hallazgo descartado; no se muestra en el informe' };
  }
  if (!['confirmed', 'possible', 'candidate', 'hardening', 'surface', 'informational'].includes(status)) {
    return { selected: false, priority: 0, reason: 'Estado fuera del conjunto de hallazgos visibles' };
  }

  const severityWeight = { critical: 50, high: 40, medium: 25, low: 8, info: 0 }[severity] || 0;
  let priority = severityWeight;

  if (status === 'confirmed') priority += 100;
  else if (status === 'possible') priority += 80;
  else if (status === 'candidate' || tool === 'gf') priority += 60;
  else if (status === 'hardening' && isHardeningCorrelatedWithConfirmed(finding, allFindings, correlations)) priority += 55;
  else if (status === 'hardening') priority += 40;
  else if (status === 'surface' && isSensitiveSurface(finding)) priority += 35;
  else if (status === 'surface') priority += 20;
  else if (status === 'informational') priority += 1;

  if (isSecretFinding(finding)) priority += 60;
  if (isSecurityType(finding)) priority += 35;
  if (/\b(rce|sqli|sql injection|ssrf)\b/.test(textOfFinding(finding))) priority += 15;

  return priority > 0
    ? { selected: true, priority, reason: 'Hallazgo priorizado para valoracion IA' }
    : { selected: false, priority: 0, reason: 'Hallazgo de bajo valor para IA individual' };
}

function selectFindingsForAI(finalFindings = [], correlations = [], options = {}) {
  const mergedOptions = { ...DEFAULT_AI_OPTIONS, ...options, mode: 'complete', maxFindings: 0 };
  const startedAt = Date.now();
  const candidates = [];
  const skipped = [];
  const skipReasons = new Map();

  safeArray(finalFindings).forEach((finding, index) => {
    const decision = priorityForFinding(finding, finalFindings, correlations, mergedOptions);
    const id = finding.id || finding.fingerprint || String(index);
    if (decision.selected) {
      candidates.push({ finding, index, id, priority: decision.priority, reason: decision.reason });
    } else {
      const item = { finding, index, id, reason: decision.reason };
      skipped.push(item);
      skipReasons.set(id, decision.reason);
    }
  });

  candidates.sort((a, b) => b.priority - a.priority || a.index - b.index);
  const selected = candidates;

  return {
    selected: selected.map(item => item.finding),
    selectedMeta: selected,
    skipped,
    skipReasons,
    maxFindings: 0,
    mode: mergedOptions.mode,
    maxCorrelations: mergedOptions.maxCorrelations,
    durationMs: Date.now() - startedAt
  };
}

function selectFindingsForIndividualAI(finalFindings = [], correlations = [], options = {}) {
  return selectFindingsForAI(finalFindings, correlations, options);
}

function deterministicTextForSkippedFinding(finding = {}) {
  const status = getFinalStatus(finding);
  const tool = String(finding.tool || '').toLowerCase();
  const text = textOfFinding(finding);

  if (status === 'candidate' || tool === 'gf') {
    return {
      impact: buildPersonalizedImpact(finding) || buildImpactText(finding),
      recommendation: buildPersonalizedRecommendation(finding)
    };
  }

  if (status === 'surface') {
    return {
      impact: buildPersonalizedImpact(finding) || buildImpactText(finding),
      recommendation: buildPersonalizedRecommendation(finding)
    };
  }

  if (tool === 'cookies' || /samesite|httponly|secure|cookie/.test(text)) {
    return {
      impact: 'La configuracion de la cookie puede aumentar el riesgo en determinados flujos cross-site. No implica compromiso directo por si sola, pero conviene reforzarla.',
      recommendation: 'Configurar HttpOnly, Secure y SameSite segun el tipo de cookie y el flujo funcional.'
    };
  }

  return {
    impact: buildPersonalizedImpact(finding) || buildImpactText(finding),
    recommendation: buildPersonalizedRecommendation(finding) || finding.recommendation || 'Revisar el hallazgo y aplicar la remediacion indicada segun la evidencia disponible.'
  };
}

function applyDeterministicAiSkip(finding = {}, reason = 'No enviado a IA por priorizacion y limite de rendimiento') {
  const status = getFinalStatus(finding);
  return {
    ...finding,
    aiProcessed: false,
    aiStatus: 'failed',
    aiEnrichmentPending: true,
    aiError: reason,
    aiSkippedReason: reason,
    impact: '',
    recommendation: '',
    impactSource: 'pending_ai',
    recommendationSource: 'pending_ai',
    probabilitySource: 'pending_ai',
    probabilityFinal: null,
    realVulnerabilityProbabilityPercent: null,
    templateUsed: false,
    fallbackUsed: false,
    templateUsedFinal: false,
    genericFallbackUsedFinal: false,
    probabilityAIMissing: ['confirmed', 'possible', 'candidate'].includes(status)
  };
}

function syncFinalFindingsToToolResults(toolResults = {}, finalFindings = []) {
  const normalizedFindings = normalizeFindingsForReporting(finalFindings);

  normalizedFindings.forEach(finding => {
    const tool = finding.tool || 'otra';
    if (!toolResults[tool]) {
      toolResults[tool] = {
        status: 'success',
        parsed: [],
        findings: [],
        metrics: {}
      };
    }

    const current = normalizeFindingsForReporting(toolResults[tool].findings || []);
    const byKey = new Map(current.map(item => [
      item.id || item.fingerprint || `${item.tool}|${item.title}|${item.affected_url || item.affected_asset}`,
      item
    ]));
    const key = finding.id || finding.fingerprint || `${finding.tool}|${finding.title}|${finding.affected_url || finding.affected_asset}`;
    byKey.set(key, finding);
    toolResults[tool].findings = Array.from(byKey.values());
    toolResults[tool].metrics = {
      ...(toolResults[tool].metrics || {}),
      findings_generados: toolResults[tool].findings.length
    };
  });

  return toolResults;
}

module.exports = {
  DEFAULT_AI_OPTIONS,
  applyDeterministicAiSkip,
  createAiCacheKey,
  getAiOptionsFromEnv,
  normalizeEndpointPattern,
  selectFindingsForAI,
  selectFindingsForIndividualAI,
  syncFinalFindingsToToolResults
};
