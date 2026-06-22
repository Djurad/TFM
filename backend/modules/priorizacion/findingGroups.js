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
    finding.potentialSeverity ||
    finding.potential_severity ||
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

function clampNumber(value, min, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return null;
  return Math.max(min, Math.min(max, parsed));
}

function normalizeProbabilityValue(value) {
  if (value === null || value === undefined || value === '') return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return null;
  const asUnit = parsed > 1 ? parsed / 100 : parsed;
  return clampNumber(asUnit, 0, 1);
}

function probabilityPercent(value) {
  const normalized = normalizeProbabilityValue(value);
  return normalized === null ? null : Math.round(normalized * 100);
}

function probabilityLabelFromValue(value) {
  const percent = probabilityPercent(value);
  if (percent === null) return 'no_aplica';
  if (percent >= 90) return 'muy_alta';
  if (percent >= 70) return 'alta';
  if (percent >= 40) return 'media';
  if (percent >= 15) return 'baja';
  if (percent >= 1) return 'muy_baja';
  return 'muy_baja';
}

function probabilityFindingText(finding = {}) {
  return [
    finding.title,
    finding.tool,
    finding.type,
    finding.category,
    finding.vulnerability_type,
    finding.source_status,
    finding.status,
    finding.evidence,
    finding.raw_reference,
    finding.payload,
    finding.dbms,
    finding.impact,
    finding.affected_url,
    finding.affected_asset
  ].filter(Boolean).join(' ').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

function hasConcreteSqlEvidence(finding = {}) {
  const text = probabilityFindingText(finding);
  const negated = /sin\s+(?:payload|dbms|extraccion|extraccion de datos|parametro|evidencia)|no\s+(?:identifico|confirmo|detecto).*(?:payload|dbms|extraccion|parametro)/.test(text);
  if (negated && !finding.payload && !finding.dbms) return false;
  return Boolean(
    finding.payload ||
    finding.dbms ||
    /payload|dbms|boolean-based|time-based|error-based|union query|tecnica|tecnica identificada|extraccion|dump/.test(text)
  );
}

function probabilityRangeMidpoint(min, max) {
  return (min + max) / 200;
}

function calculateBaseRealProbability(finding = {}) {
  const status = getFinalStatus(finding);
  const tool = String(finding.tool || '').toLowerCase();
  const text = probabilityFindingText(finding);
  const type = String(finding.vulnerability_type || finding.type || '').toLowerCase();

  if (['hardening', 'surface', 'informational'].includes(status)) {
    return {
      probability: null,
      label: 'no_aplica',
      reason: status === 'surface'
        ? 'Elemento de superficie descubierto; requiere revision pero no implica vulnerabilidad por si mismo.'
        : status === 'hardening'
          ? 'Hallazgo de configuracion observado; no representa por si mismo una vulnerabilidad explotable.'
          : 'Hallazgo informativo; no aplica probabilidad de vulnerabilidad explotable.',
      source: 'not_applicable'
    };
  }

  if (status === 'discarded' || finding.isFalsePositiveLikely === true) {
    return {
      probability: 0.03,
      label: 'muy_baja',
      reason: 'Hallazgo descartado o con alta probabilidad de falso positivo.',
      source: 'deterministic_rule'
    };
  }

  if (status === 'candidate' || tool === 'gf') {
    const vector = type || text;
    let probability = 0.18;
    if (/redirect/.test(vector)) probability = probabilityRangeMidpoint(10, 35);
    else if (/xss|sqli|sql/.test(vector)) probability = probabilityRangeMidpoint(10, 30);
    else if (/ssrf/.test(vector)) probability = probabilityRangeMidpoint(5, 25);
    else if (/lfi|rfi/.test(vector)) probability = probabilityRangeMidpoint(8, 25);
    else if (/rce|command/.test(vector)) probability = probabilityRangeMidpoint(5, 20);
    return {
      probability,
      label: probabilityLabelFromValue(probability),
      reason: 'GF identifica un patron de parametros, pero no confirma explotabilidad.',
      source: 'deterministic_rule'
    };
  }

  if (status === 'confirmed') {
    if (tool === 'dalfox' || /xss|triggered xss|found dom object/.test(text)) {
      return {
        probability: probabilityRangeMidpoint(90, 98),
        label: 'muy_alta',
        reason: 'XSS confirmado con payload reproducible o evidencia de ejecucion por la herramienta.',
        source: 'deterministic_rule'
      };
    }
    if (tool === 'sqlmap' || /sql injection|sqli/.test(text)) {
      return {
        probability: hasConcreteSqlEvidence(finding) ? probabilityRangeMidpoint(90, 98) : 0.85,
        label: 'muy_alta',
        reason: 'SQL Injection confirmada por herramienta con evidencia tecnica relevante.',
        source: 'deterministic_rule'
      };
    }
    if (tool === 'trufflehog' || /secret|secreto|credential|credencial|api key|token/.test(text)) {
      return {
        probability: probabilityRangeMidpoint(90, 99),
        label: 'muy_alta',
        reason: 'Secreto confirmado o verificado por la herramienta.',
        source: 'deterministic_rule'
      };
    }
    if (/rce|remote code execution|command injection/.test(text)) {
      return {
        probability: probabilityRangeMidpoint(95, 99),
        label: 'muy_alta',
        reason: 'Ejecucion remota confirmada con evidencia fuerte.',
        source: 'deterministic_rule'
      };
    }
    if (/ssrf|metadata|169\.254\.169\.254/.test(text)) {
      return {
        probability: probabilityRangeMidpoint(90, 98),
        label: 'muy_alta',
        reason: 'SSRF confirmada con acceso a objetivo sensible o evidencia reproducible.',
        source: 'deterministic_rule'
      };
    }
    if (tool === 'nuclei') {
      return {
        probability: probabilityRangeMidpoint(80, 95),
        label: 'alta',
        reason: 'Match de Nuclei con evidencia tecnica suficiente.',
        source: 'deterministic_rule'
      };
    }
    return {
      probability: 0.88,
      label: 'alta',
      reason: 'Hallazgo confirmado por herramienta con evidencia tecnica suficiente.',
      source: 'deterministic_rule'
    };
  }

  if (status === 'possible') {
    if (tool === 'sqlmap' || /possible_sqli|sql injection|sqli/.test(text)) {
      const probability = hasConcreteSqlEvidence(finding) ? 0.45 : probabilityRangeMidpoint(25, 45);
      return {
        probability,
        label: probabilityLabelFromValue(probability),
        reason: 'SQLMap indica posible SQLi, pero falta confirmacion completa de payload, DBMS o extraccion.',
        source: 'deterministic_rule'
      };
    }
    if (tool === 'dalfox' || /xss|reflection|refle/.test(text)) {
      return {
        probability: probabilityRangeMidpoint(35, 60),
        label: 'media',
        reason: 'Hay indicios de XSS o reflejo, pero no ejecucion confirmada.',
        source: 'deterministic_rule'
      };
    }
    if (tool === 'trufflehog' || /secret|secreto|credential|credencial|api key|token/.test(text)) {
      return {
        probability: probabilityRangeMidpoint(35, 65),
        label: 'media',
        reason: 'Se detecto un posible secreto no verificado.',
        source: 'deterministic_rule'
      };
    }
    if (tool === 'nuclei') {
      return {
        probability: probabilityRangeMidpoint(40, 70),
        label: 'media',
        reason: 'Match potencial de Nuclei pendiente de validacion adicional.',
        source: 'deterministic_rule'
      };
    }
    return {
      probability: probabilityRangeMidpoint(20, 50),
      label: 'media',
      reason: 'Existen indicios relevantes, pero la explotabilidad no esta confirmada.',
      source: 'deterministic_rule'
    };
  }

  return {
    probability: null,
    label: 'no_aplica',
    reason: 'No aplica probabilidad de vulnerabilidad real para este tipo de resultado.',
    source: 'not_applicable'
  };
}

function validateProbabilityDecision(finding = {}) {
  const status = getFinalStatus(finding);
  if (finding.aiEnrichmentPending === true || finding.aiStatus === 'failed') {
    return {
      probabilityBase: calculateBaseRealProbability(finding).probability,
      probabilityAISuggested: null,
      probabilityFinal: null,
      realVulnerabilityProbability: null,
      realVulnerabilityProbabilityPercent: null,
      probabilityLabel: 'pendiente_ia',
      probabilityReason: 'Pendiente de enriquecimiento individual por IA.',
      probabilitySource: 'pending_ai',
      probabilityAdjustedByAI: false,
      probabilityOverrideReason: finding.aiError || '',
      practicalRiskScore: null,
      practicalRisk: 'pending'
    };
  }
  const tool = String(finding.tool || '').toLowerCase();
  const text = probabilityFindingText(finding);
  const base = calculateBaseRealProbability(finding);
  const aiSuggested = normalizeProbabilityValue(
    finding.probabilityAISuggested ??
    finding.probability_ai_suggested ??
    finding.probabilitySuggested ??
    finding.probability_suggested
  );
  const existingFinal = normalizeProbabilityValue(finding.probabilityFinal ?? finding.realVulnerabilityProbability);
  const hasAi = aiSuggested !== null;
  let finalProbability = hasAi ? aiSuggested : (existingFinal !== null ? existingFinal : base.probability);
  let overrideReason = '';
  let source = base.source === 'not_applicable'
    ? 'not_applicable'
    : hasAi
      ? 'hybrid'
      : finding.probabilitySource === 'deterministic_fallback'
        ? 'deterministic_fallback'
        : 'deterministic_rule';

  if (['hardening', 'surface', 'informational'].includes(status)) {
    finalProbability = null;
    overrideReason = 'Probabilidad no aplicable a hardening, superficie o informacion.';
    source = 'not_applicable';
  } else if (status === 'discarded' || finding.isFalsePositiveLikely === true) {
    if (finalProbability === null || finalProbability > 0.05) {
      finalProbability = 0.05;
      overrideReason = 'Hallazgo descartado limitado a probabilidad maxima del 5%.';
    }
  } else if (status === 'candidate' || tool === 'gf') {
    const vector = String(finding.vulnerability_type || finding.pattern || text).toLowerCase();
    const maxCandidateProbability = /rce|command/.test(vector)
      ? 0.20
      : /ssrf|lfi|rfi/.test(vector)
        ? 0.25
        : /redirect/.test(vector)
          ? 0.35
          : 0.30;
    if (finalProbability === null || finalProbability > maxCandidateProbability) {
      finalProbability = Math.min(base.probability ?? 0.2, maxCandidateProbability);
      overrideReason = `Candidato GF limitado a probabilidad maxima del ${Math.round(maxCandidateProbability * 100)}% hasta validacion.`;
    }
  } else if (tool === 'sqlmap' && /possible_sqli/.test(text) && !hasConcreteSqlEvidence(finding)) {
    if (finalProbability === null || finalProbability < 0.25 || finalProbability > 0.45) {
      finalProbability = Math.max(0.25, Math.min(0.45, base.probability ?? 0.35));
      overrideReason = 'Possible SQLi sin payload, DBMS ni extraccion limitada al rango 25-45%.';
    }
  } else if (tool === 'dalfox' && status === 'confirmed') {
    if (finalProbability === null || finalProbability < 0.90 || finalProbability > 0.98) {
      finalProbability = Math.max(0.90, Math.min(0.98, base.probability ?? 0.94));
      overrideReason = 'XSS confirmado por Dalfox ajustado al rango tecnico 90-98%.';
    }
  } else if (status === 'possible' && finalProbability !== null && finalProbability > 0.7 && !hasConcreteSqlEvidence(finding)) {
    finalProbability = 0.7;
    overrideReason = 'Hallazgo posible sin prueba reproducible limitado al 70%.';
  } else if (status === 'confirmed' && finalProbability !== null && finalProbability < 0.85) {
    finalProbability = 0.85;
    overrideReason = 'Hallazgo confirmado con evidencia tecnica elevado al minimo del 85%.';
  }

  const percent = probabilityPercent(finalProbability);
  const label = probabilityLabelFromValue(finalProbability);

  return {
    probabilityBase: base.probability,
    probabilityAISuggested: aiSuggested,
    probabilityFinal: finalProbability,
    realVulnerabilityProbability: finalProbability,
    realVulnerabilityProbabilityPercent: percent,
    probabilityLabel: finalProbability === null ? 'no_aplica' : label,
    probabilityReason: finding.probabilityReason || finding.probability_reason || base.reason,
    probabilitySource: source,
    probabilityAdjustedByAI: hasAi && finalProbability !== base.probability,
    probabilityOverrideReason: overrideReason,
    practicalRiskScore: calculatePracticalRiskScore(getPotentialSeverity(finding), finalProbability, status),
    practicalRisk: practicalRiskLabel(calculatePracticalRiskScore(getPotentialSeverity(finding), finalProbability, status))
  };
}

function calculatePracticalRiskScore(severity, probability, status = 'possible') {
  const normalizedProbability = normalizeProbabilityValue(probability);
  const weights = { critical: 100, high: 75, medium: 50, low: 25, info: 5 };
  const severityWeight = weights[normalizeSeverity(severity)] ?? 5;
  if (normalizedProbability !== null) return Math.round(severityWeight * normalizedProbability);
  if (status === 'hardening') return Math.round(severityWeight * 0.35);
  if (status === 'surface') return Math.round(severityWeight * 0.20);
  return 0;
}

function practicalRiskLabel(score) {
  const value = Number(score || 0);
  if (value >= 75) return 'critical';
  if (value >= 50) return 'high';
  if (value >= 25) return 'medium';
  if (value >= 8) return 'low';
  return 'info';
}

function probabilityStats(findings = []) {
  return safeArray(findings).reduce((acc, finding) => {
    const label = finding.probabilityLabel || probabilityLabelFromValue(finding.probabilityFinal ?? finding.realVulnerabilityProbability);
    const key = {
      muy_alta: 'veryHigh',
      alta: 'high',
      media: 'medium',
      baja: 'low',
      muy_baja: 'veryLow',
      no_aplica: 'notApplicable'
    }[label] || 'notApplicable';
    acc[key] += 1;
    return acc;
  }, { veryHigh: 0, high: 0, medium: 0, low: 0, veryLow: 0, notApplicable: 0 });
}

function aiPersonalizationStats(findings = []) {
  return safeArray(findings).reduce((acc, finding) => {
    if (finding.aiEnrichmentPending === true || finding.impactSource === 'pending_ai') acc.pendingAI += 1;
    else if (['ai', 'ai_repaired', 'hybrid'].includes(finding.impactSource)) acc.aiPersonalizedImpacts += 1;
    else if (String(finding.impactSource || '').includes('template')) acc.templatePersonalizedImpacts += 1;
    else acc.genericFallbacks += 1;

    if (['ai', 'ai_repaired', 'hybrid'].includes(finding.recommendationSource)) {
      acc.aiPersonalizedRecommendations += 1;
    }
    if (finding.probabilitySource === 'deterministic_fallback') {
      acc.probabilityDeterministicFallbackCount += 1;
    }

    if (finding.aiProcessed === true || finding.probabilityAIMissing === true) {
      if (finding.probabilityAISuggested === null || finding.probabilityAISuggested === undefined) acc.probabilityAIMissingCount += 1;
      else acc.probabilityAISuggestedCount += 1;
    }
    return acc;
  }, {
    aiPersonalizedImpacts: 0,
    aiPersonalizedRecommendations: 0,
    templatePersonalizedImpacts: 0,
    genericFallbacks: 0,
    probabilityAISuggestedCount: 0,
    probabilityAIMissingCount: 0,
    probabilityDeterministicFallbackCount: 0,
    pendingAI: 0
  });
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

function impactSearchText(finding = {}) {
  return [
    finding.title,
    finding.tool,
    finding.type,
    finding.category,
    finding.vulnerability_type,
    finding.evidence,
    finding.impact,
    finding.severityReason,
    finding.aiReasoningSummary,
    finding.affected_url,
    finding.affected_asset
  ].filter(Boolean).join(' ').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

function hasDemonstratedCriticalImpact(finding = {}) {
  const text = impactSearchText(finding);
  return getFinalSeverity(finding) === 'critical' ||
    finding.sessionCompromise === true ||
    finding.session_compromise === true ||
    finding.sensitiveDataAccess === true ||
    finding.sensitive_data_access === true ||
    finding.dataExtraction === true ||
    finding.data_extraction === true ||
    /robo de sesion demostrado|extraccion.*confirmad|datos sensibles.*confirmad|acceso no autorizado demostrado/.test(text);
}

function findingEndpoint(finding = {}) {
  return finding.endpoint || finding.affected_url || finding.affectedAsset || finding.affected_asset || '';
}

function findingParameter(finding = {}) {
  const explicit = finding.parameter || finding.parametro || finding.param || finding.parameterName;
  if (explicit) return String(explicit);
  const endpoint = findingEndpoint(finding);
  try {
    return Array.from(new URL(endpoint).searchParams.keys())[0] || '';
  } catch {
    const match = String(endpoint).match(/[?&]([^=&#]+)=/);
    return match ? decodeURIComponent(match[1]) : '';
  }
}

function gfVector(finding = {}) {
  const text = impactSearchText(finding);
  const explicit = String(finding.vulnerability_type || finding.pattern || '').toLowerCase();
  if (/rce|command/.test(explicit)) return 'rce';
  if (/sqli|sql/.test(explicit)) return 'sqli';
  if (/ssrf/.test(explicit)) return 'ssrf';
  if (/lfi|rfi|traversal/.test(explicit)) return 'lfi';
  if (/redirect/.test(explicit)) return 'redirect';
  if (/xss/.test(explicit)) return 'xss';
  if (/ssrf/.test(text)) return 'ssrf';
  if (/rce|command/.test(text)) return 'rce';
  if (/lfi|rfi|traversal/.test(text)) return 'lfi';
  if (/redirect/.test(text)) return 'redirect';
  if (/sqli|sql injection/.test(text)) return 'sqli';
  return 'xss';
}

function hasXssCorrelation(finding = {}, context = {}) {
  const text = [
    ...safeArray(finding.correlation_notes),
    ...safeArray(finding.related_findings),
    ...safeArray(context.correlations).map(item => `${item.title || ''} ${item.description || ''}`)
  ].join(' ').toLowerCase();
  return /xss/.test(text);
}

function usefulAiText(value = '') {
  const text = String(value || '').trim();
  if (text.length < 45) return false;
  return !/requiere revision tecnica|puede indicar un endpoint|gf ha identificado un patron asociado|validar manualmente antes de tratarlo/i.test(text);
}

function buildPersonalizedImpact(finding = {}, context = {}) {
  const text = impactSearchText(finding);
  const status = getFinalStatus(finding);
  const severity = getFinalSeverity(finding);
  const tool = String(finding.tool || '').toLowerCase();
  const endpoint = findingEndpoint(finding);
  const parameter = findingParameter(finding);
  const parameterText = parameter ? `El parametro ${parameter}` : 'El parametro identificado';
  const endpointText = endpoint ? ` en ${endpoint}` : '';

  if (['confirmed', 'possible', 'candidate', 'hardening', 'surface', 'informational'].includes(status) && finding.aiProcessed === true && usefulAiText(finding.impact)) {
    let aiImpact = cleanImpactLanguage(finding.impact, finding);
    if (parameter && !aiImpact.toLowerCase().includes(parameter.toLowerCase())) {
      aiImpact = `${parameterText} es el punto de entrada observado. ${aiImpact}`;
    }
    return aiImpact;
  }

  if (status === 'confirmed' && /\bxss\b|dalfox/.test(text) && severity !== 'critical') {
    return `${parameterText}${endpointText} permite inyectar JavaScript en el navegador. Dalfox confirmo un payload reproducible, por lo que la explotabilidad es real. No se eleva a critica al no existir evidencia de robo de sesion, ejecucion privilegiada o acceso a datos sensibles.`;
  }

  if (status === 'possible' && (tool === 'sqlmap' || /possible_sqli|sql injection|sqli/.test(text))) {
    return `SQLMap identifico indicios compatibles con SQL Injection${endpointText}, pero no confirmo parametro vulnerable, payload, DBMS ni extraccion de datos. Si el vector se confirmara, podria permitir manipular consultas y afectar a los datos; con la evidencia actual sigue siendo una posible vulnerabilidad.`;
  }

  // Los candidatos se resuelven antes que las plantillas de hardening para
  // evitar que una URL https de Open Redirect se confunda con falta de redirect HTTPS.
  if (status === 'candidate' || tool === 'gf') {
    const vector = gfVector(finding);
    if (vector === 'sqli') return `GF detecto que ${parameterText.toLowerCase()}${endpointText} coincide con patrones de SQL Injection. Si alcanzara consultas construidas sin parametrizacion, el impacto potencial seria alto; GF no aporta payload, DBMS ni extraccion, por lo que permanece como candidato de baja probabilidad.`;
    if (vector === 'ssrf') return `GF detecto que ${parameterText.toLowerCase()}${endpointText} puede controlar un destino o URL asociado a peticiones SSRF. Si el servidor realizara la peticion sin restricciones, el impacto potencial seria alto; no existe evidencia de acceso a recursos internos, metadata o credenciales.`;
    if (vector === 'rce') return `GF detecto que ${parameterText.toLowerCase()}${endpointText} coincide con patrones asociados a ejecucion de comandos. Si alcanzara funciones de sistema o procesos externos, el impacto potencial seria critico; no existe ejecucion, salida, retardo controlado ni callback que lo confirme.`;
    if (vector === 'lfi') return `GF detecto que ${parameterText.toLowerCase()}${endpointText} puede influir en rutas o recursos. Si permitiera traversal o lectura de archivos, el impacto potencial seria alto; actualmente no hay evidencia de acceso a archivos.`;
    if (vector === 'redirect') return `GF detecto que ${parameterText.toLowerCase()}${endpointText} admite un destino externo. Si la aplicacion redirigiera sin validarlo, podria facilitar phishing o abuso de confianza; no se ha confirmado ninguna redireccion explotable.`;
    return `GF detecto entrada controlable en ${parameterText.toLowerCase()}${endpointText}, compatible con un vector XSS. Si el valor se insertara sin escape en HTML o JavaScript, el impacto potencial seria medio o alto; no hay ejecucion confirmada en navegador.`;
  }

  if (/content-security-policy|csp/.test(text)) {
    return hasXssCorrelation(finding, context)
      ? 'La ausencia de CSP reduce la capacidad del navegador para limitar scripts no autorizados y agrava el impacto potencial del XSS confirmado. Sigue siendo un hallazgo de hardening, no una vulnerabilidad confirmada independiente.'
      : 'La ausencia de CSP reduce la capacidad del navegador para limitar la ejecucion de scripts no autorizados. Por si sola es un hallazgo de hardening.';
  }

  if (/cookie/.test(text) && /samesite/.test(text)) {
    return 'La cookie de sesion no define SameSite, lo que puede aumentar la exposicion en ciertos flujos cross-site. No implica compromiso directo por si sola, pero conviene reforzar la configuracion.';
  }

  if (status === 'hardening' && (tool === 'httpsredirect' || /http sin redirect|http accesible sin redireccion|redireccion http.*https/.test(text))) {
    return 'El sitio responde por HTTP sin redirigir automaticamente a HTTPS. Esto puede exponer a usuarios a trafico no cifrado o ataques de degradacion si acceden por el canal inseguro.';
  }

  if (/tls|certificado/.test(text) && /expirar|caduca|expiry|near/.test(text)) {
    return 'El certificado TLS caduca proximamente, lo que puede provocar errores de confianza o interrupciones si no se renueva a tiempo.';
  }

  if (status === 'surface') {
    if (/swagger|openapi|api-docs/.test(text)) return `La documentacion API descubierta${endpointText} amplia la superficie visible y puede revelar operaciones, parametros o esquemas. No implica explotacion por si sola.`;
    if (/login|signin|auth/.test(text)) return `El acceso de autenticacion descubierto${endpointText} forma parte de la superficie publica y debe revisarse para confirmar controles de acceso, bloqueo y proteccion frente a abuso.`;
    if (/puerto|port|8080|8000|8443/.test(text)) return `El servicio alternativo expuesto${endpointText} amplia la superficie de ataque y puede alojar interfaces distintas a la aplicacion principal.`;
    return `El recurso descubierto${endpointText} amplia la superficie de ataque y debe revisarse para confirmar si requiere exposicion publica o restricciones adicionales.`;
  }

  if (tool === 'trufflehog' || /secret|secreto|credential|credencial|api key|token/.test(text)) {
    return status === 'confirmed'
      ? `La evidencia${endpointText} corresponde a un secreto verificado que podria permitir acceso no autorizado al servicio asociado. El valor debe rotarse sin reproducirlo en el informe.`
      : `Se detecto un posible secreto${endpointText}, pero su validez no esta confirmada. Requiere verificacion controlada antes de asumir impacto real.`;
  }

  if (tool === 'nuclei') {
    return `Nuclei detecto ${finding.title || 'un patron de seguridad'}${endpointText}. El impacto se limita a la evidencia concreta del template y debe validarse si no existe prueba reproducible adicional.`;
  }

  return '';
}

function buildPersonalizedRecommendation(finding = {}, context = {}) {
  const text = impactSearchText(finding);
  const status = getFinalStatus(finding);
  const tool = String(finding.tool || '').toLowerCase();
  const endpoint = findingEndpoint(finding);
  const parameter = findingParameter(finding);
  const parameterText = parameter ? `el parametro ${parameter}` : 'el parametro identificado';

  if (['confirmed', 'possible', 'candidate', 'hardening', 'surface', 'informational'].includes(status) && finding.aiProcessed === true && usefulAiText(finding.recommendation)) {
    return String(finding.recommendation).trim();
  }

  if (status === 'confirmed' && (/\bxss\b|dalfox/.test(text))) {
    return `Aplicar escape contextual a ${parameterText}, sanitizar la salida en el endpoint afectado y añadir pruebas de regresion con el payload observado. Reforzar CSP como defensa adicional, no como sustituto del escape.`;
  }
  if (status === 'possible' && (tool === 'sqlmap' || /possible_sqli|sql injection|sqli/.test(text))) {
    return `Validar manualmente ${parameterText}${endpoint ? ` en ${endpoint}` : ''} con pruebas controladas. Revisar que las consultas usen prepared statements, ORM seguro y validacion estricta de tipos.`;
  }
  if (/content-security-policy|csp/.test(text)) {
    return hasXssCorrelation(finding, context)
      ? 'Definir una CSP restrictiva compatible con la aplicacion, eliminar inline scripts cuando sea posible y volver a probar el XSS confirmado tras corregir el escape contextual.'
      : 'Definir una Content-Security-Policy adaptada a la aplicacion, comenzando en modo Report-Only antes de aplicarla de forma obligatoria.';
  }
  if (/cookie/.test(text) && /samesite/.test(text)) return 'Configurar SameSite=Lax o Strict segun el flujo funcional y verificar que Secure y HttpOnly se mantienen en cookies de sesion.';
  if (status === 'hardening' && (tool === 'httpsredirect' || /http sin redirect|http accesible sin redireccion|redireccion http.*https/.test(text))) return 'Configurar primero una redireccion 301/308 de HTTP a HTTPS en todo el sitio. Tras comprobar que no quedan recursos ni flujos HTTP, aplicar HSTS de forma progresiva.';
  if (/tls|certificado/.test(text) && /expirar|caduca|expiry|near/.test(text)) return 'Renovar el certificado antes de su caducidad y automatizar alertas o renovacion para evitar interrupciones.';

  if (status === 'candidate' || tool === 'gf') {
    const vector = gfVector(finding);
    if (vector === 'sqli') return `Validar manualmente ${parameterText} con pruebas controladas. Revisar que las consultas asociadas usen prepared statements, ORM seguro o validacion estricta.`;
    if (vector === 'ssrf') return `Comprobar si el servidor realiza peticiones salientes usando ${parameterText}. Restringir destinos y esquemas permitidos, y bloquear redes internas y metadata cloud.`;
    if (vector === 'rce') return `Validar con payloads inocuos si ${parameterText} llega a funciones de sistema, interpretes o procesos externos. Revisar el codigo, evitar concatenacion de comandos y aplicar listas blancas estrictas; mantenerlo como candidato hasta demostrar ejecucion.`;
    if (vector === 'lfi') return `Probar de forma controlada si ${parameterText} permite traversal. Usar mapeos internos de recursos en lugar de rutas directas proporcionadas por el usuario.`;
    if (vector === 'redirect') return `Validar si la aplicacion usa ${parameterText} como destino de redireccion. Permitir solo rutas internas o dominios autorizados mediante allowlist, normalizar el destino y rechazar esquemas externos no permitidos.`;
    return `Validar reflexion y contexto HTML/JavaScript de ${parameterText}. Aplicar escape contextual y sanitizacion en salida.`;
  }

  if (status === 'surface') {
    if (/swagger|openapi|api-docs/.test(text)) return 'Revisar si la documentacion API debe ser publica, exigir autenticacion cuando proceda y evitar publicar operaciones o esquemas internos innecesarios.';
    if (/login|signin|auth/.test(text)) return 'Revisar MFA, rate limiting, bloqueo progresivo, mensajes de error y controles frente a enumeracion de usuarios.';
    if (/puerto|port|8080|8000|8443/.test(text)) return 'Confirmar la necesidad del servicio, restringirlo por red o autenticacion y cerrarlo si no forma parte del alcance operativo.';
    return 'Confirmar la necesidad de exposicion publica y aplicar autenticacion, autorizacion o restricciones de red cuando corresponda.';
  }
  if (tool === 'trufflehog' || /secret|secreto|credential|credencial|api key|token/.test(text)) return 'Revocar y rotar el secreto, retirarlo del recurso publico, revisar accesos realizados y almacenarlo en un gestor de secretos.';
  if (tool === 'nuclei') return `Aplicar la remediacion asociada al template ${finding.templateID || finding.template_id || finding.title || ''} y repetir la prueba sobre el mismo endpoint.`;
  return String(finding.recommendation || 'Revisar la evidencia y aplicar la correccion especifica correspondiente al componente afectado.').trim();
}

function cleanImpactLanguage(value = '', finding = {}) {
  let clean = String(value || '').replace(/\s+/g, ' ').trim();
  if (!clean) return '';

  clean = clean
    .replace(/se\s+clasifica\s+con\s+esta\s+severidad\s+porque\s+la\s+(?:gravedad|criticidad|severidad)[^.,;]*?\s+se\s+debe\s+a\s+que\s+/gi, '')
    .replace(/se\s+clasifica\s+con\s+esta\s+severidad\s+porque\s+/gi, '')
    .replace(/se\s+clasifica\s+como\s+(?:critica|crítica|alta|media|baja|informativa|critical|high|medium|low|info)\s+porque\s+/gi, 'La prioridad se justifica porque ')
    .replace(/la\s+(?:criticidad|gravedad|severidad)\s+(?:critica|crítica|alta|media|baja|informativa|critical|high|medium|low|info)\s+se\s+debe\s+a\s+que\s+/gi, 'La prioridad se justifica porque ')
    .replace(/la\s+(?:criticidad|gravedad|severidad)\s+se\s+establece\s+en\s+[^.,;]*?\s+porque\s+/gi, 'La prioridad se justifica porque ')
    .replace(/\b(?:criticidad|gravedad|severidad)\s+(?:critica|crítica|alta|media|baja)\s+debido\s+a\s+que\s+/gi, 'La prioridad se justifica porque ')
    .replace(/\bdebido\s+a\s+que\s+debido\s+a\s+que\b/gi, 'debido a que')
    .replace(/\bLa prioridad se justifica porque la prioridad se justifica porque\b/gi, 'La prioridad se justifica porque')
    .replace(/\bla evidencia disponible indica que\b/gi, '')
    .replace(/\s+/g, ' ')
    .trim();

  clean = clean
    .replace(/cambio\s+de\s+(?:criticidad|severidad)\s+descartado[^.]*\.?/gi, '')
    .replace(/la\s+evidencia\s+disponible\s+indica\s+que\s+/gi, '')
    .replace(/la\s+prioridad\s+se\s+justifica\s+porque\s+/gi, '')
    .replace(/exploataci[oó]n/gi, 'explotacion')
    .replace(/\s+/g, ' ')
    .trim();

  if (!hasDemonstratedCriticalImpact(finding)) {
    clean = clean
      .replace(/\b(?:la\s+)?toma de control del sistema\b/gi, 'un impacto mayor no demostrado')
      .replace(/\bextracci[oó]n de datos sensibles\b/gi, 'exposicion potencial no demostrada')
      .replace(/\bcompromiso critico\b/gi, 'impacto elevado')
      .replace(/\bcr[ií]tico\b/gi, getFinalSeverity(finding) === 'critical' ? 'critico' : 'alto')
      .replace(/\s+/g, ' ')
      .trim();
  }

  return clean;
}

function mergeWithoutDuplication(base = '', extra = '') {
  const baseText = cleanImpactLanguage(base);
  const extraText = cleanImpactLanguage(extra);
  if (!baseText) return extraText;
  if (!extraText) return baseText;

  const baseNormalized = normalizeSentence(baseText);
  const extraNormalized = normalizeSentence(extraText);
  if (!extraNormalized || baseNormalized.includes(extraNormalized)) return baseText;
  if (!baseNormalized || extraNormalized.includes(baseNormalized)) return extraText;

  const formattedExtra = /^(el\s+riesgo|la\s+prioridad|la\s+evidencia|en\s+este\s+caso|no\s+se\s+eleva|se\s+mantiene|debe\s+tratarse|debe\s+validarse)/i.test(extraText)
    ? extraText
    : `El riesgo es relevante porque ${lowerFirst(extraText)}`;

  return cleanImpactLanguage(`${baseText.replace(/[.。]\s*$/, '')}. ${formattedExtra}`);
}

function buildImpactText(finding = {}) {
  if (finding.aiEnrichmentPending === true || finding.aiStatus === 'failed') {
    return 'Pendiente de enriquecimiento IA. El hallazgo conserva su evidencia tecnica, pero todavia no dispone de impacto final validado por IA.';
  }
  const personalized = buildPersonalizedImpact(finding, {
    correlations: finding.correlations || []
  });
  if (personalized) return cleanImpactLanguage(personalized, finding);

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

  return cleanImpactLanguage(mergeWithoutDuplication(impactBase, severityExplanation), finding) ||
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

function toolLabel(tool = '') {
  const canonical = canonicalToolName(String(tool || '').split(':')[0]);
  const labels = {
    dalfox: 'Dalfox', sqlmap: 'SQLMap', gf: 'GF', katana: 'Katana', gau: 'Gau',
    feroxbuster: 'Feroxbuster', headers: 'Headers', cookies: 'Cookies', tls: 'TLS',
    ports: 'Ports', nuclei: 'Nuclei', httpsRedirect: 'HTTP/HTTPS'
  };
  return labels[canonical] || String(canonical || 'tool');
}

function resolveFindingToolDisplay(finding = {}) {
  const explicitSources = safeArray(finding.sourceTools)
    .flatMap(value => String(value || '').split(/[\/,]/))
    .map(value => canonicalToolName(value.trim().split(':')[0]))
    .filter(Boolean);
  const primaryRaw = finding.sourceTool || finding.tool || finding.source || 'otra';
  const primary = canonicalToolName(String(primaryRaw).split(':')[0]);
  let sourceTools = Array.from(new Set(explicitSources));
  if (sourceTools.length) {
    const rawCandidates = [finding.sourceTool, finding.tool]
      .map(value => canonicalToolName(String(value || '').split(':')[0]))
      .filter(Boolean);
    sourceTools = Array.from(new Set([...sourceTools, ...rawCandidates]));
  } else {
    sourceTools = [primary];
  }
  const displayTool = String(finding.displayTool || '').trim() ||
    (sourceTools.length > 1 ? sourceTools.map(toolLabel).join('/') : toolLabel(primary));
  return { displayTool, sourceTools };
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
  if (type === 'rce') return 'critical';
  if (['sqli', 'ssrf', 'lfi', 'rfi'].includes(type)) return 'high';
  if (['redirect', 'open_redirect', 'xss'].includes(type)) return 'medium';
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
    Number(b.practicalRiskScore || 0) - Number(a.practicalRiskScore || 0) ||
    Number(b.realVulnerabilityProbabilityPercent || 0) - Number(a.realVulnerabilityProbabilityPercent || 0) ||
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
  const requestedFinalSeverity = hasExplicitFinalSeverity
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
  const potentialSeverity = potentialSeverityForFinding({
    ...finding,
    finalStatus,
    technicalStatus
  }, requestedFinalSeverity);
  const toolDisplay = resolveFindingToolDisplay(finding);

  const normalized = {
    ...publicFinding,
    displayTool: toolDisplay.displayTool,
    sourceTools: toolDisplay.sourceTools,
    type: statusType,
    category: finalStatus === 'hardening' ? 'defensive_configuration' : categoryForStatus(finalStatus),
    baseSeverity,
    aiSuggestedSeverity: aiSuggestedSeverity || finding.aiSuggestedSeverity || '',
    potentialSeverity,
    finalSeverity: potentialSeverity,
    severity: potentialSeverity,
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

  const withProbability = {
    ...normalized,
    ...validateProbabilityDecision(normalized),
    probabilitySource: finding.aiProcessed === true
      ? (String(finding.probabilitySource || '').includes('ai') ? finding.probabilitySource : 'ai_validated')
      : validateProbabilityDecision(normalized).probabilitySource
  };
  const aiPending = finding.aiEnrichmentPending === true || finding.aiStatus === 'failed';
  const impactSource = aiPending ? 'pending_ai' : finding.impactSource || (
    withProbability.aiProcessed === true && usefulAiText(withProbability.impact)
      ? 'ai'
      : 'template'
  );
  const recommendationSource = aiPending ? 'pending_ai' : finding.recommendationSource || (
    withProbability.aiProcessed === true && usefulAiText(withProbability.recommendation)
      ? 'ai'
      : 'template'
  );

  return {
    ...withProbability,
    impact: aiPending ? '' : (buildPersonalizedImpact(withProbability) || cleanImpactLanguage(withProbability.impact || withProbability.description || '', withProbability)),
    recommendation: aiPending ? '' : buildPersonalizedRecommendation(withProbability),
    impactSource,
    recommendationSource
  };
}

function normalizeGfCandidate(finding) {
  const vulnerabilityType = String(finding.vulnerability_type || finding.pattern || '').toLowerCase();
  const potentialSeverity = gfMaxSeverity(vulnerabilityType);
  return {
    ...finding,
    type: 'gf_candidate',
    category: 'candidate',
    baseSeverity: potentialSeverity,
    potentialSeverity,
    finalSeverity: potentialSeverity,
    severity: potentialSeverity,
    confidence: 'low',
    isVulnerability: false,
    confirmed: false,
    reportable: false,
    requiresManualValidation: true,
    isFalsePositiveLikely: false,
    falsePositiveReason: 'GF prioriza candidatos por patron; no confirma explotabilidad.',
    impact: buildPersonalizedImpact({ ...finding, finalStatus: 'candidate', finalSeverity: potentialSeverity }),
    recommendation: buildPersonalizedRecommendation({ ...finding, finalStatus: 'candidate', finalSeverity: potentialSeverity })
  };
}

function hasDalfoxConfirmation(finding = {}) {
  if (String(finding.tool || '').toLowerCase() !== 'dalfox') return false;
  const evidence = probabilityFindingText(finding);
  const explicitStatus = normalizeStatus(
    finding.technicalStatus || finding.technical_status || finding.finalStatus || finding.final_status || finding.status,
    ''
  );

  return explicitStatus === 'confirmed' ||
    finding.confirmed === true ||
    String(finding.dalfox_type || '').toUpperCase() === 'V' ||
    /triggered\s+xss\s+payload|found\s+dom\s+object|verified\s+xss|\btype["':\s]+v\b/.test(evidence);
}

function hasConfirmedSqlmapEvidence(finding = {}) {
  if (String(finding.tool || '').toLowerCase() !== 'sqlmap') return false;
  const status = normalizeStatus(
    finding.technicalStatus || finding.technical_status || finding.finalStatus || finding.final_status || finding.source_status || finding.status,
    ''
  );
  return status === 'confirmed' && Boolean(
    finding.vulnerable === true ||
    finding.payload ||
    finding.dbms ||
    finding.technique ||
    finding.tecnica ||
    hasConcreteSqlEvidence(finding)
  );
}

function findingVectorType(finding = {}) {
  const text = [
    finding.vulnerability_type,
    finding.vulnerabilityType,
    finding.family,
    finding.pattern,
    finding.type,
    finding.title,
    finding.tool
  ].filter(Boolean).join(' ').toLowerCase();
  if (/\brce\b|command injection|remote code execution|ejecucion de comandos/.test(text)) return 'rce';
  if (/\bsqli\b|sql injection|inyeccion sql|sqlmap/.test(text)) return 'sqli';
  if (/\bssrf\b|server.side request forgery/.test(text)) return 'ssrf';
  if (/\blfi\b|\brfi\b|file inclusion|path traversal/.test(text)) return 'lfi';
  if (/open.?redirect|redireccion abierta|\bredirect\b/.test(text)) return 'redirect';
  if (/\bxss\b|cross.site scripting|dalfox/.test(text)) return 'xss';
  return 'other';
}

function potentialSeverityForFinding(finding = {}, fallback = null) {
  const status = getFinalStatus(finding);
  const vector = findingVectorType(finding);
  const current = normalizeSeverity(
    finding.potentialSeverity ||
    finding.potential_severity ||
    fallback ||
    finding.finalSeverity ||
    finding.final_severity ||
    finding.aiSuggestedSeverity ||
    finding.baseSeverity ||
    finding.severity ||
    'info'
  );

  // Para candidatos y posibles la severidad describe el impacto si el vector
  // se confirmara. La probabilidad y el estado expresan la certeza actual.
  if (status === 'candidate') {
    if (vector === 'rce') return 'critical';
    if (['sqli', 'ssrf', 'lfi'].includes(vector)) return 'high';
    if (vector === 'redirect') return 'medium';
    if (vector === 'xss') return SEVERITY_RANK[current] >= SEVERITY_RANK.medium ? current : 'medium';
  }
  if (status === 'possible' && vector === 'sqli') {
    return SEVERITY_RANK[current] >= SEVERITY_RANK.high ? current : 'high';
  }
  return current;
}

function getPotentialSeverity(finding = {}) {
  return potentialSeverityForFinding(finding, getFinalSeverity(finding));
}

function hasVerifiedSecret(finding = {}) {
  if (String(finding.tool || '').toLowerCase() !== 'trufflehog') return false;
  const text = probabilityFindingText(finding);
  return finding.verified === true ||
    finding.verificado === true ||
    (/verified|verificado/.test(text) && /secret|secreto|credential|credencial|token|api key/.test(text));
}

function protectConfirmedTechnicalFinding(finding = {}) {
  const tool = String(finding.tool || finding.herramienta || '').toLowerCase();
  const currentSeverity = getFinalSeverity(finding);
  let minimumSeverity = null;
  let cwe = finding.cwe;

  if (hasDalfoxConfirmation(finding)) {
    minimumSeverity = 'high';
    cwe = cwe || 'CWE-79';
  } else if (hasConfirmedSqlmapEvidence(finding)) {
    minimumSeverity = 'high';
    cwe = cwe || 'CWE-89';
  } else if (hasVerifiedSecret(finding)) {
    minimumSeverity = 'high';
  } else if (
    tool === 'nuclei' &&
    normalizeStatus(
      finding.technicalStatus || finding.technical_status || finding.finalStatus || finding.final_status || finding.status,
      ''
    ) === 'confirmed' &&
    !isNucleiInformational(finding) &&
    getFinalSeverity(finding) !== 'info' &&
    finding.isVulnerability !== false
  ) {
    minimumSeverity = currentSeverity;
  }

  if (!minimumSeverity) return finding;

  const finalSeverity = SEVERITY_RANK[currentSeverity] >= SEVERITY_RANK[minimumSeverity]
    ? currentSeverity
    : minimumSeverity;

  return {
    ...finding,
    type: 'confirmed_vulnerability',
    category: 'vulnerability',
    technicalStatus: 'confirmed',
    technical_status: 'confirmed',
    finalStatus: 'confirmed',
    final_status: 'confirmed',
    status: 'confirmed',
    baseSeverity: SEVERITY_RANK[normalizeSeverity(finding.baseSeverity)] >= SEVERITY_RANK[minimumSeverity]
      ? normalizeSeverity(finding.baseSeverity)
      : minimumSeverity,
    potentialSeverity: finalSeverity,
    finalSeverity,
    severity: finalSeverity,
    confidence: 'high',
    evidenceStrength: 'strong',
    isVulnerability: true,
    confirmed: true,
    reportable: true,
    requiresManualValidation: false,
    isFalsePositiveLikely: false,
    falsePositiveReason: '',
    cwe,
    lockedStatus: true,
    lockedSeverity: true,
    lockedByTool: true,
    lockedTool: tool,
    technicalMinimumSeverity: minimumSeverity
  };
}

function protectConfirmedTechnicalFindings(findings = []) {
  return safeArray(findings).map(protectConfirmedTechnicalFinding);
}

function hasSqlmapEvidence(finding = {}) {
  const evidence = String(finding.evidence || finding.evidencia || '').trim();
  const weakEvidence = /possible_sqli, pero no identifico payload|possible_sqli, pero no identificó payload/i.test(evidence);
  return Boolean(
    finding.payload ||
    finding.dbms ||
    (/payload|dbms|extraccion|extracción|dump|diferencial|boolean-based|time-based|error-based|union query/i.test(evidence) && !weakEvidence)
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
      severity: capSeverity(finding.severity || 'low', 'high'),
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
  return finalizeNormalizedFinding(
    normalizeFindingClassificationBase(protectConfirmedTechnicalFinding(raw))
  );
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

function getReportableSeverityCounts(findings = []) {
  return severityDistribution(
    safeArray(findings).filter(finding => ['confirmed', 'possible'].includes(getFinalStatus(finding)))
  );
}

function getTechnicalSeverityCounts(findings = []) {
  return severityDistribution(
    safeArray(findings).filter(finding => getFinalStatus(finding) !== 'discarded')
  );
}

function getStatusCounts(findings = []) {
  return statusDistribution(findings);
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
  groups.severityReportable = getReportableSeverityCounts(normalized);
  groups.severityTechnical = getTechnicalSeverityCounts(normalized);
  groups.severityGlobal = groups.severityTechnical;
  groups.statusCounts = getStatusCounts(normalized);
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

function countFindingsByToolStatus(findings = [], tool = '', status = '') {
  const wantedTool = canonicalToolName(tool);
  return safeArray(findings).filter(finding =>
    canonicalToolName(finding.tool) === wantedTool &&
    (!status || getFinalStatus(finding) === status)
  ).length;
}

function logReconcile(logger, label, payload) {
  const message = typeof payload === 'string' ? `${label} ${payload}` : label;
  console.log(message, payload && typeof payload === 'object' ? payload : '');
  if (logger?.variable) logger.variable(label.replace(/[\[\]\s-]+/g, '_').replace(/^_|_$/g, ''), payload || {});
}

function reconcileFindings(findings = [], options = {}) {
  logReconcile(options.logger, '[RECONCILE-START]', { count: safeArray(findings).length });
  const normalized = normalizeFindingsForReporting(findings);
  const severityCounts = getTechnicalSeverityCounts(normalized);
  const reportableSeverityCounts = getReportableSeverityCounts(normalized);
  const statusCounts = getStatusCounts(normalized);
  const probabilityCounts = probabilityStats(normalized);
  const personalizationCounts = aiPersonalizationStats(normalized);

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
  normalized.forEach(finding => {
    if (!options.logger) return;
    const findingId = finding.id || finding.fingerprint || finding.title || 'sin-id';
    if (finding.lockedByTool === true) {
      logReconcile(options.logger, '[CONFIRMED-PROTECTION]', {
        findingId,
        tool: finding.lockedTool || finding.tool,
        lockedStatus: finding.lockedStatus === true,
        lockedSeverity: finding.lockedSeverity === true,
        finalStatus: finding.finalStatus,
        finalSeverity: finding.finalSeverity
      });
    }
    logReconcile(options.logger, '[PROBABILITY-BASE]', {
      findingId,
      base: finding.probabilityBase,
      reason: finding.probabilityReason
    });
    logReconcile(options.logger, '[PROBABILITY-AI]', {
      findingId,
      suggested: finding.probabilityAISuggested
    });
    logReconcile(options.logger, '[PROBABILITY-FINAL]', {
      findingId,
      final: finding.probabilityFinal,
      percent: finding.realVulnerabilityProbabilityPercent,
      adjusted: finding.probabilityAdjustedByAI,
      reason: finding.probabilityOverrideReason || finding.probabilityReason
    });
    logReconcile(options.logger, '[IMPACT-BUILD]', {
      findingId,
      source: finding.impactSource || 'template'
    });
    logReconcile(options.logger, '[RECOMMENDATION-BUILD]', {
      findingId,
      source: finding.recommendationSource || 'template'
    });
    logReconcile(options.logger, '[PROBABILITY-RENDER]', {
      findingId,
      percent: finding.realVulnerabilityProbabilityPercent,
      renderedOnce: true,
      duplicateHidden: true,
      labelHidden: true
    });
  });
  logReconcile(options.logger, '[PROBABILITY-STATS]', probabilityCounts);
  logReconcile(options.logger, '[AI-PERSONALIZATION-STATS]', personalizationCounts);
  logReconcile(options.logger, '[RECONCILE-END]', { count: normalized.length });

  return {
    findings: normalized,
    severityCounts,
    reportableSeverityCounts,
    probabilityStats: probabilityCounts,
    aiPersonalizationStats: personalizationCounts,
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
      technical: groups.severityTechnical,
      global: groups.severityGlobal
    },
    probabilityDistribution: probabilityStats(normalizeFindingsForReporting(findings)),
    statusDistribution: groups.statusCounts,
    findingsByTool
  };
}

module.exports = {
  HARDENING_TYPES,
  SEVERITY_ORDER,
  aiPersonalizationStats,
  buildDashboardMetrics,
  buildFindingGroups,
  buildImpactText,
  buildPersonalizedImpact,
  buildPersonalizedRecommendation,
  calculateBaseRealProbability,
  calculatePracticalRiskScore,
  cleanImpactLanguage,
  canonicalToolName,
  countFindingsByToolStatus,
  getFinalSeverity,
  getFinalStatus,
  getPotentialSeverity,
  findingVectorType,
  findingParameter,
  getReportableSeverityCounts,
  getStatusCounts,
  getTechnicalSeverityCounts,
  normalizeFindingClassification,
  normalizeFindingsForReporting,
  normalizeSeverity,
  normalizeStatus,
  percentage,
  probabilityLabelFromValue,
  probabilityPercent,
  probabilityStats,
  practicalRiskLabel,
  protectConfirmedTechnicalFinding,
  protectConfirmedTechnicalFindings,
  reconcileFindings,
  resolveFindingToolDisplay,
  safeArray,
  severityDistribution,
  statusDistribution,
  sortFindings,
  validateProbabilityDecision
};
