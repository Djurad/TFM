const {
  createIndividualAiFallback,
  enrichSingleFindingWithAI,
  generarJsonIA,
  validateAITextLanguage
} = require('./ia');
const { parsearJsonIAFlexible } = require('../procesamiento/normalizacion');
const {
  getFinalSeverity,
  getFinalStatus,
  normalizeFindingsForReporting,
  safeArray
} = require('../priorizacion/findingGroups');
const { calculateGlobalRiskScore, getCriticalEvidenceDetails } = require('../priorizacion/scoring');

const REPORTABLE_AI_STATUSES = new Set([
  'confirmed',
  'possible',
  'candidate',
  'hardening',
  'surface',
  'informational'
]);

function log(scanLogger, label, payload = {}) {
  const inline = Object.entries(payload).map(([key, value]) => `${key}=${value}`).join(' ');
  console.log(`${label}${inline ? ` ${inline}` : ''}`);
  if (scanLogger?.variable) {
    scanLogger.variable(label.replace(/[\[\]-]+/g, '').replace(/\s+/g, '_').toLowerCase(), payload);
  }
}

function isReportableForAI(finding = {}) {
  return REPORTABLE_AI_STATUSES.has(getFinalStatus(finding)) &&
    finding.internalDuplicate !== true &&
    finding.noise !== true &&
    finding.assetDiscarded !== true;
}

function runtimeId(finding = {}, index = 0) {
  return finding.id || finding.fingerprint || `${finding.tool || 'tool'}-${getFinalStatus(finding) || 'finding'}-${index + 1}`;
}

function validateAIEnrichmentCoverage(finalFindings = []) {
  const reportable = safeArray(finalFindings).filter(isReportableForAI);
  const failures = [];
  let aiProcessed = 0;
  let aiPersonalizedImpacts = 0;
  let aiPersonalizedRecommendations = 0;
  let templateUsedFinal = 0;
  let genericFallbacksFinal = 0;

  reportable.forEach((finding, index) => {
    const missing = [];
    const validImpactSource = ['ai', 'ai_repaired'].includes(finding.impactSource);
    const validRecommendationSource = ['ai', 'ai_repaired'].includes(finding.recommendationSource);
    if (finding.aiProcessed !== true) missing.push('aiProcessed');
    if (!validImpactSource) missing.push('impactSource');
    if (!validRecommendationSource) missing.push('recommendationSource');
    if (finding.templateUsed === true || String(finding.impactSource || '').includes('template') || String(finding.recommendationSource || '').includes('template')) missing.push('templateUsed');
    if (finding.fallbackUsed === true || String(finding.impactSource || '').includes('fallback') || String(finding.recommendationSource || '').includes('fallback')) missing.push('fallbackUsed');
    if (!String(finding.impact || '').trim()) missing.push('impact');
    if (!String(finding.recommendation || '').trim()) missing.push('recommendation');

    if (finding.aiProcessed === true) aiProcessed += 1;
    if (finding.aiProcessed === true && validImpactSource) aiPersonalizedImpacts += 1;
    if (finding.aiProcessed === true && validRecommendationSource) aiPersonalizedRecommendations += 1;
    if (finding.templateUsed === true || String(finding.impactSource || '').includes('template') || String(finding.recommendationSource || '').includes('template')) templateUsedFinal += 1;
    if (finding.fallbackUsed === true || String(finding.impactSource || '').includes('fallback') || String(finding.recommendationSource || '').includes('fallback')) genericFallbacksFinal += 1;
    if (missing.length) failures.push({ findingId: runtimeId(finding, index), missing, error: finding.aiError || null });
  });

  const totalReportableFindings = reportable.length;
  const complete = failures.length === 0 && aiProcessed === totalReportableFindings;
  return {
    complete,
    status: complete ? 'success' : 'partial',
    totalReportableFindings,
    aiProcessed,
    aiFailed: failures.length,
    aiPersonalizedImpacts,
    aiPersonalizedRecommendations,
    templateUsedFinal,
    genericFallbacksFinal,
    coveragePercent: totalReportableFindings ? Math.round((aiProcessed / totalReportableFindings) * 100) : 100,
    failures
  };
}

function statusCounts(findings = []) {
  return safeArray(findings).filter(isReportableForAI).reduce((acc, finding) => {
    const status = getFinalStatus(finding);
    const key = {
      confirmed: 'confirmed', possible: 'possible', candidate: 'gfCandidates',
      hardening: 'hardening', surface: 'surface', informational: 'informational'
    }[status];
    if (key) acc[key] += 1;
    return acc;
  }, { confirmed: 0, possible: 0, gfCandidates: 0, hardening: 0, surface: 0, informational: 0 });
}

async function enrichAllReportableFindingsWithAI(finalFindings = [], context = {}) {
  const startedAt = Date.now();
  const scanLogger = context.scanLogger || null;
  const enviar = typeof context.enviar === 'function' ? context.enviar : null;
  const enrichFinding = context.enrichFinding || enrichSingleFindingWithAI;
  const normalizedInput = normalizeFindingsForReporting(finalFindings);
  const counts = statusCounts(normalizedInput);
  const reportableIndices = normalizedInput.map((finding, index) => isReportableForAI(finding) ? index : -1).filter(index => index >= 0);
  const total = reportableIndices.length;

  log(scanLogger, '[AI-COVERAGE-PLAN]', {
    totalReportableFindings: total,
    ...counts,
    mode: 'complete',
    templatesDisabled: true,
    timeoutsDisabled: true
  });
  if (enviar) enviar({ type: 'progress', tool: 'analisis ia', status: total ? 'running' : 'success', message: `IA completa: ${total} hallazgos reportables planificados` });

  const enriched = normalizedInput.slice();
  let callsMade = 0;
  let ordinal = 0;
  for (const index of reportableIndices) {
    ordinal += 1;
    const finding = { ...enriched[index], id: runtimeId(enriched[index], index) };
    const findingId = finding.id;
    log(scanLogger, '[AI-FINDING-START]', {
      index: ordinal,
      total,
      findingId,
      tool: finding.tool || 'otra',
      status: getFinalStatus(finding),
      family: finding.family || finding.vulnerability_type || finding.type || '-',
      endpoint: finding.endpoint || finding.affected_url || finding.affected_asset || '-'
    });
    callsMade += 1;
    try {
      const aiFinding = await enrichFinding(finding, {
        target: context.target || '',
        tool: finding.tool || 'otra',
        correlations: safeArray(context.correlations),
        scanLogger,
        index: ordinal,
        total
      });
      enriched[index] = normalizeFindingsForReporting([{ ...finding, ...aiFinding, id: findingId }])[0];
    } catch (error) {
      enriched[index] = normalizeFindingsForReporting([createIndividualAiFallback(finding, error)])[0];
    }
  }

  const findings = normalizeFindingsForReporting(enriched);
  const coverage = validateAIEnrichmentCoverage(findings);
  const stats = {
    mode: 'complete',
    requireAllFindings: true,
    templatesDisabled: true,
    timeoutsDisabled: true,
    maxFindings: 0,
    selected: total,
    selectedForAI: total,
    skipped: 0,
    callsSkipped: 0,
    callsMade,
    aiCallsMade: callsMade,
    ...coverage,
    aiFallback: 0,
    templatePersonalizedImpacts: 0,
    genericFallbacks: 0,
    durationMs: Date.now() - startedAt,
    selectionDurationMs: 0
  };
  log(scanLogger, '[AI-COVERAGE-STATS]', {
    totalReportableFindings: coverage.totalReportableFindings,
    aiCallsMade: callsMade,
    aiProcessed: coverage.aiProcessed,
    aiFailed: coverage.aiFailed,
    aiPersonalizedImpacts: coverage.aiPersonalizedImpacts,
    aiPersonalizedRecommendations: coverage.aiPersonalizedRecommendations,
    templateUsedFinal: coverage.templateUsedFinal,
    genericFallbacksFinal: coverage.genericFallbacksFinal,
    coveragePercent: coverage.coveragePercent
  });
  if (scanLogger?.variable) scanLogger.variable('ai.stats', stats);
  if (enviar) {
    enviar({
      type: 'progress',
      tool: 'analisis ia',
      status: coverage.complete ? 'success' : 'partial',
      message: coverage.complete
        ? `[SUCCESS] analisis ia - ${coverage.aiProcessed}/${coverage.totalReportableFindings} hallazgos enriquecidos por IA, templates finales usados: ${coverage.templateUsedFinal}`
        : `[PARTIAL] analisis ia - ${coverage.aiProcessed}/${coverage.totalReportableFindings} hallazgos enriquecidos por IA, ${coverage.aiFailed} pendientes, templates finales usados: ${coverage.templateUsedFinal}`
    });
  }
  return { findings, stats, coverage };
}

function finalRiskLevel(score) {
  if (score === null || score === undefined) return { ai: 'info', public: 'N/D', grade: 'N/D' };
  if (score >= 90) return { ai: 'critical', public: 'critico', grade: 'E' };
  if (score >= 70) return { ai: 'high', public: 'alto', grade: 'D' };
  if (score >= 50) return { ai: 'medium', public: 'medio', grade: 'C' };
  if (score >= 25) return { ai: 'low', public: 'bajo', grade: 'B' };
  return { ai: 'info', public: 'informativo', grade: 'A' };
}

function summarizeFindingForGlobalAI(finding = {}) {
  return {
    id: finding.id || finding.fingerprint,
    tool: finding.displayTool || finding.sourceTool || finding.tool || finding.source,
    family: finding.family || finding.vulnerability_type || finding.type,
    status: getFinalStatus(finding),
    severity: finding.potentialSeverity || getFinalSeverity(finding),
    probability: finding.realVulnerabilityProbabilityPercent,
    confidence: finding.confidence,
    impactSummary: String(finding.impact || '').replace(/\s+/g, ' ').trim().slice(0, 260),
    endpoint: finding.endpoint || finding.affected_url || finding.affected_asset,
  };
}

function buildFinalRiskPrompt(enrichedFindings = [], context = {}) {
  const schema = {
    score: 0,
    riskLevel: 'critical|high|medium|low|info',
    reason: '',
    mainDrivers: [],
    whyNotHigher: '',
    whyNotLower: ''
  };
  return `Evalua el riesgo global de este analisis web.

Devuelve SOLO JSON valido, sin markdown:
${JSON.stringify(schema)}

IDIOMA OBLIGATORIO:
- Redacta reason, mainDrivers, whyNotHigher y whyNotLower exclusivamente en espanol.
- No uses frases visibles en ingles.

Reglas:
- score debe estar entre 0 y 100.
- Pondera confirmed mas que possible y possible mas que candidate.
- Hardening y surface no son vulnerabilidades confirmadas.
- Un candidate critical con probabilidad baja no convierte por si solo el sitio en critical.
- Riesgo global critical solo si existe evidencia critica confirmada.
- Con XSS confirmed high + SQLi possible + GF critical candidate de probabilidad baja, suele ser high 70-85.

Hallazgos:
${JSON.stringify(enrichedFindings.map(summarizeFindingForGlobalAI))}`;
}

function validateAIFinalScore(aiScore = {}, enrichedFindings = [], context = {}) {
  const raw = typeof aiScore === 'number' ? aiScore : (aiScore.score ?? aiScore.finalScore100);
  let score = Math.round(Math.max(0, Math.min(100, Number(raw))));
  if (!Number.isFinite(score)) return { ok: false, requiresRetry: true, error: 'finalScore100 no es numerico' };
  const findings = safeArray(enrichedFindings);
  const confirmedCritical = findings.some(f => getFinalStatus(f) === 'confirmed' && getFinalSeverity(f) === 'critical');
  const confirmedHigh = findings.some(f => getFinalStatus(f) === 'confirmed' && getFinalSeverity(f) === 'high');
  const confirmedXssHigh = findings.some(f => getFinalStatus(f) === 'confirmed' && getFinalSeverity(f) === 'high' && /xss|dalfox/i.test(`${f.title || ''} ${f.tool || ''} ${f.family || ''}`));
  const possibleHigh = findings.some(f => getFinalStatus(f) === 'possible' && ['high', 'critical'].includes(getFinalSeverity(f)));
  const criticalCandidate = findings.some(f => getFinalStatus(f) === 'candidate' && getFinalSeverity(f) === 'critical');
  const onlyCandidatesWithoutConfirmed = !findings.some(f => ['confirmed', 'possible'].includes(getFinalStatus(f))) && findings.some(f => getFinalStatus(f) === 'candidate');
  const reasons = [];
  const originalScore = score;

  if (!confirmedCritical && score > 89) { score = 89; reasons.push('Sin vulnerabilidad critica confirmada, el score global se limita a 89.'); }
  if (onlyCandidatesWithoutConfirmed && score > 65) { score = 65; reasons.push('Solo hay candidatos sin vulnerabilidades confirmadas o posibles; cap 65.'); }
  if (confirmedHigh && score < 60) { score = 60; reasons.push('Existe una vulnerabilidad high confirmada; floor 60.'); }
  if (confirmedXssHigh && score < 65) { score = 65; reasons.push('XSS high confirmado; floor 65.'); }
  if (confirmedXssHigh && possibleHigh && criticalCandidate) {
    if (score < 70) { score = 70; reasons.push('Combinacion XSS confirmado + possible high + candidato critical; floor 70.'); }
    if (score > 85) { score = 85; reasons.push('La evidencia critica es candidata, no confirmada; cap contextual 85.'); }
  }

  const level = finalRiskLevel(score);
  const aiOriginalRiskLevel = String(aiScore.riskLevel || '').trim().toLowerCase();
  if (aiOriginalRiskLevel && aiOriginalRiskLevel !== level.ai) {
    reasons.push(`riskLevel IA ${aiOriginalRiskLevel} corregido a ${level.ai} para mantener coherencia con score ${score}.`);
  }
  return {
    ok: true,
    requiresRetry: originalScore !== score,
    originalScore,
    aiOriginalRiskLevel,
    finalScore100: score,
    riskLevel: level.ai,
    publicRiskLevel: level.public,
    riskGrade: level.grade,
    overrideReason: reasons.join(' '),
    corrected: reasons.length > 0,
    hasConfirmedCritical: confirmedCritical,
    deterministicScoreBeforeAI: context.deterministicScoreBeforeAI ?? null
  };
}

async function computeFinalRiskScoreWithAI(enrichedFindings = [], context = {}) {
  const deterministicRisk = context.deterministicRisk || calculateGlobalRiskScore(enrichedFindings, { correlations: context.correlations || [] });
  const deterministicScoreBeforeAI = deterministicRisk.risk_score;
  const coverage = context.coverage || validateAIEnrichmentCoverage(enrichedFindings);
  if (!coverage.complete) {
    return {
      risk_score: null,
      risk_level: 'N/D',
      risk_grade: 'N/D',
      deterministicScoreBeforeAI,
      aiFinalScore100: null,
      finalScoreSource: 'pending_ai_global_review',
      aiFinalScoreStatus: 'partial',
      aiFinalScoreReason: `Cobertura IA incompleta: ${coverage.aiProcessed}/${coverage.totalReportableFindings}.`,
      aiFinalRiskLevel: null,
      riskScoreBreakdown: { explanation: 'Score final pendiente: la cobertura de enriquecimiento IA no es del 100%.' },
      risk_score_breakdown: { explanation: 'Score final pendiente: la cobertura de enriquecimiento IA no es del 100%.' }
    };
  }
  const invoke = context.generateJson || generarJsonIA;
  const prompt = buildFinalRiskPrompt(enrichedFindings.filter(isReportableForAI), {
    ...context,
    deterministicScoreBeforeAI
  });
  let parsed = null;
  let validation = null;
  let lastError = null;
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const retry = attempt === 1 ? '' : '\nCorrige la respuesta anterior, redacta todos los textos exclusivamente en espanol y respeta los guardrails sin inflar candidatos ni ignorar vulnerabilidades confirmadas.';
      const raw = await invoke(`${prompt}${retry}`, 0, 1, { findingId: 'global-risk-review', scanLogger: context.scanLogger || null });
      parsed = typeof raw === 'string' ? parsearJsonIAFlexible(raw) : raw;
      const language = validateAITextLanguage(parsed);
      if (!language.ok) {
        validation = null;
        throw new Error('language_not_spanish');
      }
      validation = validateAIFinalScore(parsed, enrichedFindings, { deterministicScoreBeforeAI });
      log(context.scanLogger, '[AI-FINAL-SCORE-VALIDATED]', { attempt, ok: validation.ok, originalScore: validation.originalScore, finalScore: validation.finalScore100, corrected: validation.corrected });
      if (validation.ok && !validation.requiresRetry) break;
      if (validation.ok && attempt === 2) break;
      lastError = new Error(validation.error || validation.overrideReason || 'Score IA fuera de guardrails');
    } catch (error) {
      lastError = error;
      log(context.scanLogger, '[AI-FINAL-SCORE-ERROR]', { attempt, error: error.message });
    }
  }

  if (!validation?.ok) {
    return {
      risk_score: null, risk_level: 'N/D', risk_grade: 'N/D', deterministicScoreBeforeAI,
      aiFinalScore100: null, finalScoreSource: 'pending_ai_global_review', aiFinalScoreStatus: 'failed',
      aiFinalScoreReason: lastError?.message || 'La IA no devolvio un score global valido.', aiFinalRiskLevel: null
    };
  }

  const explanation = 'La puntuacion final combina criticidad potencial, probabilidad real, estado del hallazgo, evidencia tecnica, correlaciones y revision IA global. Los candidatos criticos no se tratan como vulnerabilidades criticas confirmadas.';
  const breakdown = {
    ...(deterministicRisk.riskScoreBreakdown || deterministicRisk.risk_score_breakdown || {}),
    deterministicScoreBeforeAI,
    aiFinalScore100: validation.finalScore100,
    finalScoreSource: 'ai_global_review',
    aiFinalScoreReason: parsed.reason || parsed.scoreReason || '',
    aiFinalRiskLevel: validation.riskLevel,
    overrideReason: validation.overrideReason || null,
    explanation,
    mainDrivers: safeArray(parsed.mainDrivers),
    whyNotHigher: parsed.whyNotHigher || '',
    whyNotLower: parsed.whyNotLower || '',
    manualValidationPriorities: safeArray(parsed.manualValidationPriorities)
  };
  return {
    risk_score: validation.finalScore100,
    risk_level: validation.publicRiskLevel,
    risk_grade: validation.riskGrade,
    deterministicScoreBeforeAI,
    aiFinalScore100: validation.finalScore100,
    finalScoreSource: 'ai_global_review',
    aiFinalScoreStatus: 'success',
    aiFinalScoreReason: parsed.reason || parsed.scoreReason || '',
    aiFinalRiskLevel: validation.riskLevel,
    aiFinalScoreOverrideReason: validation.overrideReason || null,
    aiGlobalReview: parsed,
    riskScoreBreakdown: breakdown,
    risk_score_breakdown: breakdown
  };
}

module.exports = {
  REPORTABLE_AI_STATUSES,
  buildFinalRiskPrompt,
  computeFinalRiskScoreWithAI,
  enrichAllReportableFindingsWithAI,
  isReportableForAI,
  summarizeFindingForGlobalAI,
  validateAIEnrichmentCoverage,
  validateAIFinalScore
};
