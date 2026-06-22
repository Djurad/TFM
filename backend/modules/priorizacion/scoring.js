const PESOS_SEVERIDAD = {
  info: 0,
  low: 2,
  medium: 5,
  high: 8,
  critical: 10
};

const {
  getFinalSeverity,
  getFinalStatus,
  getPotentialSeverity,
  normalizeFindingClassification,
  normalizeSeverity,
  normalizeStatus,
  safeArray
} = require('./findingGroups');

function obtenerCriticidadHallazgo(severidad) {
  return PESOS_SEVERIDAD[severidad] || 0;
}

function esHallazgoPuntuable(hallazgo = {}) {
  const finalStatus = getFinalStatus(hallazgo);
  return ['confirmed', 'possible'].includes(finalStatus) &&
    hallazgo.isVulnerability === true &&
    ['high', 'medium'].includes(hallazgo.confidence) &&
    hallazgo.isFalsePositiveLikely !== true &&
    !['reconocimiento', 'surface', 'discarded', 'hardening'].includes(hallazgo.type);
}

function obtenerCriticidadEndpoint(endpoint) {
  const evidencias = endpoint.evidencias || {};

  if (evidencias.sqli?.confirmado) return 10;
  if (evidencias.xss?.confirmado) return 8;

  return 0;
}

function nivelCriticidad(valor) {
  if (valor >= 9) return 'critico';
  if (valor >= 7) return 'alto';
  if (valor >= 4) return 'medio';
  if (valor >= 2) return 'bajo';
  return 'informativo';
}

function calcularDistribucionSeveridad(hallazgos) {
  const distribucion = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0
  };

  hallazgos.filter(esHallazgoPuntuable).forEach(h => {
    const severity = getFinalSeverity(h);
    if (distribucion[severity] !== undefined) {
      distribucion[severity]++;
    }
  });

  return distribucion;
}

function calcularDistribucionEndpoints(endpoints) {
  const distribucion = {
    informativo: 0,
    bajo: 0,
    medio: 0,
    alto: 0,
    critico: 0
  };

  endpoints.forEach(endpoint => {
    if (distribucion[endpoint.nivelCriticidad] !== undefined) {
      distribucion[endpoint.nivelCriticidad]++;
    }
  });

  return distribucion;
}

function calcularScoreGlobal(hallazgos) {
  return hallazgos.filter(esHallazgoPuntuable).reduce(
    (total, h) => total + h.criticidad,
    0
  );
}

function calcularRiesgoGlobal(score) {
  if (score >= 80) return 'critico';
  if (score >= 50) return 'alto';
  if (score >= 25) return 'medio';
  if (score >= 8) return 'bajo';
  return 'informativo';
}

function aplicarScoring(datos) {
  console.log('[Scoring] usando solo confirmadas + posibles');

  const hallazgos = datos.hallazgos.map(hallazgo => {
    const criticidad = esHallazgoPuntuable(hallazgo)
      ? obtenerCriticidadHallazgo(getFinalSeverity(hallazgo))
      : 0;

    return {
      ...hallazgo,
      criticidad,
      nivelCriticidad: nivelCriticidad(criticidad)
    };
  });

  const endpoints = datos.endpoints.map(endpoint => {
    const criticidad = obtenerCriticidadEndpoint(endpoint);

    return {
      ...endpoint,
      criticidad,
      nivelCriticidad: nivelCriticidad(criticidad)
    };
  });

  const score = calcularScoreGlobal(hallazgos);
  const hallazgosPuntuables = hallazgos.filter(esHallazgoPuntuable);

  return {
    ...datos,
    endpoints,
    hallazgos,
    resumen: {
      totalSubdominios: datos.subdominios.length,
      totalActivos: datos.activos.length,
      totalEndpoints: endpoints.length,
      totalEndpointsCriticos: endpoints.filter(e => e.nivelCriticidad === 'critico').length,
      totalEndpointsAltos: endpoints.filter(e => e.nivelCriticidad === 'alto').length,
      totalHallazgos: hallazgosPuntuables.length,
      riesgoGlobal: calcularRiesgoGlobal(score),
      score
    },
    distribucionSeveridad: calcularDistribucionSeveridad(hallazgos),
    distribucionCriticidadEndpoints: calcularDistribucionEndpoints(endpoints)
  };
}

const SCORE_WEIGHTS = {
  confirmed: { critical: 45, high: 30, medium: 16, low: 6, info: 0 },
  possible: { critical: 18, high: 12, medium: 7, low: 3, info: 0 },
  candidate: { critical: 4, high: 3, medium: 2, low: 0.75, info: 0 },
  hardening: { critical: 8, high: 6, medium: 4, low: 1.5, info: 0.5 },
  surface: { critical: 6, high: 5, medium: 3, low: 1, info: 0.5 },
  informational: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  discarded: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
};

const SCORE_CAPS = {
  candidate: 10,
  hardening: 15,
  surface: 10,
  correlation: 12
};

const CONFIDENCE_FACTORS = {
  high: 1,
  medium: 0.8,
  low: 0.5,
  unknown: 0.6
};

const EVIDENCE_FACTORS = {
  strong: 1,
  medium: 0.8,
  weak: 0.5,
  unknown: 0.6
};

function nivelRiesgo(score) {
  if (score === null || score === undefined) return 'N/D';
  if (score <= 24) return 'bajo';
  if (score <= 49) return 'medio';
  if (score <= 69) return 'alto moderado';
  if (score <= 89) return 'alto';
  return 'critico';
}

function gradoRiesgo(score) {
  if (score === null || score === undefined) return 'N/D';
  if (score <= 24) return 'A';
  if (score <= 49) return 'B';
  if (score <= 69) return 'C';
  if (score <= 89) return 'D';
  return 'E';
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function textOfFinding(finding = {}) {
  return [
    finding.title,
    finding.type,
    finding.category,
    finding.tool,
    finding.evidence,
    finding.impact,
    finding.technicalImpact,
    finding.businessImpact,
    finding.severityReason,
    finding.aiReasoningSummary,
    finding.affected_url,
    finding.affected_asset,
    finding.payload,
    finding.dbms,
    finding.detectorName,
    finding.raw_reference
  ].filter(Boolean).join(' ').toLowerCase();
}

function hasEvidence(finding = {}, pattern) {
  return pattern.test(textOfFinding(finding));
}

function searchText(finding = {}) {
  return textOfFinding(finding)
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '');
}

function boolFlag(finding = {}, names = []) {
  return names.some(name => {
    const value = finding[name];
    if (value === true) return true;
    if (typeof value !== 'string') return false;
    return ['true', 'yes', 'si', 'sí', '1', 'confirmed', 'demostrado'].includes(value.toLowerCase());
  });
}

function findingKind(finding = {}) {
  const text = [
    finding.family,
    finding.vulnerability_family,
    finding.vulnerabilityType,
    finding.vulnerability_type,
    finding.type,
    finding.category,
    finding.tool,
    finding.title,
    finding.detectorName,
    finding.templateID,
    finding.template_id
  ].filter(Boolean).join(' ').toLowerCase();

  if (/\brce\b|remote code execution|command injection|os command|ejecucion remota|ejecución remota/.test(text)) return 'rce';
  if (/\bsqli\b|sql injection|inyeccion sql|inyección sql|sqlmap/.test(text)) return 'sqli';
  if (/\bssrf\b|server side request forgery/.test(text)) return 'ssrf';
  if (/\bxss\b|cross.site scripting|dalfox/.test(text)) return 'xss';
  if (/\blfi\b|\brfi\b|file inclusion/.test(text)) return 'lfi';
  if (/secret|secreto|credential|credencial|api key|token|password|trufflehog/.test(text)) return 'secret';
  return 'other';
}

function normalizeEvidenceStrength(value) {
  const normalized = String(value || '').toLowerCase();
  if (['strong', 'medium', 'weak'].includes(normalized)) return normalized;
  if (['alta', 'high', 'confirmada', 'confirmed'].includes(normalized)) return 'strong';
  if (['media', 'moderate', 'moderada'].includes(normalized)) return 'medium';
  if (['baja', 'low', 'limited', 'limitada'].includes(normalized)) return 'weak';
  return '';
}

function inferEvidenceStrength(finding = {}) {
  const explicit = normalizeEvidenceStrength(finding.evidenceStrength || finding.evidence_strength);
  if (explicit) return explicit;

  const status = getFinalStatus(finding);
  const tool = String(finding.tool || '').toLowerCase();
  const text = textOfFinding(finding);

  if (status === 'candidate' || tool === 'gf') return 'weak';
  if (tool === 'dalfox' && /triggered|payload|poc|found dom object|confirmed|confirmado|xss/.test(text)) return 'strong';
  if (tool === 'sqlmap') {
    if (status === 'confirmed' && /payload|dbms|extraccion|extracci[oó]n|vulnerable|technique|t[eé]cnica/.test(text)) return 'strong';
    if (status === 'possible' && !/payload|dbms|parametro|par[aá]metro|parameter|error|diferencial/.test(text)) return 'weak';
    return status === 'possible' ? 'weak' : 'medium';
  }
  if (tool === 'trufflehog') return /verified|verificado|valid|valido|v[aá]lido/.test(text) ? 'strong' : 'medium';
  if (['headers', 'cookies', 'httpsredirect', 'tls'].includes(tool) && status === 'hardening') return 'medium';
  if (tool === 'ports' && /data-store|database|redis|mongodb|mysql|postgres/.test(text)) return 'medium';
  if (status === 'surface') return /swagger|openapi|admin|login|8080|8443/.test(text) ? 'medium' : 'weak';
  if (status === 'confirmed') {
    return /payload|poc|triggered|matched-at|verified|verificado|confirmad|dbms|secret|credential|extracted|extraccion|extracci[oó]n|vulnerable/.test(text)
      ? 'strong'
      : 'medium';
  }
  if (status === 'possible') {
    return /payload|parametro|par[aá]metro|parameter|error|trace|dbms|indic|diferencial/.test(text) ? 'medium' : 'weak';
  }
  if (status === 'hardening') return text ? 'medium' : 'weak';
  return 'unknown';
}

function confidenceFactor(value) {
  const confidence = String(value || 'unknown').toLowerCase();
  return CONFIDENCE_FACTORS[confidence] ?? CONFIDENCE_FACTORS.unknown;
}

function evidenceFactor(value) {
  const evidenceStrength = normalizeEvidenceStrength(value) || 'unknown';
  return EVIDENCE_FACTORS[evidenceStrength] ?? EVIDENCE_FACTORS.unknown;
}

function calculateStatusSeverityBasePoints(status, severity) {
  const normalizedStatus = normalizeStatus(status, 'informational') || 'informational';
  const normalizedSeverity = normalizeSeverity(severity || 'info');
  return SCORE_WEIGHTS[normalizedStatus]?.[normalizedSeverity] ?? 0;
}

function applyConfidenceMultiplier(points, confidence) {
  return points * confidenceFactor(confidence);
}

function applyEvidenceMultiplier(points, evidenceStrength) {
  return points * evidenceFactor(evidenceStrength);
}

function isCriticalCondition(finding = {}) {
  const status = getFinalStatus(finding);
  const severity = getFinalSeverity(finding);
  if (status !== 'confirmed') return false;
  const text = textOfFinding(finding);
  const strongCriticalEvidence = /rce|remote code execution|ejecucion remota|ejecuci[oó]n remota|command injection|extraccion|extracci[oó]n|dump|bypass|escritura|write|credencial|credential|secret|secreto|verified secret|metadata|169\.254\.169\.254|session hijack|robo de sesi[oó]n|acceso no autorizado|datos sensibles/.test(text);
  const sqliExtraction = /sql|sqli|injection|inyeccion|inyecci[oó]n/.test(text) &&
    /extraccion|extracci[oó]n|dump|datos sensibles|bypass|escritura|write|acceso no autorizado/.test(text);
  const criticalSeverityWithProof = severity === 'critical' &&
    /payload|poc|confirmad|verified|verificado|extracted|extraccion|extracci[oó]n|dbms|secret|secreto|metadata|session|sesi[oó]n|acceso|datos/.test(text);
  const strongEvidence = inferEvidenceStrength(finding) === 'strong';
  if (severity === 'critical' && !strongEvidence && !strongCriticalEvidence && !sqliExtraction) return false;
  return strongCriticalEvidence || sqliExtraction || criticalSeverityWithProof;
}

function isConfirmedCritical(finding = {}) {
  return getFinalStatus(finding) === 'confirmed' && getFinalSeverity(finding) === 'critical';
}

function isRceConfirmed(finding = {}) {
  return getFinalStatus(finding) === 'confirmed' &&
    /rce|remote code execution|ejecucion remota|ejecuci[oó]n remota|command injection|os command|code execution/.test(textOfFinding(finding));
}

function isSqliWithExtraction(finding = {}) {
  const text = textOfFinding(finding);
  return getFinalStatus(finding) === 'confirmed' &&
    /sql|sqli|injection|inyeccion|inyecci[oó]n/.test(text) &&
    /extraccion|extracci[oó]n|dump|datos sensibles|bypass|escritura|write|acceso no autorizado/.test(text);
}

function isSensitiveVerifiedSecret(finding = {}) {
  const text = textOfFinding(finding);
  return getFinalStatus(finding) === 'confirmed' &&
    /secret|secreto|token|api key|credential|credencial|password/.test(text) &&
    /verified|verificado|valido|v[aá]lido|valid|sensible|sensitive/.test(text);
}

function hasSessionOrSensitiveAccess(finding = {}) {
  return getFinalStatus(finding) === 'confirmed' &&
    /session hijack|robo de sesi[oó]n|compromiso de sesi[oó]n|acceso no autorizado|datos sensibles/.test(textOfFinding(finding));
}

function hasCriticalGate(finding = {}) {
  return isCriticalCondition(finding) ||
    isRceConfirmed(finding) ||
    isSqliWithExtraction(finding) ||
    isSensitiveVerifiedSecret(finding) ||
    hasSessionOrSensitiveAccess(finding);
}

function hasCriticalEvidence(findings = [], correlations = []) {
  const normalizedFindings = safeArray(findings).map(normalizeFindingClassification);
  if (normalizedFindings.some(isConfirmedCritical)) return true;
  if (normalizedFindings.some(hasCriticalGate)) return true;
  return normalizedFindings.filter(isStrongHighImpact).length >= 2 && correlationAllowsCritical(correlations);
}

function isStrongHighImpact(finding = {}) {
  if (getFinalStatus(finding) !== 'confirmed') return false;
  if (getFinalSeverity(finding) !== 'high') return false;
  return hasEvidence(finding, /payload|poc|triggered|matched-at|verified|confirmad|dbms|secret|credential|sesi[oó]n|session|admin|datos sensibles/);
}

function probabilityFactorForScore(status, finding = {}) {
  if (!['possible', 'candidate'].includes(status)) return 1;
  const probability = finding.probabilityFinal ?? finding.realVulnerabilityProbability;
  const parsed = Number(probability);
  if (!Number.isFinite(parsed)) return 1;
  const factor = parsed > 1 ? parsed / 100 : parsed;
  return clamp(factor, 0, 1);
}

function recordAdjustment(breakdown, finding, status, severity, base, confidence, evidenceStrength, adjusted, probabilityFactor = 1) {
  breakdown.confidenceAdjustments[confidence] = (breakdown.confidenceAdjustments[confidence] || 0) + 1;
  breakdown.evidenceAdjustments[evidenceStrength] = (breakdown.evidenceAdjustments[evidenceStrength] || 0) + 1;
  breakdown.findingPoints.push({
    id: finding.id || finding.title || 'sin-id',
    tool: finding.tool || 'otra',
    status,
    severity,
    potentialSeverity: getPotentialSeverity(finding),
    basePoints: Number(base.toFixed(2)),
    confidence,
    confidenceMultiplier: confidenceFactor(confidence),
    evidenceStrength,
    evidenceMultiplier: evidenceFactor(evidenceStrength),
    probabilityFactor,
    probabilityFinal: finding.probabilityFinal ?? finding.realVulnerabilityProbability ?? null,
    probabilityPercent: finding.realVulnerabilityProbabilityPercent ?? null,
    practicalRisk: finding.practicalRisk || null,
    practicalRiskScore: finding.practicalRiskScore ?? null,
    adjustedPoints: Number(adjusted.toFixed(2))
  });
}

function addWithCap(breakdown, bucket, value) {
  const cap = SCORE_CAPS[bucket] ?? Number.POSITIVE_INFINITY;
  const current = breakdown[`${bucket}Points`] || 0;
  const applied = clamp(value, 0, Math.max(0, cap - current));
  breakdown[`${bucket}Points`] = current + applied;
  if (applied < value && !breakdown.capsApplied.includes(`${bucket} cap ${cap}`)) {
    breakdown.capsApplied.push(`${bucket} cap ${cap}`);
  }
  return applied;
}

function calculateFindingPoints(finding = {}, breakdown = null) {
  const normalized = normalizeFindingClassification(finding);
  const status = getFinalStatus(normalized);
  const severity = getFinalSeverity(normalized);
  const base = calculateStatusSeverityBasePoints(status, severity);
  if (!base || normalized.isFalsePositiveLikely) return 0;

  const confidence = ['high', 'medium', 'low'].includes(String(normalized.confidence || '').toLowerCase())
    ? String(normalized.confidence).toLowerCase()
    : 'unknown';
  const evidenceStrength = inferEvidenceStrength(normalized);
  const adjusted = applyEvidenceMultiplier(
    applyConfidenceMultiplier(base, confidence),
    evidenceStrength
  ) * probabilityFactorForScore(status, normalized);

  if (!breakdown) return adjusted;

  recordAdjustment(breakdown, normalized, status, severity, base, confidence, evidenceStrength, adjusted, probabilityFactorForScore(status, normalized));

  if (status === 'confirmed') {
    breakdown.confirmedPoints += adjusted;
    return adjusted;
  }
  if (status === 'possible') {
    breakdown.possiblePoints += adjusted;
    return adjusted;
  }
  if (status === 'candidate') return addWithCap(breakdown, 'candidate', adjusted);
  if (status === 'hardening') return addWithCap(breakdown, 'hardening', adjusted);
  if (status === 'surface') return addWithCap(breakdown, 'surface', adjusted);

  breakdown.informationalPoints += adjusted;
  return adjusted;
}

function calculateCorrelationPoints(correlations = []) {
  const rawPoints = safeArray(correlations).reduce((total, correlation) => {
    const severity = normalizeSeverity(correlation.severity || correlation.finalSeverity || 'info');
    const text = [
      correlation.title,
      correlation.description,
      safeArray(correlation.chain).join(' ')
    ].filter(Boolean).join(' ').toLowerCase();

    const strong = /xss.*cookie|cookie.*xss|xss.*csp|csp.*xss|sqli.*confirm|sql.*extraccion|sql.*extracci[oó]n|rce|secret.*admin|metadata|session|sesi[oó]n|explot/.test(text);
    const medium = /gf.*sqlmap|sqlmap.*gf|swagger.*sensible|admin|panel|puerto.*web|correl/.test(text);

    if (strong) return total + (severity === 'critical' ? 8 : severity === 'high' ? 6 : 5);
    if (medium) return total + (severity === 'high' ? 4 : 3);
    return total + (severity === 'info' ? 0.5 : 1);
  }, 0);

  return Math.min(SCORE_CAPS.correlation, rawPoints);
}

function correlationAllowsCritical(correlations = []) {
  return safeArray(correlations).some(correlation =>
    /cadena.*explot|explot.*confirm|rce|extraccion|extracci[oó]n|secret|sesi[oó]n|datos sensibles|critical|critica/i
      .test(`${correlation.title || ''} ${correlation.description || ''} ${safeArray(correlation.chain).join(' ')}`)
  );
}

// Puerta critica estricta: evidencia fuerte no equivale a evidencia critica.
// Solo permite riesgo Critico cuando hay impacto critico demostrado o severidad final critical.
function isRceConfirmed(finding = {}) {
  return getFinalStatus(finding) === 'confirmed' &&
    findingKind(finding) === 'rce' &&
    inferEvidenceStrength(finding) === 'strong';
}

function isSqliWithExtraction(finding = {}) {
  const text = searchText(finding);
  const explicitImpact = boolFlag(finding, [
    'dataExtraction',
    'data_extraction',
    'extractionConfirmed',
    'authenticationBypass',
    'authentication_bypass',
    'authBypass',
    'writeAccess',
    'write_access',
    'sensitiveDataAccess',
    'sensitive_data_access'
  ]);
  const demonstratedText = /extraccion.*(demostrad|confirmad)|dump.*(demostrad|confirmad)|bypass.*(demostrad|confirmad)|escritura.*(demostrad|confirmad)|write access|sensitive data access|acceso.*datos sensibles/.test(text);
  const proof = boolFlag(finding, ['payloadConfirmed', 'payload_confirmed']) ||
    Boolean(finding.payload && finding.dbms) ||
    /payload|dbms|tecnica|técnica|confirmad|vulnerable/.test(text);

  return getFinalStatus(finding) === 'confirmed' &&
    findingKind(finding) === 'sqli' &&
    proof &&
    (explicitImpact || demonstratedText);
}

function isSensitiveVerifiedSecret(finding = {}) {
  const text = searchText(finding);
  return getFinalStatus(finding) === 'confirmed' &&
    findingKind(finding) === 'secret' &&
    (
      (boolFlag(finding, ['verified', 'isVerified', 'secretVerified']) && boolFlag(finding, ['sensitive', 'isSensitive', 'secretSensitive'])) ||
      (/verified|verificado|valido|valid/.test(text) && /sensible|sensitive|credential|credencial|password|api key/.test(text))
    );
}

function isSensitiveVerifiedSecretWithAccess(finding = {}) {
  if (!isSensitiveVerifiedSecret(finding)) return false;
  const text = searchText(finding);
  return boolFlag(finding, ['accessConfirmed', 'allowsAccess', 'realAccess', 'sensitiveDataAccess']) ||
    /permite acceso|acceso real|acceso demostrado|credencial valida con acceso|token valido con acceso/.test(text);
}

function isSsrfCritical(finding = {}) {
  if (getFinalStatus(finding) !== 'confirmed' || findingKind(finding) !== 'ssrf') return false;
  const text = searchText(finding);
  return boolFlag(finding, ['cloudMetadataAccess', 'metadataAccess', 'internalNetworkAccess', 'credentialAccess']) ||
    /169\.254\.169\.254|metadata|cloud metadata|red interna|internal network|credencial|credential|servicio interno sensible/.test(text);
}

function hasSessionOrSensitiveAccess(finding = {}) {
  const text = searchText(finding);
  return getFinalStatus(finding) === 'confirmed' && (
    boolFlag(finding, ['sessionCompromise', 'session_compromise']) ||
    (boolFlag(finding, ['unauthorizedAccess', 'unauthorized_access']) && boolFlag(finding, ['sensitiveDataAccess', 'sensitive_data_access'])) ||
    /robo de sesion demostrado|session hijack.*demonstrated|compromiso de sesion demostrado|acceso no autorizado demostrado.*datos sensibles/.test(text)
  );
}

function criticalDetailForFinding(finding = {}) {
  const id = finding.id || finding.fingerprint || finding.title || 'sin-id';

  if (isConfirmedCritical(finding)) {
    return {
      criticalEvidenceType: 'confirmed_critical',
      criticalEvidenceReason: 'Hallazgo confirmado con severidad final critical.',
      criticalEvidenceFindingIds: [id]
    };
  }

  if (isRceConfirmed(finding)) {
    return {
      criticalEvidenceType: 'confirmed_rce',
      criticalEvidenceReason: 'RCE confirmada con evidencia tecnica fuerte.',
      criticalEvidenceFindingIds: [id]
    };
  }

  if (isSqliWithExtraction(finding)) {
    return {
      criticalEvidenceType: 'sqli_critical_impact',
      criticalEvidenceReason: 'SQL Injection confirmada con extraccion, bypass, escritura o acceso sensible demostrado.',
      criticalEvidenceFindingIds: [id]
    };
  }

  if (isSensitiveVerifiedSecretWithAccess(finding)) {
    return {
      criticalEvidenceType: 'sensitive_secret_with_access',
      criticalEvidenceReason: 'Secreto valido y sensible con acceso real demostrado.',
      criticalEvidenceFindingIds: [id]
    };
  }

  if (isSsrfCritical(finding)) {
    return {
      criticalEvidenceType: 'critical_ssrf',
      criticalEvidenceReason: 'SSRF confirmada contra metadata cloud, red interna, credenciales o servicio interno sensible.',
      criticalEvidenceFindingIds: [id]
    };
  }

  if (hasSessionOrSensitiveAccess(finding)) {
    return {
      criticalEvidenceType: 'session_or_sensitive_access',
      criticalEvidenceReason: 'Compromiso de sesion o acceso no autorizado a datos sensibles demostrado.',
      criticalEvidenceFindingIds: [id]
    };
  }

  return null;
}

function hasCriticalChain(correlation = {}, normalizedFindings = []) {
  if (correlation.chainDemonstrated !== true || correlation.criticalImpact !== true) return false;
  const ids = new Set([
    ...safeArray(correlation.related_ids),
    ...safeArray(correlation.relatedIds),
    ...safeArray(correlation.finding_ids),
    ...safeArray(correlation.findingIds)
  ].filter(Boolean));

  if (!ids.size) {
    return normalizedFindings.some(f =>
      getFinalStatus(f) === 'confirmed' &&
      ['high', 'critical'].includes(getFinalSeverity(f))
    );
  }

  return normalizedFindings.some(f => {
    const id = f.id || f.fingerprint || f.title;
    return ids.has(id) &&
      getFinalStatus(f) === 'confirmed' &&
      ['high', 'critical'].includes(getFinalSeverity(f));
  });
}

function getCriticalEvidenceDetails(findings = [], correlations = []) {
  const normalizedFindings = safeArray(findings).map(normalizeFindingClassification);

  for (const finding of normalizedFindings) {
    const detail = criticalDetailForFinding(finding);
    if (detail) {
      return {
        hasCriticalEvidence: true,
        ...detail
      };
    }
  }

  const criticalCorrelation = safeArray(correlations).find(correlation => hasCriticalChain(correlation, normalizedFindings));
  if (criticalCorrelation) {
    const ids = [
      ...safeArray(criticalCorrelation.related_ids),
      ...safeArray(criticalCorrelation.relatedIds),
      ...safeArray(criticalCorrelation.finding_ids),
      ...safeArray(criticalCorrelation.findingIds)
    ].filter(Boolean);
    return {
      hasCriticalEvidence: true,
      criticalEvidenceType: 'demonstrated_critical_chain',
      criticalEvidenceReason: criticalCorrelation.criticalReason ||
        criticalCorrelation.reason ||
        'Cadena de explotacion demostrada con impacto critico.',
      criticalEvidenceFindingIds: ids
    };
  }

  return {
    hasCriticalEvidence: false,
    criticalEvidenceType: null,
    criticalEvidenceReason: null,
    criticalEvidenceFindingIds: []
  };
}

function hasCriticalEvidence(findings = [], correlations = []) {
  return getCriticalEvidenceDetails(findings, correlations).hasCriticalEvidence === true;
}

function applyGlobalCapsAndFloors(score, normalizedFindings, context = {}, breakdown = { capsApplied: [], floorsApplied: [] }) {
  const confirmed = normalizedFindings.filter(f => getFinalStatus(f) === 'confirmed');
  const possible = normalizedFindings.filter(f => getFinalStatus(f) === 'possible');
  const candidates = normalizedFindings.filter(f => getFinalStatus(f) === 'candidate');
  const hardening = normalizedFindings.filter(f => getFinalStatus(f) === 'hardening');
  const surface = normalizedFindings.filter(f => getFinalStatus(f) === 'surface');
  const informational = normalizedFindings.filter(f => getFinalStatus(f) === 'informational');
  const highConfirmed = confirmed.filter(f => getFinalSeverity(f) === 'high');
  const criticalConfirmed = confirmed.filter(isConfirmedCritical);
  const correlations = context.correlations || context.correlaciones || [];
  const criticalDetails = context.criticalEvidenceDetails || getCriticalEvidenceDetails(normalizedFindings, correlations);
  const criticalAllowed = criticalDetails.hasCriticalEvidence === true && Boolean(criticalDetails.criticalEvidenceReason);
  breakdown.hasCriticalEvidence = criticalAllowed;
  breakdown.criticalEvidenceReason = criticalDetails.criticalEvidenceReason || null;
  breakdown.criticalEvidenceFindingIds = criticalDetails.criticalEvidenceFindingIds || [];
  breakdown.criticalEvidenceType = criticalDetails.criticalEvidenceType || null;

  let adjustedScore = score;
  const cap = (max, reason) => {
    if (adjustedScore > max) {
      adjustedScore = max;
      breakdown.capsApplied.push(reason);
    }
  };
  const floor = (min, reason) => {
    if (adjustedScore < min) {
      adjustedScore = min;
      breakdown.floorsApplied.push(reason);
    }
  };

  if (!confirmed.length && !possible.length && !candidates.length && !hardening.length && surface.length && !criticalAllowed) {
    cap(30, 'solo superficie/informativos: max 30');
  }
  if (!confirmed.length && !possible.length && (candidates.length || hardening.length || surface.length) && !criticalAllowed) {
    cap(45, 'sin vulnerabilidades explotables, solo candidatos/hardening/superficie: max 45');
  }
  if (!confirmed.length && !criticalAllowed) {
    cap(60, 'sin vulnerabilidades confirmadas: max 60');
  }

  if (highConfirmed.length === 1 && confirmed.length === 1 && !criticalAllowed) {
    const hasPossibleRelevant = possible.some(f => ['medium', 'high'].includes(getFinalSeverity(f)));
    const hasRelevantContext = hasPossibleRelevant || hardening.length || surface.length || breakdown.correlationPoints > 0;
    if (!hasRelevantContext) {
      cap(72, 'una high confirmada aislada: max 72');
      floor(65, 'una high confirmada aislada: min 65');
    } else {
      const hasMediumHardeningCombo = hasPossibleRelevant && hardening.length;
      cap(hasMediumHardeningCombo && breakdown.correlationPoints < 5 ? 80 : 88, 'una high confirmada con contexto no critico: max 80/88');
      floor(hasMediumHardeningCombo ? 70 : 68, 'una high confirmada con contexto: min 68/70');
    }
  }

  if (highConfirmed.length >= 2 && !criticalAllowed) {
    floor(80, 'dos high confirmadas: min 80');
    cap(89, 'dos high confirmadas sin cadena critica demostrada: max 89');
  }

  if (criticalConfirmed.length && !criticalAllowed) {
    floor(85, 'confirmed critical sin evidencia critica fuerte: min 85');
    cap(89, 'critical sin puerta critica fuerte: max 89');
  }

  if (normalizedFindings.some(isSensitiveVerifiedSecret)) floor(85, 'secreto verificado sensible: min 85');
  if (criticalAllowed) {
    floor(90, 'evidencia critica real confirmada: min 90');
    if (!breakdown.capsApplied.includes('critico permitido por evidencia critica real')) {
      breakdown.capsApplied.push('critico permitido por evidencia critica real');
    }
  } else {
    cap(89, 'score critico bloqueado: falta evidencia critica real');
  }

  if (!confirmed.length && !possible.length && !candidates.length && !hardening.length && !surface.length && informational.length) {
    cap(10, 'solo informativos: max 10');
  }

  return adjustedScore;
}

function createBreakdown() {
  return {
    confirmedPoints: 0,
    possiblePoints: 0,
    candidatePoints: 0,
    hardeningPoints: 0,
    surfacePoints: 0,
    informationalPoints: 0,
    correlationPoints: 0,
    confidenceAdjustments: { high: 0, medium: 0, low: 0, unknown: 0 },
    evidenceAdjustments: { strong: 0, medium: 0, weak: 0, unknown: 0 },
    findingPoints: [],
    capsApplied: [],
    floorsApplied: [],
    hasCriticalEvidence: false,
    criticalEvidenceReason: null,
    criticalEvidenceFindingIds: [],
    criticalEvidenceType: null,
    validation: null,
    explanation: 'El score prioriza vulnerabilidades confirmadas y evidencia tecnica. Los candidatos GF, hardening y superficie tienen peso limitado para evitar inflar falsos positivos.'
  };
}

function validateRiskConsistency(score, normalizedFindings = [], criticalDetails = {}, breakdown = {}) {
  const criticalCount = normalizedFindings.filter(f => getFinalSeverity(f) === 'critical').length;
  const finalScoreBeforeValidation = Math.min(100, Math.max(0, Math.round(score)));
  let finalScoreAfterValidation = finalScoreBeforeValidation;
  const hasCriticalEvidenceFlag = criticalDetails.hasCriticalEvidence === true && Boolean(criticalDetails.criticalEvidenceReason);

  const validation = {
    criticalCount,
    hasCriticalEvidence: hasCriticalEvidenceFlag,
    criticalEvidenceReason: criticalDetails.criticalEvidenceReason || null,
    rawScore: breakdown.rawScore ?? null,
    finalScoreBeforeValidation,
    finalScoreAfterValidation,
    riskLevel: nivelRiesgo(finalScoreBeforeValidation)
  };

  if (!hasCriticalEvidenceFlag && finalScoreAfterValidation >= 90) {
    finalScoreAfterValidation = 89;
    validation.finalScoreAfterValidation = finalScoreAfterValidation;
    validation.riskLevel = nivelRiesgo(finalScoreAfterValidation);
    validation.corrected = true;
    validation.correctionReason = 'Critical risk blocked because no critical evidence was found';
    if (!breakdown.capsApplied.includes('score critico bloqueado por validacion final')) {
      breakdown.capsApplied.push('score critico bloqueado por validacion final');
    }
    console.log('[SCORE-CORRECTED] reason="Critical risk blocked because no critical evidence was found"');
  }

  console.log('[SCORE-VALIDATION]', JSON.stringify(validation));
  breakdown.validation = validation;
  return finalScoreAfterValidation;
}

function calculateGlobalRiskScore(finalFindings = [], context = {}) {
  const normalizedFindings = safeArray(finalFindings).map(normalizeFindingClassification);
  if (!normalizedFindings.length) {
    return {
      risk_score: null,
      risk_level: 'N/D',
      risk_grade: 'N/D',
      riskScoreBreakdown: null
    };
  }

  const breakdown = createBreakdown();
  normalizedFindings.forEach(finding => calculateFindingPoints(finding, breakdown));

  const correlations = context.correlations || context.correlaciones || [];
  const criticalEvidenceDetails = getCriticalEvidenceDetails(normalizedFindings, correlations);
  const criticalEvidence = criticalEvidenceDetails.hasCriticalEvidence === true && Boolean(criticalEvidenceDetails.criticalEvidenceReason);
  breakdown.hasCriticalEvidence = criticalEvidence;
  breakdown.criticalEvidenceReason = criticalEvidenceDetails.criticalEvidenceReason || null;
  breakdown.criticalEvidenceFindingIds = criticalEvidenceDetails.criticalEvidenceFindingIds || [];
  breakdown.criticalEvidenceType = criticalEvidenceDetails.criticalEvidenceType || null;
  const rawCorrelationPoints = safeArray(correlations).reduce(
    (total, correlation) => total + calculateCorrelationPoints([correlation]),
    0
  );
  const correlationCap = criticalEvidence ? SCORE_CAPS.correlation : 8;
  breakdown.correlationPoints = Math.min(correlationCap, rawCorrelationPoints);
  if (rawCorrelationPoints > breakdown.correlationPoints) {
    breakdown.capsApplied.push(`correlation cap ${correlationCap}`);
  }

  const rawScore =
    breakdown.confirmedPoints +
    breakdown.possiblePoints +
    breakdown.candidatePoints +
    breakdown.hardeningPoints +
    breakdown.surfacePoints +
    breakdown.informationalPoints +
    breakdown.correlationPoints;

  breakdown.rawScore = Number(rawScore.toFixed(2));
  const adjustedScore = applyGlobalCapsAndFloors(rawScore, normalizedFindings, {
    ...context,
    criticalEvidenceDetails
  }, breakdown);
  const risk_score = validateRiskConsistency(adjustedScore, normalizedFindings, criticalEvidenceDetails, breakdown);
  breakdown.finalScore = risk_score;
  breakdown.riskLevel = nivelRiesgo(risk_score);
  if (risk_score >= 90 && breakdown.criticalEvidenceReason) {
    breakdown.explanation = `${breakdown.explanation} Riesgo critico permitido por: ${breakdown.criticalEvidenceReason}`;
  }
  const confirmedCount = normalizedFindings.filter(f => getFinalStatus(f) === 'confirmed').length;
  const highCount = normalizedFindings.filter(f => getFinalStatus(f) === 'confirmed' && getFinalSeverity(f) === 'high').length;
  console.log('[SCORE-CHECK]', JSON.stringify({
    confirmedCount,
    highCount,
    hasConfirmedHigh: highCount > 0,
    finalScore: risk_score,
    riskLevel: breakdown.riskLevel
  }));

  return {
    risk_score,
    risk_level: breakdown.riskLevel,
    risk_grade: gradoRiesgo(risk_score),
    riskScoreBreakdown: breakdown,
    risk_score_breakdown: breakdown
  };
}

function calcularRiskScore(findings = [], context = {}) {
  return calculateGlobalRiskScore(findings, context);
}

module.exports = {
  aplicarScoring,
  applyConfidenceMultiplier,
  applyEvidenceMultiplier,
  applyGlobalCapsAndFloors,
  calculateCorrelationPoints,
  calculateFindingPoints,
  calculateGlobalRiskScore,
  calculateStatusSeverityBasePoints,
  calcularRiskScore,
  getCriticalEvidenceDetails,
  hasCriticalEvidence
};
