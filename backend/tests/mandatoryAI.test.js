const assert = require('assert');
const {
  validateAITextSpecificity,
  validateCvssLikeAIResult
} = require('../modules/ia/ia');
const {
  computeFinalRiskScoreWithAI,
  enrichAllReportableFindingsWithAI,
  validateAIEnrichmentCoverage,
  validateAIFinalScore
} = require('../modules/ia/aiMandatoryPipeline');

function baseFinding(id, status = 'candidate', tool = 'gf', severity = 'medium') {
  return {
    id,
    tool,
    title: `${status} ${id}`,
    type: status === 'candidate' ? 'gf_candidate' : status,
    vulnerability_type: id.includes('rce') ? 'rce' : id.includes('sqli') ? 'sqli' : id.includes('xss') ? 'xss' : 'configuration',
    technicalStatus: status,
    finalStatus: status,
    baseSeverity: severity,
    potentialSeverity: severity,
    finalSeverity: severity,
    severity,
    confidence: status === 'confirmed' ? 'high' : status === 'possible' ? 'medium' : 'low',
    affected_url: `https://example.test/${id}?id=1`,
    parameter: 'id',
    evidence: `${tool} observo evidencia tecnica para ${id}.`
  };
}

function completeAiResult(finding) {
  const status = finding.finalStatus || finding.technicalStatus;
  const probability = ['hardening', 'surface', 'informational'].includes(status) ? null : 0.2;
  return {
    ...finding,
    aiProcessed: true,
    aiEnrichmentId: `ai-${finding.id}`,
    aiModel: 'test-model',
    aiRawResponse: JSON.stringify({ id: finding.id, ok: true }),
    aiStatus: 'success',
    aiEnrichmentPending: false,
    impact: `${finding.tool} analizo ${finding.affected_url} y el parametro id segun la evidencia tecnica disponible, sin afirmar explotacion no demostrada.`,
    recommendation: `Configurar una mitigacion concreta en ${finding.affected_url} para el parametro id, verificarla con ${finding.tool} y repetir la prueba tecnica.`,
    impactSource: 'ai',
    recommendationSource: 'ai',
    severitySource: 'ai_validated',
    probabilitySource: 'ai_validated',
    probabilityAISuggested: probability,
    probabilityFinal: probability,
    realVulnerabilityProbability: probability,
    realVulnerabilityProbabilityPercent: probability === null ? null : Math.round(probability * 100),
    cvssLikeScore: Number(finding.cvssLikeScore ?? (finding.finalSeverity === 'critical' ? 9.5 : finding.finalSeverity === 'high' ? 8 : 5.5)),
    cvssLikeSeverity: finding.finalSeverity,
    cvssVectorApprox: { evidenceStrength: status === 'confirmed' ? 'confirmed' : status === 'candidate' ? 'weak' : 'observed' },
    templateUsed: false,
    fallbackUsed: false
  };
}

async function testThirtyFiveFindingsProduceThirtyFiveIndividualCalls() {
  const statuses = ['confirmed', 'possible', 'candidate', 'hardening', 'surface', 'informational'];
  const findings = Array.from({ length: 35 }, (_, index) => {
    const status = statuses[index % statuses.length];
    return baseFinding(`finding-${index}`, status, status === 'candidate' ? 'gf' : status === 'hardening' ? 'headers' : status === 'surface' ? 'katana' : 'nuclei', status === 'confirmed' ? 'high' : 'medium');
  });
  let calls = 0;
  const result = await enrichAllReportableFindingsWithAI(findings, {
    target: 'https://example.test',
    enrichFinding: async finding => { calls += 1; return completeAiResult(finding); }
  });
  assert.strictEqual(calls, 35);
  assert.strictEqual(result.stats.aiCallsMade, 35);
  assert.strictEqual(result.stats.aiProcessed, 35);
  assert.strictEqual(result.stats.templateUsedFinal, 0);
  assert.strictEqual(result.stats.genericFallbacksFinal, 0);
  assert.strictEqual(result.coverage.complete, true);
}

function testGfRceCvssLikeGuardrails() {
  const finding = baseFinding('gf-rce', 'candidate', 'gf', 'critical');
  const validated = validateCvssLikeAIResult(finding, {
    aiSuggestedStatus: 'confirmed',
    potentialSeverity: 'critical',
    cvssLikeScore: 10,
    probabilityAISuggested: 95,
    severityReason: 'GF solo detecto un patron RCE y no ejecuto comandos.'
  });
  assert.strictEqual(validated.potentialSeverity, 'critical');
  assert.ok(validated.cvssLikeScore >= 9 && validated.cvssLikeScore <= 10);
  assert.ok(validated.probabilityAISuggested >= 5 && validated.probabilityAISuggested <= 20);
}

function testSpecificHardeningAndRedirectValidation() {
  const cookie = {
    ...baseFinding('cookie-samesite', 'hardening', 'cookies', 'medium'),
    title: 'Cookie JSESSIONID sin SameSite',
    evidence: 'JSESSIONID: Secure presente; HttpOnly presente; Path presente; SameSite ausente.'
  };
  const cookieText = validateAITextSpecificity(
    cookie,
    'Cookies observo en https://example.test/cookie-samesite la ausencia de SameSite en JSESSIONID; Secure y HttpOnly ya estan presentes.',
    'En https://example.test/cookie-samesite, configurar SameSite=Lax o SameSite=Strict segun los flujos cross-site, mantener Secure y mantener HttpOnly, y validar login y logout con cookies.'
  );
  assert.strictEqual(cookieText.genericRecommendation, false, cookieText.reasons.join(', '));

  const redirect = {
    ...baseFinding('http-redirect', 'hardening', 'httpsRedirect', 'medium'),
    title: 'HTTP accesible sin redireccion a HTTPS',
    evidence: 'HTTP 200 sin Location.'
  };
  const redirectText = validateAITextSpecificity(
    redirect,
    'httpsRedirect observo que https://example.test/http-redirect responde por HTTP sin salto automatico a HTTPS.',
    'Configurar en https://example.test/http-redirect una redireccion permanente 301 o 308 de HTTP a HTTPS y, una vez validado HTTPS, habilitar HSTS como paso posterior.'
  );
  assert.strictEqual(redirectText.genericRecommendation, false, redirectText.reasons.join(', '));

  const openRedirect = {
    ...baseFinding('open-redirect', 'candidate', 'gf', 'medium'),
    title: 'Open Redirect candidate',
    vulnerability_type: 'open_redirect',
    affected_url: 'https://example.test/leave?url=https://evil.test',
    parameter: 'url'
  };
  const openText = validateAITextSpecificity(
    openRedirect,
    'GF marco https://example.test/leave y el parametro url como candidato a redireccion externa utilizable en phishing; no confirma explotacion.',
    'Aplicar una allowlist de destinos en https://example.test/leave para el parametro url, rechazar origenes externos y repetir la validacion con GF.'
  );
  assert.strictEqual(openText.genericRecommendation, false, openText.reasons.join(', '));
}

async function testGlobalAIScoreAndGuardrails() {
  const xss = completeAiResult({ ...baseFinding('xss-confirmed', 'confirmed', 'dalfox', 'high'), cvssLikeScore: 8.1 });
  const sqli = completeAiResult({ ...baseFinding('sqli-possible', 'possible', 'sqlmap', 'high'), cvssLikeScore: 8.0 });
  const rce = completeAiResult({ ...baseFinding('rce-candidate', 'candidate', 'gf', 'critical'), cvssLikeScore: 9.6 });
  const findings = [xss, sqli, rce];
  const coverage = validateAIEnrichmentCoverage(findings);
  const risk = await computeFinalRiskScoreWithAI(findings, {
    coverage,
    generateJson: async () => JSON.stringify({
      finalScore100: 80,
      riskLevel: 'high',
      scoreReason: 'XSS high confirmado con SQLi posible y RCE candidato de baja probabilidad.',
      mainDrivers: ['XSS confirmado'],
      whyNotHigher: 'No hay impacto critico confirmado.',
      whyNotLower: 'Existe XSS reproducible.'
    })
  });
  assert.ok(risk.risk_score >= 70 && risk.risk_score <= 85);
  assert.strictEqual(risk.aiFinalRiskLevel, 'high');
  assert.strictEqual(risk.finalScoreSource, 'ai_global_review');

  const inflated = validateAIFinalScore({ finalScore100: 95 }, findings);
  assert.ok(inflated.finalScore100 <= 85);
  const sunk = validateAIFinalScore({ finalScore100: 20 }, findings);
  assert.ok(sunk.finalScore100 >= 70);
}

async function testOneFailureProducesPartialAndNoGlobalScore() {
  const findings = [baseFinding('ok-1', 'confirmed', 'dalfox', 'high'), baseFinding('fail-1', 'candidate', 'gf', 'critical')];
  const result = await enrichAllReportableFindingsWithAI(findings, {
    enrichFinding: async finding => {
      if (finding.id === 'fail-1') throw new Error('Ollama unavailable');
      return completeAiResult(finding);
    }
  });
  assert.strictEqual(result.coverage.complete, false);
  assert.strictEqual(result.coverage.aiProcessed, 1);
  assert.strictEqual(result.coverage.templateUsedFinal, 0);
  assert.strictEqual(result.findings[1].impactSource, 'pending_ai');
  const risk = await computeFinalRiskScoreWithAI(result.findings, { coverage: result.coverage });
  assert.strictEqual(risk.risk_score, null);
  assert.strictEqual(risk.aiFinalScoreStatus, 'partial');
}

async function main() {
  await testThirtyFiveFindingsProduceThirtyFiveIndividualCalls();
  testGfRceCvssLikeGuardrails();
  testSpecificHardeningAndRedirectValidation();
  await testGlobalAIScoreAndGuardrails();
  await testOneFailureProducesPartialAndNoGlobalScore();
  console.log('mandatory AI tests passed');
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
