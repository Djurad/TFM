const assert = require('assert');
const {
  aplicarImpactosIA,
  createIndividualAiFallback,
  promptImpactoRecomendacionIndividual,
  validateAIEnrichmentResult
} = require('../modules/ia/ia');

function testPromptRequiresProbability() {
  const prompt = promptImpactoRecomendacionIndividual('https://example.test', 'dalfox', {
    id: 'xss-1',
    finalStatus: 'confirmed',
    finalSeverity: 'high',
    probabilityBase: 0.94,
    parameter: 'HostName'
  });

  assert.match(prompt, /"probability"/);
  assert.match(prompt, /"status"/);
  assert.match(prompt, /"severity"/);
  assert.doesNotMatch(prompt, /severityReason|validationSteps|remediationSteps/);
}

function testAiCannotDowngradeLockedDalfoxFinding() {
  const finding = {
    id: 'xss-locked',
    tool: 'dalfox',
    title: 'XSS confirmado por Dalfox',
    technicalStatus: 'confirmed',
    finalStatus: 'confirmed',
    baseSeverity: 'high',
    finalSeverity: 'high',
    severity: 'high',
    lockedStatus: true,
    lockedSeverity: true,
    technicalMinimumSeverity: 'high',
    evidence: 'Triggered XSS Payload en HostName'
  };
  const validation = validateAIEnrichmentResult(finding, {
    aiSuggestedStatus: 'possible',
    suggestedSeverity: 'medium',
    severityReason: 'El endpoint tiene impacto limitado y requiere interaccion del usuario.'
  });

  assert.strictEqual(validation.finalStatus, 'confirmed');
  assert.strictEqual(validation.finalSeverity, 'high');
  assert.strictEqual(validation.overriddenByRule, true);
  assert.match(validation.overrideReason, /conserva|ignorado/i);
}

function testAiProbabilityIsParsedAndValidated() {
  const findings = [{
    id: 'xss-1',
    tool: 'dalfox',
    title: 'XSS confirmado',
    finalStatus: 'confirmed',
    technicalStatus: 'confirmed',
    finalSeverity: 'high',
    baseSeverity: 'high',
    severity: 'high',
    confidence: 'high',
    probabilityBase: 0.94,
    affected_url: 'https://example.test/status?HostName=x',
    evidence: 'Triggered XSS Payload',
    isVulnerability: true
  }];
  const result = aplicarImpactosIA(findings, [{
    id: 'xss-1',
    impacto: 'El parametro HostName permite ejecutar un payload reproducible en el navegador.',
    recomendacion: 'Aplicar escape contextual al parametro HostName y repetir la prueba.',
    motivo_criticidad: 'XSS confirmado con payload reproducible.',
    probabilidad_real: 96,
    motivo_probabilidad: 'Dalfox confirmo ejecucion reproducible.'
  }])[0];

  assert.strictEqual(result.probabilityAISuggested, 0.96);
  assert.strictEqual(result.realVulnerabilityProbabilityPercent, 96);
  assert.strictEqual(result.probabilitySource, 'ai_validated');
}

function testGfCandidateCannotBecomeConfirmed() {
  const finding = {
    id: 'gf-sqli-1',
    tool: 'gf',
    type: 'gf_candidate',
    vulnerability_type: 'sqli',
    title: 'Candidato SQLi',
    technicalStatus: 'candidate',
    finalStatus: 'candidate',
    baseSeverity: 'medium',
    finalSeverity: 'medium',
    confidence: 'low',
    affected_url: 'https://example.test/item?id=1',
    parameter: 'id',
    evidence: 'Patron GF: sqli'
  };
  const result = aplicarImpactosIA([finding], [{
    id: finding.id,
    aiSuggestedStatus: 'confirmed',
    aiSuggestedSeverity: 'critical',
    probabilityAISuggested: 90,
    confidence: 'high',
    severityReason: 'El parametro id podria alcanzar una consulta SQL, pero GF no prueba explotacion.',
    probabilityReason: 'Solo existe una coincidencia heuristica.',
    impact: 'El parametro id de /item coincide con un patron SQLi y podria alterar consultas si se concatena sin parametrizacion.',
    recommendation: 'Validar id manualmente y usar prepared statements con validacion estricta de tipo.'
  }])[0];

  assert.strictEqual(result.finalStatus, 'candidate');
  assert.strictEqual(result.finalSeverity, 'high');
  assert.strictEqual(result.confidence, 'low');
  assert.ok(result.realVulnerabilityProbabilityPercent <= 30);
  assert.strictEqual(result.overriddenByRule, true);
}

function testPromptKeepsOnlyMinimalGfRules() {
  const prompt = promptImpactoRecomendacionIndividual('https://example.test', 'gf', {
    id: 'gf-1',
    tool: 'gf',
    family: 'ssrf',
    finalStatus: 'candidate',
    parameter: 'url'
  });
  assert.match(prompt, /GF nunca puede ser confirmed/i);
  assert.match(prompt, /"family":"ssrf"/i);
  assert.doesNotMatch(prompt, /cvssVectorApprox|businessImpact/i);
}

function testIndividualAiFailureKeepsFindingPendingWithoutFinalTemplate() {
  const fallback = createIndividualAiFallback({
    id: 'gf-sqli-fallback',
    tool: 'gf',
    type: 'gf_candidate',
    vulnerability_type: 'sqli',
    finalStatus: 'candidate',
    technicalStatus: 'candidate',
    finalSeverity: 'medium',
    baseSeverity: 'medium',
    confidence: 'low',
    affected_url: 'https://example.test/item?id=1',
    parameter: 'id',
    evidence: 'Patron GF: sqli'
  }, new Error('connect ECONNREFUSED 127.0.0.1:11434'));

  assert.strictEqual(fallback.id, 'gf-sqli-fallback');
  assert.strictEqual(fallback.finalStatus, 'candidate');
  assert.strictEqual(fallback.aiProcessed, false);
  assert.strictEqual(fallback.impactSource, 'pending_ai');
  assert.strictEqual(fallback.recommendationSource, 'pending_ai');
  assert.strictEqual(fallback.probabilitySource, 'pending_ai');
  assert.strictEqual(fallback.impact, '');
  assert.strictEqual(fallback.recommendation, '');
  assert.strictEqual(fallback.templateUsedFinal, false);
  assert.match(fallback.aiError, /ECONNREFUSED/i);
}

testPromptRequiresProbability();
testAiProbabilityIsParsedAndValidated();
testAiCannotDowngradeLockedDalfoxFinding();
testGfCandidateCannotBecomeConfirmed();
testPromptKeepsOnlyMinimalGfRules();
testIndividualAiFailureKeepsFindingPendingWithoutFinalTemplate();

console.log('ai probability tests passed');
