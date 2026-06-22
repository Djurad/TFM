const assert = require('assert');
const { calculateGlobalRiskScore, hasCriticalEvidence } = require('../modules/priorizacion/scoring');

function finding(overrides = {}) {
  const status = overrides.finalStatus || 'confirmed';
  return {
    id: overrides.id || Math.random().toString(36).slice(2),
    title: overrides.title || 'Hallazgo',
    tool: overrides.tool || 'dalfox',
    finalStatus: status,
    technicalStatus: status,
    finalSeverity: overrides.finalSeverity || 'high',
    baseSeverity: overrides.baseSeverity || overrides.finalSeverity || 'high',
    confidence: overrides.confidence || 'high',
    evidenceStrength: overrides.evidenceStrength || 'strong',
    isVulnerability: ['confirmed', 'possible'].includes(status),
    evidence: overrides.evidence || 'payload reproducible confirmado',
    impact: overrides.impact || 'Impacto tecnico acotado.',
    ...overrides
  };
}

function testXssHighWithHardeningAndPossibleSqli() {
  const result = calculateGlobalRiskScore([
    finding({ title: 'XSS confirmado', finalSeverity: 'high', evidence: 'payload XSS reproducible confirmado por Dalfox' }),
    finding({ tool: 'headers', finalStatus: 'hardening', finalSeverity: 'medium', confidence: 'medium', evidenceStrength: 'medium', isVulnerability: false }),
    finding({ tool: 'cookies', finalStatus: 'hardening', finalSeverity: 'medium', confidence: 'medium', evidenceStrength: 'medium', isVulnerability: false }),
    finding({ tool: 'sqlmap', finalStatus: 'possible', finalSeverity: 'medium', confidence: 'low', evidenceStrength: 'weak', evidence: 'possible_sqli sin payload ni DBMS' })
  ]);

  assert.ok(result.risk_score >= 70, `score ${result.risk_score} deberia ser >= 70`);
  assert.ok(result.risk_score <= 80, `score ${result.risk_score} deberia ser <= 80`);
  assert.notStrictEqual(result.risk_level, 'critico');
}

function testSingleHighConfirmed() {
  const result = calculateGlobalRiskScore([
    finding({ title: 'XSS confirmado', evidence: 'payload XSS reproducible' })
  ]);

  assert.ok(result.risk_score >= 65, `score ${result.risk_score} deberia ser >= 65`);
  assert.ok(result.risk_score <= 72, `score ${result.risk_score} deberia ser <= 72`);
  assert.notStrictEqual(result.risk_level, 'critico');
  assert.strictEqual(result.riskScoreBreakdown.hasCriticalEvidence, false);
}

function testStrongEvidenceDoesNotMeanCriticalEvidence() {
  const findings = [
    finding({
      title: 'XSS confirmado High',
      finalSeverity: 'high',
      evidenceStrength: 'strong',
      evidence: 'payload XSS reproducible confirmado por Dalfox',
      impact: 'La vulnerabilidad XSS puede permitir extraccion de datos sensibles o la toma de control del sistema. La criticidad alta se debe a que hay payload reproducible.'
    })
  ];
  const result = calculateGlobalRiskScore(findings);

  assert.strictEqual(hasCriticalEvidence(findings, []), false);
  assert.ok(result.risk_score < 90, `score ${result.risk_score} no deberia ser critico`);
  assert.strictEqual(result.risk_level === 'critico', false);
}

function testPossibleSqliAndGfDoNotInflate() {
  const result = calculateGlobalRiskScore([
    finding({ tool: 'sqlmap', finalStatus: 'possible', finalSeverity: 'medium', confidence: 'low', evidenceStrength: 'weak', evidence: 'possible_sqli sin payload, DBMS ni extraccion' }),
    ...Array.from({ length: 20 }, (_, index) => finding({
      tool: 'gf',
      title: `GF candidate ${index}`,
      finalStatus: 'candidate',
      finalSeverity: 'medium',
      confidence: 'low',
      evidenceStrength: 'weak',
      isVulnerability: false
    }))
  ]);

  assert.ok(result.risk_score <= 55, `score ${result.risk_score} deberia ser <= 55`);
  assert.ok(result.riskScoreBreakdown.candidatePoints <= 10);
}

function testOnlyHardeningAndSurfaceCap() {
  const result = calculateGlobalRiskScore([
    ...Array.from({ length: 10 }, (_, index) => finding({
      tool: 'headers',
      title: `Hardening ${index}`,
      finalStatus: 'hardening',
      finalSeverity: 'medium',
      confidence: 'medium',
      evidenceStrength: 'medium',
      isVulnerability: false
    })),
    ...Array.from({ length: 10 }, (_, index) => finding({
      tool: 'ports',
      title: `Surface ${index}`,
      finalStatus: 'surface',
      finalSeverity: 'low',
      confidence: 'low',
      evidenceStrength: 'weak',
      isVulnerability: false
    }))
  ]);

  assert.ok(result.risk_score <= 50, `score ${result.risk_score} deberia ser <= 50`);
}

function testConfirmedRceIsCritical() {
  const result = calculateGlobalRiskScore([
    finding({
      title: 'RCE confirmada',
      finalSeverity: 'critical',
      evidence: 'remote code execution payload confirmado',
      impact: 'Ejecucion remota de comandos confirmada.'
    })
  ]);

  assert.ok(result.risk_score >= 90);
  assert.strictEqual(result.risk_level, 'critico');
}

function testConfirmedSqliExtractionIsCritical() {
  const result = calculateGlobalRiskScore([
    finding({
      tool: 'sqlmap',
      title: 'SQL Injection confirmada con extraccion',
      finalSeverity: 'critical',
      dataExtraction: true,
      evidence: 'DBMS identificado y extraccion de datos demostrada',
      impact: 'Extraccion de datos confirmada.'
    })
  ]);

  assert.ok(result.risk_score >= 90);
  assert.strictEqual(result.risk_level, 'critico');
}

function testManyGfCandidatesAreCapped() {
  const result = calculateGlobalRiskScore(
    Array.from({ length: 50 }, (_, index) => finding({
      tool: 'gf',
      title: `GF ${index}`,
      finalStatus: 'candidate',
      finalSeverity: 'high',
      confidence: 'low',
      evidenceStrength: 'weak',
      isVulnerability: false
    }))
  );

  assert.ok(result.riskScoreBreakdown.candidatePoints <= 10);
  assert.ok(result.risk_score <= 45);
}

function testLargeSurfaceIsCapped() {
  const result = calculateGlobalRiskScore(
    Array.from({ length: 50 }, (_, index) => finding({
      tool: 'ports',
      title: `Surface ${index}`,
      finalStatus: 'surface',
      finalSeverity: 'medium',
      confidence: 'medium',
      evidenceStrength: 'medium',
      isVulnerability: false
    }))
  );

  assert.ok(result.riskScoreBreakdown.surfacePoints <= 10);
  assert.ok(result.risk_score <= 30);
}

function testTwoIndependentHighsAreNotCriticalWithoutChain() {
  const result = calculateGlobalRiskScore([
    finding({ id: 'xss-1', title: 'XSS confirmado', finalSeverity: 'high', evidence: 'payload XSS reproducible' }),
    finding({ id: 'xss-2', title: 'Open Redirect confirmado', finalSeverity: 'high', evidence: 'payload reproducible', impact: 'Impacto alto sin cadena critica demostrada.' })
  ]);

  assert.ok(result.risk_score >= 80, `score ${result.risk_score} deberia ser >= 80`);
  assert.ok(result.risk_score <= 89, `score ${result.risk_score} deberia ser <= 89`);
  assert.notStrictEqual(result.risk_level, 'critico');
  assert.strictEqual(result.riskScoreBreakdown.hasCriticalEvidence, false);
}

testXssHighWithHardeningAndPossibleSqli();
testSingleHighConfirmed();
testStrongEvidenceDoesNotMeanCriticalEvidence();
testPossibleSqliAndGfDoNotInflate();
testOnlyHardeningAndSurfaceCap();
testConfirmedRceIsCritical();
testConfirmedSqliExtractionIsCritical();
testManyGfCandidatesAreCapped();
testLargeSurfaceIsCapped();
testTwoIndependentHighsAreNotCriticalWithoutChain();

console.log('scoringConservative tests passed');
