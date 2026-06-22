const assert = require('assert');
const {
  normalizeFindingClassification,
  validateProbabilityDecision
} = require('../modules/priorizacion/findingGroups');

function normalized(overrides = {}) {
  return normalizeFindingClassification({
    id: overrides.id || 'finding-1',
    title: overrides.title || 'Hallazgo',
    tool: overrides.tool || 'dalfox',
    finalStatus: overrides.finalStatus || 'confirmed',
    technicalStatus: overrides.finalStatus || 'confirmed',
    finalSeverity: overrides.finalSeverity || 'high',
    severity: overrides.finalSeverity || 'high',
    confidence: overrides.confidence || 'high',
    evidenceStrength: overrides.evidenceStrength || 'strong',
    isVulnerability: ['confirmed', 'possible'].includes(overrides.finalStatus || 'confirmed'),
    evidence: overrides.evidence || 'payload reproducible confirmado',
    ...overrides
  });
}

function assertBetween(value, min, max, message) {
  assert.ok(value >= min && value <= max, `${message}: ${value} no esta entre ${min} y ${max}`);
}

function testDalfoxConfirmedXss() {
  const finding = normalized({
    tool: 'dalfox',
    title: 'XSS confirmado por Dalfox',
    evidence: 'Triggered XSS Payload con payload reproducible'
  });

  assertBetween(finding.probabilityFinal, 0.9, 0.98, 'XSS confirmado');
  assertBetween(finding.realVulnerabilityProbabilityPercent, 90, 98, 'XSS confirmado percent');
  assert.strictEqual(finding.probabilityLabel, 'muy_alta');
}

function testSqlmapPossibleWithoutEvidence() {
  const finding = normalized({
    tool: 'sqlmap',
    title: 'possible_sqli',
    finalStatus: 'possible',
    finalSeverity: 'medium',
    confidence: 'low',
    evidenceStrength: 'weak',
    source_status: 'possible_sqli',
    evidence: 'possible_sqli sin payload, DBMS ni extraccion'
  });

  assertBetween(finding.probabilityFinal, 0.25, 0.45, 'SQLMap possible_sqli');
  assert.strictEqual(finding.probabilityLabel, 'baja');
}

function testGfSqliCandidate() {
  const finding = normalized({
    tool: 'gf',
    vulnerability_type: 'sqli',
    finalStatus: 'candidate',
    finalSeverity: 'medium',
    confidence: 'low',
    evidenceStrength: 'weak',
    isVulnerability: false
  });

  assertBetween(finding.probabilityFinal, 0.1, 0.3, 'GF SQLi');
  assert.strictEqual(finding.finalStatus, 'candidate');
}

function testGfRceCandidateIsCapped() {
  const finding = normalized({
    tool: 'gf',
    vulnerability_type: 'rce',
    finalStatus: 'candidate',
    finalSeverity: 'high',
    probabilityAISuggested: 90,
    confidence: 'low',
    isVulnerability: false
  });

  assert.ok(finding.probabilityFinal <= 0.2);
  assert.ok(finding.probabilityOverrideReason);
}

function testHardeningNoAplica() {
  const finding = normalized({
    tool: 'headers',
    title: 'CSP ausente',
    finalStatus: 'hardening',
    finalSeverity: 'medium',
    isVulnerability: false
  });

  assert.strictEqual(finding.probabilityFinal, null);
  assert.strictEqual(finding.realVulnerabilityProbability, null);
  assert.strictEqual(finding.probabilityLabel, 'no_aplica');
}

function testSurfaceNoAplica() {
  const finding = normalized({
    tool: 'ports',
    title: 'Puerto 8080 expuesto',
    finalStatus: 'surface',
    finalSeverity: 'low',
    isVulnerability: false
  });

  assert.strictEqual(finding.probabilityFinal, null);
  assert.strictEqual(finding.probabilityLabel, 'no_aplica');
}

function testAiSqliPossibleOverruled() {
  const finding = normalized({
    tool: 'sqlmap',
    title: 'possible_sqli',
    finalStatus: 'possible',
    finalSeverity: 'medium',
    source_status: 'possible_sqli',
    evidence: 'possible_sqli sin payload ni DBMS',
    probabilityAISuggested: 95
  });

  assert.ok(finding.probabilityFinal <= 0.5);
  assert.ok(finding.probabilityOverrideReason);
}

function testConfirmedStrongMinimum() {
  const result = validateProbabilityDecision({
    tool: 'dalfox',
    title: 'XSS confirmado',
    finalStatus: 'confirmed',
    finalSeverity: 'high',
    evidence: 'payload reproducible',
    probabilityAISuggested: 30
  });

  assert.ok(result.probabilityFinal >= 0.85);
}

function testDiscardedCapped() {
  const finding = normalized({
    tool: 'nuclei',
    title: 'Falso positivo',
    finalStatus: 'discarded',
    finalSeverity: 'info',
    isFalsePositiveLikely: true,
    probabilityAISuggested: 50
  });

  assert.ok(finding.probabilityFinal <= 0.05);
}

testDalfoxConfirmedXss();
testSqlmapPossibleWithoutEvidence();
testGfSqliCandidate();
testGfRceCandidateIsCapped();
testHardeningNoAplica();
testSurfaceNoAplica();
testAiSqliPossibleOverruled();
testConfirmedStrongMinimum();
testDiscardedCapped();

console.log('probability tests passed');
