const assert = require('assert');
const { calcularRiskScore } = require('../modules/priorizacion/scoring');
const {
  buildImpactText,
  buildFindingGroups,
  getFinalSeverity,
  normalizeSeverity,
  normalizeStatus,
  reconcileFindings,
  normalizeFindingClassification
} = require('../modules/priorizacion/findingGroups');

function group(findings) {
  return buildFindingGroups(findings.map(normalizeFindingClassification));
}

function testOnlyGfCandidates() {
  const groups = group([
    { tool: 'gf', type: 'gf-candidate', vulnerability_type: 'sqli', severity: 'critical', confidence: 'high', isVulnerability: true },
    { tool: 'gf', type: 'gf-candidate', vulnerability_type: 'xss', severity: 'high', confidence: 'medium', isVulnerability: true }
  ]);
  const risk = calcularRiskScore([...groups.gfCandidates]);

  assert.strictEqual(groups.confirmed.length, 0);
  assert.strictEqual(groups.possible.length, 0);
  assert.strictEqual(groups.gfCandidates.length, 2);
  assert.ok(groups.gfCandidates.every(f => f.isVulnerability === false));
  assert.ok(groups.gfCandidates.every(f => ['low', 'medium'].includes(f.severity)));
  assert.ok((risk.risk_score || 0) < 20);
}

function testSqlmapPossible() {
  const groups = group([
    { tool: 'sqlmap', status: 'possible_sqli', severity: 'low', confidence: 'low', isVulnerability: false, affected_url: 'https://example.test/item?id=1' }
  ]);

  assert.strictEqual(groups.confirmed.length, 0);
  assert.strictEqual(groups.possible.length, 1);
  assert.strictEqual(groups.discarded.length, 0);
  assert.strictEqual(groups.possible[0].severity, 'medium');
  assert.strictEqual(groups.possible[0].requiresManualValidation, true);
}

function testSqlmapConfirmed() {
  const groups = group([
    { tool: 'sqlmap', status: 'confirmed_sqli', payload: "' OR 1=1--", dbms: 'MySQL', severity: 'medium', confidence: 'medium', isVulnerability: true }
  ]);

  assert.strictEqual(groups.confirmed.length, 1);
  assert.strictEqual(groups.possible.length, 0);
  assert.ok(['critical', 'high'].includes(groups.confirmed[0].severity));
}

function testOnlyHardening() {
  const groups = group([
    { tool: 'headers', type: 'missing_security_header', severity: 'medium', confidence: 'medium', isVulnerability: true }
  ]);

  assert.strictEqual(groups.confirmed.length, 0);
  assert.strictEqual(groups.possible.length, 0);
  assert.strictEqual(groups.hardening.length, 1);
  assert.strictEqual(groups.hardening[0].isVulnerability, false);
}

function testNucleiTechDetect() {
  const groups = group([
    { tool: 'nuclei', templateID: 'tech-detect', type: 'vulnerability', severity: 'high', confidence: 'high', isVulnerability: true, evidence: '[tech-detect] [http] [info] https://example.test' },
    { tool: 'nuclei', templateID: 'waf-detect', type: 'vulnerability', severity: 'medium', confidence: 'medium', isVulnerability: true }
  ]);

  assert.strictEqual(groups.confirmed.length, 0);
  assert.strictEqual(groups.possible.length, 0);
  assert.strictEqual(groups.informational.length, 2);
}

function testSeverityNormalizationAndPriority() {
  assert.strictEqual(normalizeSeverity('alta'), 'high');
  assert.strictEqual(normalizeSeverity('high'), 'high');
  assert.strictEqual(normalizeSeverity('crítica'), 'critical');
  assert.strictEqual(normalizeSeverity('critica'), 'critical');
  assert.strictEqual(normalizeSeverity('media'), 'medium');
  assert.strictEqual(normalizeSeverity('baja'), 'low');

  assert.strictEqual(getFinalSeverity({ criticidad: 'crítica', finalSeverity: 'high' }), 'high');
  assert.strictEqual(getFinalSeverity({ severity: 'critical', finalSeverity: 'medium' }), 'medium');
  assert.strictEqual(getFinalSeverity({ baseSeverity: 'high', aiSuggestedSeverity: 'medium', finalSeverity: 'medium' }), 'medium');
}

function testStatusNormalization() {
  assert.strictEqual(normalizeStatus('confirmada'), 'confirmed');
  assert.strictEqual(normalizeStatus('possible_sqli'), 'possible');
  assert.strictEqual(normalizeStatus('gf'), 'candidate');
  assert.strictEqual(normalizeStatus('hardening'), 'hardening');
  assert.strictEqual(normalizeStatus('surface'), 'surface');
}

function testCountersFromFinalFields() {
  const reconciled = reconcileFindings([
    { tool: 'dalfox', title: 'XSS', finalSeverity: 'high', finalStatus: 'confirmed', confidence: 'high', isVulnerability: true },
    { tool: 'sqlmap', title: 'SQLi posible', finalSeverity: 'medium', finalStatus: 'possible', confidence: 'medium', isVulnerability: true },
    { tool: 'headers', title: 'CSP ausente', finalSeverity: 'medium', finalStatus: 'hardening' },
    { tool: 'ports', title: '443 abierto', finalSeverity: 'info', finalStatus: 'surface' }
  ]);

  assert.deepStrictEqual(reconciled.severityCounts, {
    critical: 0,
    high: 1,
    medium: 2,
    low: 0,
    info: 1
  });
  assert.strictEqual(reconciled.statusCounts.confirmed, 1);
  assert.strictEqual(reconciled.statusCounts.possible, 1);
  assert.strictEqual(reconciled.statusCounts.hardening, 1);
  assert.strictEqual(reconciled.statusCounts.surface, 1);
}

function testBuildImpactText() {
  const impact = buildImpactText({
    impact: 'Permite ejecutar JavaScript en el navegador.',
    severityReason: 'Se clasifica como alta porque está confirmada por Dalfox.'
  });

  assert.strictEqual(
    impact,
    'Permite ejecutar JavaScript en el navegador. Se clasifica como alta porque está confirmada por Dalfox.'
  );
}

testOnlyGfCandidates();
testSqlmapPossible();
testSqlmapConfirmed();
testOnlyHardening();
testNucleiTechDetect();
testSeverityNormalizationAndPriority();
testStatusNormalization();
testCountersFromFinalFields();
testBuildImpactText();

console.log('findingGroups tests passed');
