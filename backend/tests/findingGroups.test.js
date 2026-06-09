const assert = require('assert');
const { calcularRiskScore } = require('../modules/procesamiento/scoring');
const {
  buildFindingGroups,
  normalizeFindingClassification
} = require('../modules/procesamiento/findingGroups');

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

testOnlyGfCandidates();
testSqlmapPossible();
testSqlmapConfirmed();
testOnlyHardening();
testNucleiTechDetect();

console.log('findingGroups tests passed');
