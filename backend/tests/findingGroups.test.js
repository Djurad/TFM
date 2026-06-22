const assert = require('assert');
const { calcularRiskScore } = require('../modules/priorizacion/scoring');
const {
  buildImpactText,
  cleanImpactLanguage,
  buildFindingGroups,
  getFinalSeverity,
  getReportableSeverityCounts,
  getTechnicalSeverityCounts,
  getStatusCounts,
  normalizeSeverity,
  normalizeStatus,
  protectConfirmedTechnicalFindings,
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
  assert.ok(groups.gfCandidates.every(f => ['medium', 'high', 'critical'].includes(f.severity)));
  assert.ok((risk.risk_score || 0) < 20);
}

function testSqlmapPossible() {
  const groups = group([
    { tool: 'sqlmap', status: 'possible_sqli', severity: 'low', confidence: 'low', isVulnerability: false, affected_url: 'https://example.test/item?id=1' }
  ]);

  assert.strictEqual(groups.confirmed.length, 0);
  assert.strictEqual(groups.possible.length, 1);
  assert.strictEqual(groups.discarded.length, 0);
  assert.strictEqual(groups.possible[0].severity, 'high');
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
  const findings = [
    { tool: 'dalfox', title: 'XSS', finalSeverity: 'high', finalStatus: 'confirmed', confidence: 'high', isVulnerability: true },
    { tool: 'sqlmap', title: 'SQLi posible', finalSeverity: 'medium', finalStatus: 'possible', confidence: 'medium', isVulnerability: true },
    { tool: 'gf', title: 'GF 1', finalSeverity: 'low', finalStatus: 'candidate' },
    { tool: 'gf', title: 'GF 2', finalSeverity: 'low', finalStatus: 'candidate' },
    { tool: 'headers', title: 'CSP ausente', finalSeverity: 'medium', finalStatus: 'hardening' },
    { tool: 'ports', title: '443 abierto', finalSeverity: 'info', finalStatus: 'surface' }
  ];
  const reconciled = reconcileFindings(findings);

  assert.deepStrictEqual(getReportableSeverityCounts(reconciled.findings), {
    critical: 0,
    high: 2,
    medium: 0,
    low: 0,
    info: 0
  });
  assert.deepStrictEqual(getTechnicalSeverityCounts(reconciled.findings), {
    critical: 0,
    high: 2,
    medium: 1,
    low: 2,
    info: 1
  });
  assert.strictEqual(getStatusCounts(reconciled.findings).candidate, 2);
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
    'Permite ejecutar JavaScript en el navegador. El riesgo es relevante porque está confirmada por Dalfox.'
  );
}

function testCleanImpactLanguage() {
  const cleaned = cleanImpactLanguage('Se clasifica con esta severidad porque la gravedad media se debe a que no hay evidencia confirmada.');
  assert.ok(!/Se clasifica con esta severidad porque/i.test(cleaned));
  assert.ok(!/la gravedad media se debe a que/i.test(cleaned));
  assert.ok(/evidencia|confirmada/i.test(cleaned));
}

function testXssImpactDoesNotExaggerateHighSeverity() {
  const impact = buildImpactText({
    tool: 'dalfox',
    title: 'XSS confirmado',
    finalStatus: 'confirmed',
    finalSeverity: 'high',
    evidence: 'Triggered XSS Payload',
    impact: 'Puede permitir extraccion de datos sensibles o toma de control del sistema.'
  });

  assert.ok(!/toma de control del sistema/i.test(impact));
  assert.ok(!/extracci[oó]n de datos sensibles/i.test(impact));
  assert.ok(!/critico/i.test(impact));
  assert.ok(/No se eleva a critica/i.test(impact));
}

function testPossibleSqliImpactIsPrudent() {
  const impact = buildImpactText({
    tool: 'sqlmap',
    title: 'possible_sqli',
    finalStatus: 'possible',
    finalSeverity: 'medium',
    evidence: 'possible_sqli sin payload ni DBMS'
  });

  assert.ok(/no confirmo parametro vulnerable/i.test(impact));
  assert.ok(!/criticidad alta/i.test(impact));
}

function testConfirmedDalfoxIsProtectedBeforeReconciliation() {
  const [protectedFinding] = protectConfirmedTechnicalFindings([{
    id: 'dalfox-regression',
    tool: 'dalfox',
    title: 'XSS detectado',
    technicalStatus: 'possible',
    finalStatus: 'possible',
    baseSeverity: 'medium',
    finalSeverity: 'medium',
    confidence: 'low',
    evidence: 'Mensaje Dalfox: Triggered XSS Payload (found DOM Object): HostName=',
    payload: '\"><svg onload=alert(1)>',
    param: 'HostName'
  }]);
  const normalized = normalizeFindingClassification(protectedFinding);

  assert.strictEqual(normalized.finalStatus, 'confirmed');
  assert.strictEqual(normalized.finalSeverity, 'high');
  assert.strictEqual(normalized.confidence, 'high');
  assert.strictEqual(normalized.evidenceStrength, 'strong');
  assert.strictEqual(normalized.lockedStatus, true);
  assert.strictEqual(normalized.lockedSeverity, true);
  assert.strictEqual(normalized.cwe, 'CWE-79');
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
testCleanImpactLanguage();
testXssImpactDoesNotExaggerateHighSeverity();
testPossibleSqliImpactIsPrudent();
testConfirmedDalfoxIsProtectedBeforeReconciliation();

console.log('findingGroups tests passed');
