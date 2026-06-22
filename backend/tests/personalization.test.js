const assert = require('assert');
const {
  buildPersonalizedImpact,
  buildPersonalizedRecommendation,
  countFindingsByToolStatus,
  getFinalSeverity,
  getFinalStatus,
  normalizeFindingClassification,
  normalizeFindingsForReporting
} = require('../modules/priorizacion/findingGroups');
const { correlacionarFindings } = require('../modules/priorizacion/correlacion');

function testConfirmedXssUsesParameterAndEvidence() {
  const finding = normalizeFindingClassification({
    id: 'xss-1',
    tool: 'dalfox',
    title: 'XSS confirmado',
    finalStatus: 'confirmed',
    technicalStatus: 'confirmed',
    finalSeverity: 'high',
    confidence: 'high',
    evidenceStrength: 'strong',
    affected_url: 'https://example.test/status?HostName=test',
    payload: '<img src=x onerror=alert(1)>',
    evidence: 'Triggered XSS Payload',
    isVulnerability: true
  });

  assert.match(finding.impact, /HostName/i);
  assert.match(finding.impact, /payload reproducible|confirmo un payload/i);
  assert.doesNotMatch(finding.impact, /toma de control del sistema/i);
  assert.ok(finding.realVulnerabilityProbabilityPercent >= 90 && finding.realVulnerabilityProbabilityPercent <= 98);
}

function testPossibleSqlmapIsSpecific() {
  const finding = normalizeFindingClassification({
    id: 'sql-1',
    tool: 'sqlmap',
    title: 'possible_sqli',
    source_status: 'possible_sqli',
    finalStatus: 'possible',
    technicalStatus: 'possible',
    finalSeverity: 'medium',
    confidence: 'low',
    affected_url: 'https://example.test/item?id=1',
    evidence: 'possible_sqli sin payload, DBMS ni extraccion',
    isVulnerability: true
  });

  assert.match(finding.impact, /no confirmo parametro vulnerable, payload, DBMS ni extraccion/i);
  assert.match(finding.recommendation, /prepared statements|ORM seguro/i);
  assert.ok(finding.realVulnerabilityProbabilityPercent >= 25 && finding.realVulnerabilityProbabilityPercent <= 45);
}

function gfFinding(vector, url) {
  return normalizeFindingClassification({
    id: `gf-${vector}`,
    tool: 'gf',
    type: 'gf_candidate',
    vulnerability_type: vector,
    finalStatus: 'candidate',
    technicalStatus: 'candidate',
    finalSeverity: 'medium',
    confidence: 'low',
    affected_url: url,
    isVulnerability: false
  });
}

function testGfTemplatesAreVectorSpecific() {
  const sqli = gfFinding('sqli', 'https://example.test/item?id=1');
  const ssrf = gfFinding('ssrf', 'https://example.test/fetch?url=https://external.test');
  const rce = gfFinding('rce', 'https://example.test/run?cmd=id');

  assert.match(sqli.impact, /consultas.*sin parametrizacion|consultas o filtros de base de datos/i);
  assert.match(sqli.recommendation, /prepared statements/i);
  assert.ok(sqli.realVulnerabilityProbabilityPercent <= 30);
  assert.match(ssrf.impact, /peticiones SSRF|recursos internos/i);
  assert.match(ssrf.recommendation, /redes internas|metadata cloud/i);
  assert.ok(ssrf.realVulnerabilityProbabilityPercent <= 25);
  assert.match(rce.impact, /ejecucion de comandos/i);
  assert.match(rce.recommendation, /funciones de sistema|procesos externos/i);
  assert.ok(rce.realVulnerabilityProbabilityPercent <= 30);
}

function testCspCorrelatedWithXssStaysMediumHardening() {
  const xss = normalizeFindingClassification({
    id: 'xss-confirmed',
    tool: 'dalfox',
    title: 'XSS confirmado',
    finalStatus: 'confirmed',
    finalSeverity: 'high',
    confidence: 'high',
    evidence: 'Triggered XSS Payload',
    affected_url: 'https://example.test/search?q=x',
    isVulnerability: true
  });
  const csp = normalizeFindingClassification({
    id: 'csp-missing',
    tool: 'headers',
    header: 'content-security-policy',
    title: 'Content-Security-Policy ausente',
    finalStatus: 'hardening',
    technicalStatus: 'hardening',
    finalSeverity: 'low',
    severity: 'low',
    confidence: 'medium',
    isVulnerability: false
  });

  const correlated = correlacionarFindings([xss, csp], {});
  const final = normalizeFindingsForReporting(correlated.findings);
  const finalCsp = final.find(item => item.id === 'csp-missing');

  assert.strictEqual(getFinalStatus(finalCsp), 'hardening');
  assert.strictEqual(getFinalSeverity(finalCsp), 'medium');
  assert.strictEqual(finalCsp.category, 'defensive_configuration');
  assert.match(buildPersonalizedImpact(finalCsp), /agrava.*XSS confirmado/i);
}

function testKatanaSurfaceCounterUsesFinalStatus() {
  const findings = normalizeFindingsForReporting([
    { id: 'k1', tool: 'katana', title: 'Swagger', finalStatus: 'surface', finalSeverity: 'low' },
    { id: 'k2', tool: 'katana', title: 'Login', finalStatus: 'surface', finalSeverity: 'low' },
    { id: 'g1', tool: 'gau', title: 'Login', finalStatus: 'surface', finalSeverity: 'low' }
  ]);

  assert.strictEqual(countFindingsByToolStatus(findings, 'katana', 'surface'), 2);
}

testConfirmedXssUsesParameterAndEvidence();
testPossibleSqlmapIsSpecific();
testGfTemplatesAreVectorSpecific();
testCspCorrelatedWithXssStaysMediumHardening();
testKatanaSurfaceCounterUsesFinalStatus();

console.log('personalization tests passed');
