const assert = require('assert');
const fs = require('fs');
const path = require('path');

const {
  normalizeFindingClassification
} = require('../modules/priorizacion/findingGroups');
const {
  calculateGlobalRiskScore,
  hasCriticalEvidence
} = require('../modules/priorizacion/scoring');
const {
  getAiOptionsFromEnv,
  selectFindingsForAI
} = require('../modules/ia/aiSelection');

function gf(vector, endpoint, parameter) {
  return normalizeFindingClassification({
    id: `gf-${vector}`,
    tool: 'gf',
    type: 'gf_candidate',
    vulnerability_type: vector,
    technicalStatus: 'candidate',
    finalStatus: 'candidate',
    confidence: 'low',
    evidenceStrength: 'weak',
    affected_url: endpoint,
    parameter,
    evidence: `GF marco el parametro ${parameter} con el patron ${vector}.`
  });
}

function testGfRceUsesCriticalPotentialSeverity() {
  const finding = gf('rce', 'https://example.test/survey_questions.jsp?step=1', 'step');
  assert.strictEqual(finding.finalStatus, 'candidate');
  assert.strictEqual(finding.potentialSeverity, 'critical');
  assert.strictEqual(finding.finalSeverity, 'critical');
  assert.ok(finding.realVulnerabilityProbabilityPercent >= 5 && finding.realVulnerabilityProbabilityPercent <= 20);
  assert.ok(['low', 'medium'].includes(finding.practicalRisk));
  assert.match(finding.impact, /impacto potencial seria critico/i);
  assert.match(finding.impact, /no existe ejecucion/i);
  assert.strictEqual(hasCriticalEvidence([finding], []), false);
  assert.ok(calculateGlobalRiskScore([finding]).risk_score < 90);
}

function testGfSqliUsesHighPotentialSeverity() {
  const finding = gf('sqli', 'https://example.test/item?id=1', 'id');
  assert.strictEqual(finding.finalStatus, 'candidate');
  assert.strictEqual(finding.finalSeverity, 'high');
  assert.ok(finding.realVulnerabilityProbabilityPercent >= 10 && finding.realVulnerabilityProbabilityPercent <= 30);
  assert.match(finding.recommendation, /prepared statements/i);
}

function testOpenRedirectDoesNotUseHttpsRedirectTemplate() {
  const finding = gf('open_redirect', 'https://example.test/disclaimer.htm?url=https://external.test', 'url');
  assert.strictEqual(finding.finalSeverity, 'medium');
  assert.match(finding.impact, /destino externo|phishing/i);
  assert.doesNotMatch(finding.impact, /trafico no cifrado|canal inseguro/i);
  assert.match(finding.recommendation, /allowlist/i);
}

function testObservedHardeningHasNoProbability() {
  const cookie = normalizeFindingClassification({
    id: 'cookie-samesite',
    tool: 'cookies',
    title: 'Cookie JSESSIONID sin SameSite',
    technicalStatus: 'hardening',
    finalStatus: 'hardening',
    finalSeverity: 'medium',
    evidence: 'JSESSIONID: Secure presente; HttpOnly presente; SameSite ausente.'
  });
  assert.strictEqual(cookie.probabilityFinal, null);
  assert.strictEqual(cookie.finalStatus, 'hardening');
  assert.match(cookie.recommendation, /SameSite=Lax o Strict/i);
  assert.doesNotMatch(cookie.recommendation, /Path=/i);

  const redirect = normalizeFindingClassification({
    id: 'https-redirect',
    tool: 'httpsRedirect',
    title: 'HTTP accesible sin redireccion a HTTPS',
    technicalStatus: 'hardening',
    finalStatus: 'hardening',
    finalSeverity: 'medium',
    evidence: 'HTTP 200 sin Location.'
  });
  assert.match(redirect.recommendation, /301\/308/i);
  assert.match(redirect.recommendation, /HSTS/i);
  assert.doesNotMatch(redirect.impact, /Open Redirect/i);
}

function testCompleteModeSelectsEveryVisibleFinding() {
  const findings = Array.from({ length: 32 }, (_, index) => ({
    id: `finding-${index}`,
    tool: index < 12 ? 'gf' : index < 22 ? 'headers' : 'katana',
    finalStatus: index < 12 ? 'candidate' : index < 22 ? 'hardening' : 'surface',
    technicalStatus: index < 12 ? 'candidate' : index < 22 ? 'hardening' : 'surface',
    finalSeverity: 'medium'
  }));
  const options = getAiOptionsFromEnv({ AI_MODE: 'complete', AI_MAX_INDIVIDUAL_FINDINGS: '0' });
  const selection = selectFindingsForAI(findings, [], options);
  assert.strictEqual(selection.selected.length, 32);
  assert.strictEqual(selection.skipped.length, 0);

  const pipeline = fs.readFileSync(path.join(__dirname, '..', 'modules', 'ia', 'aiMandatoryPipeline.js'), 'utf8');
  assert.match(pipeline, /for \(const index of reportableIndices\)/);
  assert.match(pipeline, /await enrichFinding\(finding/);
  assert.doesNotMatch(pipeline, /Promise\.all\([^)]*enrichFinding/);
}

function testCandidateCriticalDoesNotInflateConfirmedHighScore() {
  const confirmed = normalizeFindingClassification({
    id: 'xss-confirmed',
    tool: 'dalfox',
    title: 'XSS confirmado por Dalfox',
    technicalStatus: 'confirmed',
    finalStatus: 'confirmed',
    finalSeverity: 'high',
    confidence: 'high',
    evidenceStrength: 'strong',
    evidence: 'Triggered XSS Payload reproducible.'
  });
  const findings = [
    confirmed,
    gf('rce', 'https://example.test/run?step=1', 'step'),
    gf('sqli', 'https://example.test/item?id=1', 'id')
  ];
  const risk = calculateGlobalRiskScore(findings);
  assert.strictEqual(risk.riskScoreBreakdown.hasCriticalEvidence, false);
  assert.ok(risk.risk_score >= 65 && risk.risk_score < 90);
}

testGfRceUsesCriticalPotentialSeverity();
testGfSqliUsesHighPotentialSeverity();
testOpenRedirectDoesNotUseHttpsRedirectTemplate();
testObservedHardeningHasNoProbability();
testCompleteModeSelectsEveryVisibleFinding();
testCandidateCriticalDoesNotInflateConfirmedHighScore();

console.log('potential severity tests passed');
