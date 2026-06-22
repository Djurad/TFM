const assert = require('assert');
const fs = require('fs');
const path = require('path');
const {
  applyDeterministicAiSkip,
  createAiCacheKey,
  normalizeEndpointPattern,
  selectFindingsForAI
} = require('../modules/ia/aiSelection');

function finding(overrides = {}) {
  const status = overrides.finalStatus || 'confirmed';
  return {
    id: overrides.id || Math.random().toString(36).slice(2),
    title: overrides.title || 'Hallazgo',
    tool: overrides.tool || 'dalfox',
    type: overrides.type || 'xss',
    finalStatus: status,
    technicalStatus: status,
    finalSeverity: overrides.finalSeverity || 'high',
    confidence: overrides.confidence || 'high',
    evidence: overrides.evidence || 'payload reproducible',
    affected_url: overrides.affected_url || 'https://example.test/search?q=1',
    ...overrides
  };
}

function testGfCandidatesAreSentIndividually() {
  const findings = Array.from({ length: 30 }, (_, index) => finding({
    id: `gf-${index}`,
    tool: 'gf',
    type: 'gf_candidate',
    finalStatus: 'candidate',
    finalSeverity: 'medium',
    confidence: 'low'
  }));

  const selection = selectFindingsForAI(findings, []);
  assert.strictEqual(selection.selected.length, 30);
  assert.strictEqual(selection.skipped.length, 0);
}

function testCompleteModeDoesNotLimitSurfaceItems() {
  const findings = Array.from({ length: 50 }, (_, index) => finding({
    id: `surface-${index}`,
    tool: 'katana',
    type: 'surface',
    finalStatus: 'surface',
    finalSeverity: 'low',
    affected_url: `https://example.test/path-${index}`
  }));

  const selection = selectFindingsForAI(findings, []);
  assert.strictEqual(selection.selected.length, 50);
  assert.strictEqual(selection.skipped.length, 0);
}

function testConfirmedAndPossibleArePrioritized() {
  const findings = [
    finding({ id: 'xss-1', finalStatus: 'confirmed', finalSeverity: 'high' }),
    finding({ id: 'sqli-1', tool: 'sqlmap', type: 'sqli', finalStatus: 'possible', finalSeverity: 'medium' }),
    ...Array.from({ length: 20 }, (_, index) => finding({
      id: `gf-${index}`,
      tool: 'gf',
      finalStatus: 'candidate',
      finalSeverity: 'medium'
    }))
  ];

  const selection = selectFindingsForAI(findings, [], { maxFindings: 8 });
  assert.strictEqual(selection.selected.length, 22);
  assert.deepStrictEqual(selection.selected.slice(0, 2).map(item => item.id), ['xss-1', 'sqli-1']);
}

function testFiveVisibleFindingsProduceFiveIndividualSelections() {
  const findings = [
    finding({ id: 'xss', finalStatus: 'confirmed' }),
    finding({ id: 'sqli', tool: 'sqlmap', finalStatus: 'possible', finalSeverity: 'medium' }),
    finding({ id: 'gf-sqli', tool: 'gf', finalStatus: 'candidate', vulnerability_type: 'sqli', finalSeverity: 'medium' }),
    finding({ id: 'gf-ssrf', tool: 'gf', finalStatus: 'candidate', vulnerability_type: 'ssrf', finalSeverity: 'medium' }),
    finding({ id: 'gf-rce', tool: 'gf', finalStatus: 'candidate', vulnerability_type: 'rce', finalSeverity: 'medium' })
  ];
  const selection = selectFindingsForAI(findings, []);
  let individualCalls = 0;
  selection.selected.forEach(() => { individualCalls += 1; });

  assert.strictEqual(selection.selected.length, 5);
  assert.strictEqual(individualCalls, 5);
}

function testServerUsesOnlySingleFindingEnrichment() {
  const serverSource = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  const pipelineSource = fs.readFileSync(path.join(__dirname, '..', 'modules', 'ia', 'aiMandatoryPipeline.js'), 'utf8');
  assert.match(serverSource, /enrichAllReportableFindingsWithAI\(findings/);
  assert.match(pipelineSource, /for \(const index of reportableIndices\)/);
  assert.match(pipelineSource, /await enrichFinding\(finding/);
  assert.doesNotMatch(serverSource, /enriquecerFindingsIA|enrichFindingsBatch|sendAllFindingsToAI/);
  assert.doesNotMatch(pipelineSource, /Promise\.all\([^)]*enrichFinding/);
}

function testCacheKeyUsesEndpointPattern() {
  const first = finding({
    affected_url: 'https://example.test/search?q=123&page=1',
    evidence: 'payload reproducible'
  });
  const second = finding({
    affected_url: 'https://example.test/search?page=99&q=abc',
    evidence: 'payload reproducible'
  });

  assert.strictEqual(normalizeEndpointPattern(first.affected_url), 'https://example.test/search?page&q');
  assert.strictEqual(createAiCacheKey(first), createAiCacheKey(second));
}

function testSkippedFindingRemainsPendingWithoutTemplate() {
  const skipped = applyDeterministicAiSkip(finding({
    tool: 'gf',
    type: 'gf_candidate',
    vulnerability_type: 'xss',
    finalStatus: 'candidate',
    finalSeverity: 'medium'
  }));

  assert.strictEqual(skipped.aiProcessed, false);
  assert.strictEqual(skipped.impact, '');
  assert.strictEqual(skipped.recommendation, '');
  assert.strictEqual(skipped.impactSource, 'pending_ai');
  assert.strictEqual(skipped.recommendationSource, 'pending_ai');
  assert.strictEqual(skipped.templateUsedFinal, false);
}

testGfCandidatesAreSentIndividually();
testCompleteModeDoesNotLimitSurfaceItems();
testConfirmedAndPossibleArePrioritized();
testFiveVisibleFindingsProduceFiveIndividualSelections();
testServerUsesOnlySingleFindingEnrichment();
testCacheKeyUsesEndpointPattern();
testSkippedFindingRemainsPendingWithoutTemplate();

console.log('aiSelection tests passed');
