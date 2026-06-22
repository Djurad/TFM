const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..', '..');
const { displayTool, getRemediationSectionTitle, probabilityDisplay } = require('../modules/pdf/pdfUtils');

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), 'utf8');
}

function testReportableSeverityPanelRemoved() {
  const frontend = read('frontend/app.js');
  const pdfTemplate = read('backend/modules/pdf/pdfTemplate.js');
  const pdfGenerator = read('backend/modules/pdf/pdfGenerator.js');

  assert.ok(!frontend.includes('SEVERIDAD DE VULNERABILIDADES'));
  assert.ok(!pdfTemplate.includes('Severidad de vulnerabilidades reportables'));
  assert.ok(!pdfGenerator.includes('drawMetrics(doc, report)'));
}

function testMechanicalImpactPhraseRemoved() {
  const frontend = read('frontend/app.js');
  const findingGroups = read('backend/modules/priorizacion/findingGroups.js');

  assert.ok(!frontend.includes('La evidencia disponible indica que'));
  assert.ok(!findingGroups.includes('La evidencia disponible indica que'));
}

function testRemediationTitleDependsOnConfirmedCritical() {
  assert.strictEqual(
    getRemediationSectionTitle([{ finalStatus: 'confirmed', finalSeverity: 'high' }]),
    'Acciones de alta prioridad'
  );
  assert.strictEqual(
    getRemediationSectionTitle([{ finalStatus: 'confirmed', finalSeverity: 'critical' }]),
    'Acciones criticas inmediatas'
  );
}

function testProbabilityPresentationHidesInternalLabels() {
  assert.strictEqual(probabilityDisplay({ realVulnerabilityProbabilityPercent: 94, probabilityLabel: 'muy_alta' }), '94%');
  assert.strictEqual(probabilityDisplay({ realVulnerabilityProbabilityPercent: null, probabilityLabel: 'no_aplica' }), 'N/A');
  assert.strictEqual(probabilityDisplay({ finalStatus: 'candidate', probabilityFinal: 0.17 }), '17%');
  assert.strictEqual(probabilityDisplay({ finalStatus: 'candidate', probabilityFinal: 17 }), '17%');
  assert.strictEqual(probabilityDisplay({ finalStatus: 'surface', probabilityFinal: null }), 'N/A');

  const frontend = read('frontend/app.js');
  assert.ok(!frontend.includes("muy alta"));
  assert.ok(!frontend.includes("muy baja"));
}

function testObservedAndDisplayToolPresentation() {
  assert.strictEqual(displayTool({ tool: 'gau', sourceTool: 'gau' }), 'Gau');
  assert.strictEqual(displayTool({ sourceTools: ['katana', 'gau'] }), 'Katana/Gau');
  const frontend = read('frontend/app.js');
  assert.ok(frontend.includes('function probabilityPercentValue'));
  assert.ok(frontend.includes("finding.probabilityFinal"));
  assert.ok(frontend.includes('Verificacion:'));
  assert.ok(frontend.includes('displayToolFinding(finding)'));
}

function testGfUsesIndividualCardsInUiAndPdf() {
  const frontend = read('frontend/app.js');
  const frontendHtml = read('frontend/index.html');
  assert.ok(frontend.includes("renderGrupoHallazgos('Candidatos priorizados por GF'"));
  assert.ok(!frontend.includes('renderGfCompactTable'));
  assert.ok(!frontendHtml.includes('.gf-table'));
  assert.ok(frontend.includes('no una vulnerabilidad confirmada'));

  const pdfTemplate = read('backend/modules/pdf/pdfTemplate.js');
  const start = pdfTemplate.indexOf('function drawGfCandidates');
  const end = pdfTemplate.indexOf('function drawHardening', start);
  const block = pdfTemplate.slice(start, end);
  assert.ok(!block.includes('drawTableHeader'));
  assert.ok(block.includes("drawFindingCard(doc, finding, 'Candidato')"));
}

function testProbabilityIsRenderedOnceOnMainCards() {
  const frontend = read('frontend/app.js');
  const cardStart = frontend.indexOf('function renderFindingCard');
  const cardEnd = frontend.indexOf('function renderGrupoHallazgos', cardStart);
  const card = frontend.slice(cardStart, cardEnd);
  assert.ok(card.includes('renderProbabilityBadge(finding)'));
  assert.ok(!card.includes('Probabilidad real:'));
  assert.ok(!card.includes('Confianza:'));

  const pdfTemplate = read('backend/modules/pdf/pdfTemplate.js');
  const pdfStart = pdfTemplate.indexOf('function drawFindingCard');
  const pdfEnd = pdfTemplate.indexOf('function drawFindingSection', pdfStart);
  const pdfCard = pdfTemplate.slice(pdfStart, pdfEnd);
  assert.ok(pdfCard.includes('drawProbabilityBlock'));
  assert.ok(!pdfCard.includes("smallMeta(doc, 'Prob. real'"));
  assert.ok(!pdfCard.includes("smallMeta(doc, 'Confianza'"));
}

testReportableSeverityPanelRemoved();
testMechanicalImpactPhraseRemoved();
testRemediationTitleDependsOnConfirmedCritical();
testProbabilityPresentationHidesInternalLabels();
testObservedAndDisplayToolPresentation();
testGfUsesIndividualCardsInUiAndPdf();
testProbabilityIsRenderedOnceOnMainCards();

console.log('presentation tests passed');
