const PDFDocument = require('pdfkit');
const { PAGE } = require('./pdfStyles');
const { prepareReportData } = require('./pdfUtils');
const {
  drawCharts,
  drawCover,
  drawExecutiveSummary,
  drawFindingSection,
  drawFindingsSummaryTable,
  drawGfCandidates,
  drawHardening,
  drawHeaderFooter,
  drawPageBackground,
  drawRecommendations,
  drawSurface,
  drawCorrelations,
  drawTechnicalAnnex
} = require('./pdfTemplate');

function generarNombreArchivo(target) {
  const slug = String(target || 'objetivo')
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/[^a-z0-9.-]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 60) || 'objetivo';
  return `informe-auditoria-web-${slug}.pdf`;
}

function crearDocumento() {
  const doc = new PDFDocument({
    size: 'A4',
    margin: PAGE.margin,
    bufferPages: true,
    autoFirstPage: true
  });

  drawPageBackground(doc);
  doc.on('pageAdded', () => {
    drawPageBackground(doc);
    doc.y = PAGE.top;
  });

  return doc;
}

function renderReport(doc, report) {
  drawCover(doc, report);

  doc.addPage();
  drawExecutiveSummary(doc, report);
  drawCharts(doc, report);

  doc.addPage();
  drawFindingsSummaryTable(doc, report);
  drawFindingSection(
    doc,
    'Vulnerabilidades confirmadas',
    'Estado: Confirmada',
    report.groups.confirmed,
    'Confirmada',
    'No se identificaron vulnerabilidades confirmadas.'
  );
  drawFindingSection(
    doc,
    'Posibles vulnerabilidades',
    'Requieren validacion manual',
    report.groups.possible,
    'Posible',
    'No se identificaron posibles vulnerabilidades con evidencia suficiente.'
  );

  drawGfCandidates(doc, report);
  drawHardening(doc, report);
  drawSurface(doc, report);
  drawCorrelations(doc, report);
  drawRecommendations(doc, report);
  drawTechnicalAnnex(doc, report);
  drawHeaderFooter(doc, report);
}

function generarPdfAuditoria(res, target, findings = [], context = {}) {
  const report = prepareReportData(target, findings, context);
  const doc = crearDocumento();

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename=${generarNombreArchivo(target)}`);

  doc.pipe(res);
  renderReport(doc, report);
  doc.end();
}

module.exports = {
  generarPdfAuditoria,
  generarNombreArchivo
};
