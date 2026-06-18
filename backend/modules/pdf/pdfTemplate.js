const fs = require('fs');
const path = require('path');
const { COLORS, SEVERITY, FONTS, PAGE } = require('./pdfStyles');
const { drawDonutChart, drawHorizontalChart, drawRiskGauge, drawSeverityBars } = require('./pdfCharts');
const { buildImpactText, getAsset, getFinalSeverity, normalizeSeverity, safeArray, text, truncate } = require('./pdfUtils');

function getLogoPath() {
  const logoPath = path.join(__dirname, '../../../frontend/assets/site-logo.png');
  return fs.existsSync(logoPath) ? logoPath : null;
}

function pageBounds(doc) {
  return {
    width: doc.page.width,
    height: doc.page.height,
    left: PAGE.margin,
    right: doc.page.width - PAGE.margin,
    bottom: doc.page.height - PAGE.bottom
  };
}

function drawPageBackground(doc) {
  const { width, height } = pageBounds(doc);
  doc.rect(0, 0, width, height).fill(COLORS.bg);
  doc.strokeColor('#0F2730').lineWidth(0.25).opacity(0.45);
  for (let x = 0; x <= width; x += 32) {
    doc.moveTo(x, 0).lineTo(x, height).stroke();
  }
  for (let y = 0; y <= height; y += 32) {
    doc.moveTo(0, y).lineTo(width, y).stroke();
  }
  doc.opacity(1);
  doc.fillOpacity(1);
}

function ensureSpace(doc, height) {
  const bounds = pageBounds(doc);
  if (doc.y + height > bounds.bottom) {
    doc.addPage();
    doc.y = PAGE.top;
  }
}

function sectionTitle(doc, title, kicker = '') {
  ensureSpace(doc, 54);
  const { left } = pageBounds(doc);
  doc.moveDown(0.5);
  if (kicker) {
    doc.font(FONTS.bold).fontSize(7).fillColor(COLORS.cyan).text(String(kicker).toUpperCase(), left, doc.y, {
      width: PAGE.contentWidth
    });
    doc.moveDown(0.2);
  }
  doc.font(FONTS.bold).fontSize(18).fillColor(COLORS.text).text(title, left, doc.y, { width: PAGE.contentWidth });
  doc.moveTo(left, doc.y + 5).lineTo(left + PAGE.contentWidth, doc.y + 5).strokeColor(COLORS.border).lineWidth(0.8).stroke();
  doc.moveDown(0.9);
}

function panel(doc, x, y, width, height, options = {}) {
  doc.roundedRect(x, y, width, height, 8).fill(options.fill || COLORS.panel);
  doc.roundedRect(x, y, width, height, 8).strokeColor(options.stroke || COLORS.border).lineWidth(0.8).stroke();
  if (options.accent) {
    doc.roundedRect(x, y, 4, height, 2).fill(options.accent);
  }
}

function fixedText(doc, value, x, y, options = {}) {
  const previous = { x: doc.x, y: doc.y };
  doc.text(String(value), x, y, {
    lineBreak: false,
    height: options.height || 14,
    ...options
  });
  doc.x = previous.x;
  doc.y = previous.y;
}

function severityColor(severity) {
  return (SEVERITY[normalizeSeverity(severity)] || SEVERITY.info).color;
}

function severityLabel(severity) {
  return (SEVERITY[normalizeSeverity(severity)] || SEVERITY.info).label;
}

function chip(doc, x, y, label, color) {
  const width = Math.max(48, doc.widthOfString(label) + 18);
  doc.roundedRect(x, y, width, 16, 8).fill(color);
  doc.font(FONTS.bold).fontSize(7).fillColor(COLORS.white);
  fixedText(doc, label, x + 9, y + 4, { width: width - 18, align: 'center', height: 8 });
  return width;
}

function smallMeta(doc, label, value, x, y, width) {
  doc.font(FONTS.bold).fontSize(6.5).fillColor(COLORS.subtle);
  fixedText(doc, String(label).toUpperCase(), x, y, { width, height: 8 });
  doc.font(FONTS.regular).fontSize(8.5).fillColor(COLORS.text);
  fixedText(doc, truncate(value, 72), x, y + 10, { width, height: 12 });
}

function drawCover(doc, report) {
  const { left, width, height } = pageBounds(doc);
  doc.y = 92;

  doc.roundedRect(left, 70, PAGE.contentWidth, height - 140, 14).fill(COLORS.panelAlt);
  doc.roundedRect(left, 70, PAGE.contentWidth, height - 140, 14).strokeColor(COLORS.border).lineWidth(1).stroke();
  doc.rect(left, 70, PAGE.contentWidth, 7).fill(COLORS.low);

  doc.font(FONTS.bold).fontSize(8).fillColor(COLORS.cyan).text('WEB SECURITY AUDIT', left + 32, 112, {
    width: PAGE.contentWidth - 64
  });

  const logoPath = getLogoPath();
  if (logoPath) {
    try {
      doc.image(logoPath, left + PAGE.contentWidth - 126, 102, { fit: [92, 92] });
    } catch {
      // El logo es decorativo; si PDFKit no puede leerlo, el informe sigue generandose.
    }
  }

  doc.font(FONTS.bold).fontSize(34).fillColor(COLORS.text)
    .text('Informe de Auditoria de Vulnerabilidades Web', left + 32, 145, {
      width: PAGE.contentWidth - (logoPath ? 188 : 96),
      lineGap: 3
    });

  const score = report.risk.score === null || report.risk.score === undefined ? 'N/D' : `${report.risk.score}/100`;
  panel(doc, left + 32, 326, 210, 110, { fill: COLORS.panel, accent: severityColor(scoreToSeverity(report.risk.score)) });
  doc.font(FONTS.bold).fontSize(10).fillColor(COLORS.muted).text('RIESGO GLOBAL', left + 52, 348);
  doc.font(FONTS.bold).fontSize(31).fillColor(COLORS.cyan).text(score, left + 52, 368);
  doc.font(FONTS.bold).fontSize(10).fillColor(severityColor(scoreToSeverity(report.risk.score)));
  fixedText(doc, report.risk.label, left + 52, 408, { width: 170, height: 12 });

  panel(doc, left + 262, 326, 214, 110, { fill: COLORS.panel });
  smallMeta(doc, 'Target analizado', report.target, left + 282, 350, 174);
  smallMeta(doc, 'Fecha del analisis', report.generatedAtLabel, left + 282, 394, 174);

  drawRiskGauge(doc, left + 52, 482, PAGE.contentWidth - 104, report.risk.score);

  doc.font(FONTS.bold).fontSize(8).fillColor(COLORS.cyan).text('RESUMEN DE ALCANCE', left + 52, 552);
  const coverMetrics = [
    ['Confirmadas', report.groups.confirmed.length],
    ['Posibles', report.groups.possible.length],
    ['GF candidatos', report.groups.gfCandidates.length],
    ['Hardening', report.groups.hardening.length],
    ['Superficie', report.groups.attackSurface.length]
  ];
  coverMetrics.forEach((item, index) => {
    const x = left + 42 + (index * 94);
    doc.font(FONTS.bold).fontSize(20).fillColor(COLORS.text);
    fixedText(doc, String(item[1]), x, 576, { width: 84, align: 'center', height: 22 });
    doc.font(FONTS.regular).fontSize(8).fillColor(COLORS.muted);
    fixedText(doc, item[0], x, 603, { width: 84, align: 'center', height: 10 });
  });

  doc.font(FONTS.regular).fontSize(8).fillColor(COLORS.subtle)
    .text('El informe separa vulnerabilidades confirmadas, candidatos pendientes de validacion, hardening y superficie de ataque para evitar inflar falsos positivos.', left + 52, height - 130, {
      width: PAGE.contentWidth - 104,
      align: 'center'
    });
}

function scoreToSeverity(score) {
  if (score === null || score === undefined) return 'info';
  if (score > 80) return 'critical';
  if (score > 60) return 'high';
  if (score > 40) return 'medium';
  if (score > 20) return 'low';
  return 'info';
}

function drawExecutiveSummary(doc, report) {
  sectionTitle(doc, 'Resumen ejecutivo', 'Sintesis');
  const { left } = pageBounds(doc);
  const tools = Object.keys(report.toolResults || {}).join(', ') || 'herramientas configuradas en el pipeline';
  const paragraph = [
    `Se ha analizado ${report.target} mediante un pipeline automatizado de reconocimiento, validacion y correlacion de hallazgos web.`,
    `Las herramientas registradas incluyen ${tools}. GF se trata como priorizador de candidatos y no como confirmacion de vulnerabilidades.`,
    `El nivel de riesgo general es ${report.risk.label} con score ${text(report.risk.score, 'N/D')}/100. Se identificaron ${report.groups.confirmed.length} vulnerabilidades confirmadas y ${report.groups.possible.length} posibles vulnerabilidades que requieren validacion manual o evidencia adicional.`,
    `Tambien se han separado ${report.groups.gfCandidates.length} candidatos GF, ${report.groups.hardening.length} hallazgos de hardening y ${report.groups.attackSurface.length} elementos de superficie de ataque para mantener trazabilidad sin exagerar la criticidad.`
  ].join('\n\n');

  doc.font(FONTS.regular).fontSize(9.4);
  const paragraphHeight = doc.heightOfString(paragraph, {
    width: PAGE.contentWidth - 36,
    lineGap: 3,
    align: 'justify'
  });
  const panelHeight = Math.max(154, paragraphHeight + 40);
  ensureSpace(doc, panelHeight + 18);

  const y = doc.y;
  panel(doc, left, y, PAGE.contentWidth, panelHeight, { fill: COLORS.panel });
  doc.font(FONTS.regular).fontSize(9.4).fillColor(COLORS.text).text(paragraph, left + 18, y + 18, {
    width: PAGE.contentWidth - 36,
    lineGap: 3,
    align: 'justify'
  });
  doc.y = y + panelHeight + 18;
}

function drawMetrics(doc, report) {
  const cols = 4;
  const gap = 10;
  const cardWidth = (PAGE.contentWidth - (gap * (cols - 1))) / cols;
  const cardHeight = 58;
  const rows = Math.ceil(report.metrics.length / cols);

  ensureSpace(doc, 78 + rows * (cardHeight + gap));
  sectionTitle(doc, 'Panel de metricas', 'Indicadores');
  const { left } = pageBounds(doc);
  const startY = doc.y;

  report.metrics.forEach((item, index) => {
    const row = Math.floor(index / cols);
    const col = index % cols;
    const x = left + col * (cardWidth + gap);
    const y = startY + row * (cardHeight + gap);
    panel(doc, x, y, cardWidth, cardHeight, { fill: COLORS.panelSoft, accent: severityColor(item.accent) });
    doc.font(FONTS.bold).fontSize(19).fillColor(COLORS.text);
    fixedText(doc, String(item.value), x + 12, y + 12, { width: cardWidth - 24, height: 22 });
    doc.font(FONTS.regular).fontSize(7.5).fillColor(COLORS.muted);
    fixedText(doc, item.label, x + 12, y + 37, { width: cardWidth - 24, height: 10 });
  });

  doc.y = startY + rows * (cardHeight + gap) + 8;
}

function drawCharts(doc, report) {
  ensureSpace(doc, 410);
  sectionTitle(doc, 'Graficas', 'Visualizacion');
  ensureSpace(doc, 340);
  const { left } = pageBounds(doc);
  const gap = 12;
  const half = (PAGE.contentWidth - gap) / 2;
  const y = doc.y;
  const chartPanelHeight = 216;

  panel(doc, left, y, half, chartPanelHeight, { fill: COLORS.panel });
  doc.font(FONTS.bold).fontSize(10).fillColor(COLORS.text).text('Distribucion global por severidad', left + 14, y + 14, { width: half - 28 });
  drawSeverityBars(doc, left + 14, y + 42, half - 28, report.groups.severity);

  panel(doc, left + half + gap, y, half, chartPanelHeight, { fill: COLORS.panel });
  doc.font(FONTS.bold).fontSize(10).fillColor(COLORS.text).text('Resultados tecnicos por herramienta', left + half + gap + 14, y + 14, { width: half - 28 });
  drawDonutChart(doc, left + half + gap + 16, y + 40, 76, report.toolChart, {
    maxItems: 6,
    label: 'total',
    innerColor: COLORS.panel,
    colors: [COLORS.low, COLORS.high, COLORS.medium, COLORS.info, COLORS.critical, COLORS.success, COLORS.borderSoft]
  });
  const toolChartHeight = drawHorizontalChart(doc, left + half + gap + 100, y + 42, half - 114, report.toolChart, {
    maxItems: 6,
    colors: [COLORS.low, COLORS.medium, COLORS.high, COLORS.success, COLORS.info]
  });
  const noteY = Math.min(y + chartPanelHeight - 34, y + 42 + toolChartHeight + 12);
  doc.font(FONTS.regular).fontSize(6.8).fillColor(COLORS.subtle)
    .text('Incluye resultados tecnicos, candidatos y hardening; no todos son vulnerabilidades confirmadas.', left + half + gap + 14, noteY, { width: half - 28 });

  doc.y = y + chartPanelHeight + 16;
  ensureSpace(doc, 112);
  panel(doc, left, doc.y, PAGE.contentWidth, 96, { fill: COLORS.panel });
  doc.font(FONTS.bold).fontSize(10).fillColor(COLORS.text).text('Score global de riesgo', left + 16, doc.y + 14);
  drawRiskGauge(doc, left + 16, doc.y + 42, PAGE.contentWidth - 32, report.risk.score);
  doc.y += 112;
}

function drawFindingsSummaryTable(doc, report) {
  sectionTitle(doc, 'Tabla resumen de vulnerabilidades', 'Trazabilidad');
  const rows = [...report.groups.confirmed, ...report.groups.possible];
  const { left } = pageBounds(doc);
  const widths = [58, 156, 62, 154, 58, 55];
  const headers = ['Severidad', 'Titulo', 'Tool', 'Activo', 'Conf.', 'Estado'];

  if (!rows.length) {
    emptyPanel(doc, 'No hay vulnerabilidades confirmadas o posibles que listar.');
    return;
  }

  drawTableHeader(doc, left, widths, headers);
  rows.forEach(finding => {
    ensureSpace(doc, 34);
    const y = doc.y;
    doc.rect(left, y, PAGE.contentWidth, 30).fill(COLORS.panelAlt);
    doc.moveTo(left, y + 30).lineTo(left + PAGE.contentWidth, y + 30).strokeColor(COLORS.borderSoft).lineWidth(0.5).stroke();
    const state = report.groups.confirmed.includes(finding) ? 'Confirmada' : 'Posible';
    const finalSeverity = getFinalSeverity(finding);
    const values = [
      severityLabel(finalSeverity),
      truncate(finding.title, 58),
      text(finding.tool, '-'),
      truncate(getAsset(finding), 64),
      text(finding.confidence, '-'),
      state
    ];
    let x = left;
    values.forEach((value, index) => {
      const color = index === 0 ? severityColor(finalSeverity) : COLORS.text;
      doc.font(index === 0 ? FONTS.bold : FONTS.regular).fontSize(7.2).fillColor(color);
      fixedText(doc, value, x + 6, y + 9, { width: widths[index] - 10, height: 9 });
      x += widths[index];
    });
    doc.y += 30;
  });
  doc.moveDown(0.7);
}

function drawTableHeader(doc, x, widths, headers) {
  ensureSpace(doc, 30);
  const y = doc.y;
  doc.rect(x, y, PAGE.contentWidth, 24).fill(COLORS.borderSoft);
  let cursorX = x;
  headers.forEach((header, index) => {
    doc.font(FONTS.bold).fontSize(7).fillColor(COLORS.muted);
    fixedText(doc, header.toUpperCase(), cursorX + 6, y + 8, { width: widths[index] - 10, height: 9 });
    cursorX += widths[index];
  });
  doc.y += 24;
}

function emptyPanel(doc, message) {
  const { left } = pageBounds(doc);
  ensureSpace(doc, 58);
  panel(doc, left, doc.y, PAGE.contentWidth, 46, { fill: COLORS.panel });
  doc.font(FONTS.regular).fontSize(9).fillColor(COLORS.muted).text(message, left + 14, doc.y + 17, { width: PAGE.contentWidth - 28 });
  doc.y += 58;
}

function findingHeight(doc, finding) {
  const titleHeight = doc.font(FONTS.bold).fontSize(12).heightOfString(text(finding.title, 'Hallazgo sin titulo'), { width: PAGE.contentWidth - 32 });
  const assetHeight = doc.font(FONTS.regular).fontSize(8).heightOfString(text(getAsset(finding)), { width: PAGE.contentWidth - 32 });
  const evidenceHeight = doc.font(FONTS.mono).fontSize(7).heightOfString(text(finding.evidence || finding.raw_reference, 'Sin evidencia detallada disponible.'), { width: PAGE.contentWidth - 32, lineGap: 1 });
  const colW = (PAGE.contentWidth - 46) / 2;
  const impactHeight = doc.font(FONTS.regular).fontSize(7.5).heightOfString(text(buildImpactText(finding), 'No disponible'), { width: colW });
  const recHeight = doc.font(FONTS.regular).fontSize(7.5).heightOfString(text(finding.recommendation, 'No disponible'), { width: colW });
  const correlationHeight = safeArray(finding.correlation_notes).length
    ? doc.font(FONTS.regular).fontSize(7).heightOfString(`Correlacion: ${truncate(finding.correlation_notes.join(' | '), 160)}`, { width: PAGE.contentWidth - 32 })
    : 0;

  return Math.max(
    170,
    30 + titleHeight + 34 + 34 + assetHeight + 28 + Math.max(evidenceHeight, 20) + 30 + Math.max(impactHeight, recHeight, 20) + correlationHeight + 42
  );
}

function drawFindingCard(doc, finding, state) {
  const { left } = pageBounds(doc);
  const height = findingHeight(doc, finding);
  ensureSpace(doc, height + 14);
  const y = doc.y;
  const sev = getFinalSeverity(finding);

  panel(doc, left, y, PAGE.contentWidth, height, { fill: COLORS.panel, accent: severityColor(sev) });
  chip(doc, left + 16, y + 14, severityLabel(sev).toUpperCase(), severityColor(sev));
  chip(doc, left + 96, y + 14, state.toUpperCase(), state === 'Confirmada' ? COLORS.success : COLORS.medium);
  doc.font(FONTS.bold).fontSize(12).fillColor(COLORS.text).text(text(finding.title, 'Hallazgo sin titulo'), left + 16, y + 40, {
    width: PAGE.contentWidth - 32
  });
  const titleBottom = doc.y;

  const metaY = Math.max(y + 74, titleBottom + 10);
  smallMeta(doc, 'Herramienta', finding.tool, left + 16, metaY, 110);
  smallMeta(doc, 'Confianza', finding.confidence, left + 134, metaY, 90);
  smallMeta(doc, 'CWE', finding.cwe, left + 234, metaY, 72);
  smallMeta(doc, 'CVSS', finding.cvss, left + 314, metaY, 64);
  smallMeta(doc, 'OWASP', finding.owasp || finding.owasp_top10, left + 384, metaY, 118);

  const assetY = metaY + 38;
  doc.font(FONTS.bold).fontSize(7).fillColor(COLORS.subtle).text('ACTIVO AFECTADO', left + 16, assetY);
  doc.font(FONTS.regular).fontSize(8).fillColor(COLORS.text).text(text(getAsset(finding)), left + 16, assetY + 12, { width: PAGE.contentWidth - 32 });
  const assetBottom = doc.y;

  const evidenceY = assetBottom + 14;
  doc.font(FONTS.bold).fontSize(7).fillColor(COLORS.subtle).text('EVIDENCIA TECNICA', left + 16, evidenceY);
  doc.font(FONTS.mono).fontSize(7).fillColor(COLORS.muted).text(text(finding.evidence || finding.raw_reference, 'Sin evidencia detallada disponible.'), left + 16, evidenceY + 12, {
    width: PAGE.contentWidth - 32,
    lineGap: 1
  });
  const evidenceBottom = doc.y;

  const bottomY = evidenceBottom + 18;
  const colW = (PAGE.contentWidth - 46) / 2;
  doc.font(FONTS.bold).fontSize(7).fillColor(COLORS.subtle).text('IMPACTO', left + 16, bottomY);
  doc.font(FONTS.regular).fontSize(7.5).fillColor(COLORS.text).text(text(buildImpactText(finding), 'No disponible'), left + 16, bottomY + 11, { width: colW });
  const impactBottom = doc.y;
  doc.font(FONTS.bold).fontSize(7).fillColor(COLORS.subtle).text('SOLUCION RECOMENDADA', left + 28 + colW, bottomY);
  doc.font(FONTS.regular).fontSize(7.5).fillColor(COLORS.text).text(text(finding.recommendation, 'No disponible'), left + 28 + colW, bottomY + 11, { width: colW });
  const recommendationBottom = doc.y;

  let extraBottom = Math.max(impactBottom, recommendationBottom);
  if (safeArray(finding.correlation_notes).length) {
    const correlationY = extraBottom + 12;
    doc.font(FONTS.regular).fontSize(7).fillColor(COLORS.low)
      .text(`Correlacion: ${truncate(finding.correlation_notes.join(' | '), 160)}`, left + 16, correlationY, { width: PAGE.contentWidth - 32 });
  }

  doc.y = y + height + 12;
}

function drawFindingSection(doc, title, kicker, findings, state, emptyMessage) {
  sectionTitle(doc, title, kicker);
  if (!findings.length) {
    emptyPanel(doc, emptyMessage);
    return;
  }
  findings.forEach(finding => drawFindingCard(doc, finding, state));
}

function drawNotePanel(doc, message, accent = COLORS.info) {
  const { left } = pageBounds(doc);
  ensureSpace(doc, 64);
  panel(doc, left, doc.y, PAGE.contentWidth, 50, { fill: COLORS.panelAlt, accent });
  doc.font(FONTS.regular).fontSize(8.5).fillColor(COLORS.muted).text(message, left + 16, doc.y + 14, {
    width: PAGE.contentWidth - 32,
    lineGap: 2
  });
  doc.y += 62;
}

function drawGfCandidates(doc, report) {
  sectionTitle(doc, 'Candidatos priorizados por GF', 'Validacion manual');
  drawNotePanel(
    doc,
    'Estos elementos no son vulnerabilidades confirmadas. GF solo prioriza URLs que coinciden con patrones habituales. Requieren validacion manual o confirmacion por herramientas como Dalfox, SQLMap o Nuclei.',
    COLORS.info
  );

  if (!report.groups.gfCandidates.length) {
    emptyPanel(doc, 'No se identificaron candidatos GF.');
    return;
  }

  report.groups.gfCandidates.forEach(finding => drawFindingCard(doc, finding, 'Candidato GF'));
}

function drawHardening(doc, report) {
  drawFindingSection(
    doc,
    'Hardening y configuracion defensiva',
    'Defensa',
    report.groups.hardening,
    'Hardening',
    'No se identificaron problemas de hardening destacables.'
  );
}

function drawSurface(doc, report) {
  sectionTitle(doc, 'Superficie de ataque descubierta', 'Exposicion');
  const rows = report.interestingSurface.length ? report.interestingSurface : report.groups.attackSurface.slice(0, 45);

  if (!rows.length) {
    emptyPanel(doc, 'No se identifico superficie sensible destacable.');
    return;
  }

  const { left } = pageBounds(doc);
  const widths = [78, 122, 260, 60];
  drawTableHeader(doc, left, widths, ['Fuente', 'Tipo', 'Endpoint o activo', 'Sev.']);
  rows.forEach(finding => {
    ensureSpace(doc, 31);
    const y = doc.y;
    doc.rect(left, y, PAGE.contentWidth, 28).fill(COLORS.panelAlt);
    doc.moveTo(left, y + 28).lineTo(left + PAGE.contentWidth, y + 28).strokeColor(COLORS.borderSoft).lineWidth(0.5).stroke();
    const finalSeverity = getFinalSeverity(finding);
    const values = [
      text(finding.tool, '-'),
      truncate(finding.title, 44),
      truncate(getAsset(finding), 106),
      severityLabel(finalSeverity)
    ];
    let x = left;
    values.forEach((value, index) => {
      doc.font(index === 3 ? FONTS.bold : FONTS.regular).fontSize(7.2)
        .fillColor(index === 3 ? severityColor(finalSeverity) : COLORS.text);
      fixedText(doc, value, x + 6, y + 8, { width: widths[index] - 10, height: 9 });
      x += widths[index];
    });
    doc.y += 28;
  });
  doc.moveDown(0.7);
}

function drawCorrelations(doc, report) {
  sectionTitle(doc, 'Correlaciones', 'Contexto');
  if (!report.correlations.length) {
    emptyPanel(doc, 'No se detectaron correlaciones automaticas destacables.');
    return;
  }
  const { left } = pageBounds(doc);
  report.correlations.forEach(correlation => {
    ensureSpace(doc, 78);
    const y = doc.y;
    panel(doc, left, y, PAGE.contentWidth, 66, { fill: COLORS.panel, accent: severityColor(correlation.severity) });
    chip(doc, left + 14, y + 14, severityLabel(correlation.severity).toUpperCase(), severityColor(correlation.severity));
    doc.font(FONTS.bold).fontSize(10).fillColor(COLORS.text).text(truncate(correlation.title, 86), left + 96, y + 15, { width: PAGE.contentWidth - 112 });
    doc.font(FONTS.regular).fontSize(8).fillColor(COLORS.muted).text(truncate(correlation.description, 180), left + 14, y + 36, { width: PAGE.contentWidth - 28 });
    doc.font(FONTS.mono).fontSize(7).fillColor(COLORS.low).text(`Cadena: ${safeArray(correlation.chain).join(' -> ') || 'No disponible'}`, left + 14, y + 53, { width: PAGE.contentWidth - 28 });
    doc.y += 78;
  });
}

function drawRecommendations(doc, report) {
  sectionTitle(doc, 'Recomendaciones priorizadas', 'Remediacion');
  const groups = [
    ['Acciones criticas inmediatas', report.recommendations.critical, COLORS.critical],
    ['Acciones de corto plazo', report.recommendations.shortTerm, COLORS.high],
    ['Mejoras de hardening', report.recommendations.hardening, COLORS.low],
    ['Validaciones manuales recomendadas', report.recommendations.manual, COLORS.medium]
  ];

  groups.forEach(([title, items, color]) => {
    drawBulletPanel(doc, title, items, color);
  });
}

function drawBulletPanel(doc, title, items, accent) {
  const { left } = pageBounds(doc);
  const content = safeArray(items).slice(0, 10);
  const height = 42 + content.reduce((sum, item) => sum + Math.max(15, doc.heightOfString(truncate(item, 150), { width: PAGE.contentWidth - 52 }) + 4), 0);
  ensureSpace(doc, Math.min(height, 220) + 10);
  const y = doc.y;
  panel(doc, left, y, PAGE.contentWidth, Math.min(height, 220), { fill: COLORS.panel, accent });
  doc.font(FONTS.bold).fontSize(10).fillColor(COLORS.text).text(title, left + 16, y + 14, { width: PAGE.contentWidth - 32 });
  let cursorY = y + 36;
  content.forEach(item => {
    doc.circle(left + 22, cursorY + 4, 2.2).fill(accent);
    doc.font(FONTS.regular).fontSize(8).fillColor(COLORS.muted).text(truncate(item, 150), left + 32, cursorY, {
      width: PAGE.contentWidth - 48,
      lineGap: 2
    });
    cursorY += Math.max(15, doc.heightOfString(truncate(item, 150), { width: PAGE.contentWidth - 52 }) + 5);
  });
  doc.y = y + Math.min(height, 220) + 12;
}

function drawTechnicalAnnex(doc, report) {
  sectionTitle(doc, 'Anexo tecnico', 'Ejecucion');
  drawTimeline(doc, report);
  drawToolStatus(doc, report);
  drawLimitations(doc, report);
}

function drawTimeline(doc, report) {
  const items = report.timeline;
  if (!items.length) {
    emptyPanel(doc, 'No hay timeline registrado.');
    return;
  }
  const { left } = pageBounds(doc);
  ensureSpace(doc, 44);
  doc.font(FONTS.bold).fontSize(10).fillColor(COLORS.text)
    .text('Herramientas ejecutadas y estado', left, doc.y, { width: PAGE.contentWidth });
  doc.moveDown(0.5);

  items.forEach(item => {
    const extras = [
      item.warning ? `Warning: ${item.warning}` : null,
      item.error ? `Error: ${item.error}` : null
    ].filter(Boolean);
    const detail = `[${text(item.status, '--').toUpperCase()}] ${text(item.tool, '--')} - ${text(item.detail, 'sin datos')}${item.duration_ms ? ` (${item.duration_ms} ms)` : ''}`;
    const extraText = extras.join(' | ');
    const rowHeight = extraText ? 46 : 32;

    ensureSpace(doc, rowHeight + 8);
    const y = doc.y;
    const color = item.status === 'error'
      ? COLORS.critical
      : item.status === 'partial'
        ? COLORS.medium
        : item.status === 'success'
          ? COLORS.success
          : COLORS.info;

    panel(doc, left, y, PAGE.contentWidth, rowHeight, { fill: COLORS.panelAlt, accent: color });
    doc.font(FONTS.mono).fontSize(7.4).fillColor(COLORS.text)
      .text(detail, left + 14, y + 10, { width: PAGE.contentWidth - 28 });
    if (extraText) {
      doc.font(FONTS.regular).fontSize(7).fillColor(COLORS.muted)
        .text(truncate(extraText, 175), left + 14, y + 26, { width: PAGE.contentWidth - 28 });
    }
    doc.y = y + rowHeight + 6;
  });
}

function drawToolStatus(doc, report) {
  const counters = report.toolCounters || {};
  const items = Object.entries(counters).map(([tool, values]) => {
    const summary = Object.entries(values || {})
      .slice(0, 5)
      .map(([key, value]) => `${key}=${value}`)
      .join(', ');
    return `${tool}: ${summary || 'sin contadores disponibles'}`;
  });
  drawBulletPanel(doc, 'Contadores por herramienta', items.length ? items : ['No hay contadores por herramienta disponibles.'], COLORS.info);
}

function drawLimitations(doc, report = {}) {
  drawBulletPanel(doc, 'Limitaciones del analisis', [
    'Los resultados automatizados dependen de la accesibilidad del objetivo, permisos, WAF, timeouts y profundidad configurada.',
    'Los candidatos de GF y superficie descubierta requieren validacion manual antes de tratarlos como vulnerabilidades confirmadas.',
    'No se generan CVE, CVSS, CWE u OWASP si no existen en la evidencia recibida.',
    ...safeArray(report.limitations)
  ], COLORS.medium);

  drawBulletPanel(doc, 'Nota etica y legal', [
    'Este analisis debe ejecutarse unicamente sobre sistemas propios o con autorizacion expresa.',
    'El informe debe usarse para remediacion defensiva y mejora de seguridad.'
  ], COLORS.success);
}

function drawHeaderFooter(doc, report) {
  const range = doc.bufferedPageRange();
  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);
    const { left, right, height } = pageBounds(doc);
    const pageNumber = i + 1;

    doc.rect(0, 0, doc.page.width, 34).fillOpacity(0.82).fill(COLORS.bg);
    doc.fillOpacity(1);
    doc.font(FONTS.bold).fontSize(7).fillColor(COLORS.muted);
    fixedText(doc, 'Informe de Auditoria Web', left, 14, { width: 170, height: 9 });
    doc.font(FONTS.regular).fontSize(7).fillColor(COLORS.subtle);
    fixedText(doc, truncate(report.target, 64), left + 180, 14, { width: 210, align: 'center', height: 9 });
    fixedText(doc, report.generatedAtLabel, right - 120, 14, { width: 120, align: 'right', height: 9 });

    doc.rect(0, height - 30, doc.page.width, 30).fillOpacity(0.82).fill(COLORS.bg);
    doc.fillOpacity(1);
    doc.moveTo(left, height - 30).lineTo(right, height - 30).strokeColor(COLORS.border).lineWidth(0.5).stroke();
    doc.font(FONTS.regular).fontSize(7).fillColor(COLORS.subtle);
    fixedText(doc, 'Documento tecnico generado desde datos reales del analisis.', left, height - 20, { width: 280, height: 9 });
    doc.font(FONTS.bold).fontSize(7).fillColor(COLORS.muted);
    fixedText(doc, `${pageNumber}/${range.count}`, right - 50, height - 20, { width: 50, align: 'right', height: 9 });
  }
}

module.exports = {
  drawCharts,
  drawCover,
  drawExecutiveSummary,
  drawFindingSection,
  drawGfCandidates,
  drawFindingsSummaryTable,
  drawHardening,
  drawHeaderFooter,
  drawMetrics,
  drawPageBackground,
  drawRecommendations,
  drawSurface,
  drawCorrelations,
  drawTechnicalAnnex,
  ensureSpace
};
