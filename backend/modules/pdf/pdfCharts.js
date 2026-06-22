const { COLORS, SEVERITY, FONTS } = require('./pdfStyles');
const { percentage } = require('./pdfUtils');

function fixedText(doc, value, x, y, options = {}) {
  const previous = { x: doc.x, y: doc.y };
  doc.text(String(value), x, y, {
    lineBreak: false,
    height: options.height || 12,
    ...options
  });
  doc.x = previous.x;
  doc.y = previous.y;
}

function drawSeverityBars(doc, x, y, width, data = {}) {
  const barWidth = width - 86;
  const max = Math.max(1, ...Object.values(data).map(Number));
  let cursorY = y;

  Object.keys(SEVERITY).forEach(key => {
    const value = Number(data[key] || 0);
    const fillWidth = Math.max(2, Math.round((value / max) * barWidth));
    const severity = SEVERITY[key];

    doc.font(FONTS.bold).fontSize(7).fillColor(COLORS.muted);
    fixedText(doc, severity.label, x, cursorY + 2, { width: 48 });
    doc.roundedRect(x + 54, cursorY, barWidth, 10, 5).fill(COLORS.borderSoft);
    if (value > 0) doc.roundedRect(x + 54, cursorY, fillWidth, 10, 5).fill(severity.color);
    doc.font(FONTS.bold).fontSize(8).fillColor(COLORS.text);
    fixedText(doc, String(value), x + 62 + barWidth, cursorY - 1, { width: 24, align: 'right' });
    cursorY += 18;
  });

  return cursorY - y;
}

function drawHorizontalChart(doc, x, y, width, items = [], options = {}) {
  const maxItems = options.maxItems || 8;
  const rows = items.slice(0, maxItems);
  const max = Math.max(1, ...rows.map(item => Number(item.value || 0)));
  const barWidth = width - 126;
  let cursorY = y;

  rows.forEach((item, index) => {
    const value = Number(item.value || 0);
    const fillWidth = Math.max(value > 0 ? 2 : 0, Math.round((value / max) * barWidth));
    const color = options.colors?.[index % options.colors.length] || COLORS.low;
    const label = String(item.label || '');
    const shortLabel = label.length > 15 ? `${label.slice(0, 12)}...` : label;

    doc.font(FONTS.regular).fontSize(7.5).fillColor(COLORS.muted);
    fixedText(doc, shortLabel, x, cursorY - 1, { width: 78 });
    doc.roundedRect(x + 84, cursorY, barWidth, 9, 4).fill(COLORS.borderSoft);
    if (fillWidth > 0) doc.roundedRect(x + 84, cursorY, fillWidth, 9, 4).fill(color);
    doc.font(FONTS.bold).fontSize(7.5).fillColor(COLORS.text);
    fixedText(doc, String(value), x + 90 + barWidth, cursorY - 1, { width: 32, align: 'right' });
    cursorY += 18;
  });

  if (!rows.length) {
    doc.font(FONTS.regular).fontSize(8).fillColor(COLORS.muted);
    fixedText(doc, 'Sin datos disponibles.', x, y, { width });
    return 16;
  }

  return cursorY - y;
}

function drawRiskGauge(doc, x, y, width, score) {
  const value = score === null || score === undefined ? null : Math.max(0, Math.min(100, Number(score)));
  const percent = value === null ? 0 : value / 100;
  const gradientStops = [
    { limit: 24, color: COLORS.low },
    { limit: 49, color: COLORS.success },
    { limit: 69, color: COLORS.medium },
    { limit: 89, color: COLORS.high },
    { limit: 100, color: COLORS.critical }
  ];
  const active = gradientStops.find(stop => value !== null && value <= stop.limit) || gradientStops[gradientStops.length - 1];
  const filled = Math.round(width * percent);

  doc.roundedRect(x, y, width, 16, 8).fill(COLORS.borderSoft);
  if (value !== null && filled > 0) {
    doc.roundedRect(x, y, Math.max(10, filled), 16, 8).fill(active.color);
  }

  [0, 25, 50, 75, 100].forEach(mark => {
    const markX = x + (width * mark / 100);
    doc.moveTo(markX, y + 20).lineTo(markX, y + 25).strokeColor(COLORS.border).lineWidth(0.5).stroke();
    doc.font(FONTS.regular).fontSize(6).fillColor(COLORS.subtle);
    fixedText(doc, String(mark), markX - 8, y + 27, { width: 16, align: 'center', height: 8 });
  });

  const label = value === null ? 'N/D' : `${Math.round(value)}/100`;
  doc.font(FONTS.bold).fontSize(8).fillColor(COLORS.white);
  fixedText(doc, label, x, y + 3, { width, align: 'center', height: 10 });

  return 40;
}

function drawDonutChart(doc, x, y, size, items = [], options = {}) {
  const colors = options.colors || [COLORS.low, COLORS.high, COLORS.medium, COLORS.info, COLORS.critical, COLORS.success, COLORS.borderSoft];
  const rows = items.slice(0, options.maxItems || 6);
  const rest = items.slice(options.maxItems || 6).reduce((sum, item) => sum + Number(item.value || 0), 0);
  const data = rest > 0 ? [...rows, { label: 'otros', value: rest }] : rows;
  const total = data.reduce((sum, item) => sum + Number(item.value || 0), 0);
  const cx = x + size / 2;
  const cy = y + size / 2;
  const radius = size / 2;
  let start = -90;

  if (total <= 0) {
    doc.circle(cx, cy, radius).fill(COLORS.borderSoft);
  } else {
    data.forEach((item, index) => {
      const value = Number(item.value || 0);
      if (value <= 0) return;
      const sweep = (value / total) * 360;
      const end = start + sweep;
      const steps = Math.max(3, Math.ceil(sweep / 8));

      doc.moveTo(cx, cy);
      for (let i = 0; i <= steps; i += 1) {
        const angle = (start + ((end - start) * i / steps)) * Math.PI / 180;
        const px = cx + Math.cos(angle) * radius;
        const py = cy + Math.sin(angle) * radius;
        if (i === 0) doc.lineTo(px, py);
        else doc.lineTo(px, py);
      }
      doc.closePath().fill(colors[index % colors.length]);
      start = end;
    });
  }

  doc.circle(cx, cy, radius * 0.58).fill(options.innerColor || COLORS.panel);
  doc.circle(cx, cy, radius).strokeColor(COLORS.borderSoft).lineWidth(0.6).stroke();
  doc.font(FONTS.bold).fontSize(options.valueSize || 11).fillColor(COLORS.text);
  fixedText(doc, String(total), x, y + size / 2 - 8, { width: size, align: 'center', height: 12 });
  doc.font(FONTS.regular).fontSize(5.8).fillColor(COLORS.muted);
  fixedText(doc, options.label || 'total', x, y + size / 2 + 5, { width: size, align: 'center', height: 8 });

  return size;
}

function drawDonutLegend(doc, x, y, items = [], total = 0) {
  let cursorY = y;
  items.forEach(item => {
    doc.circle(x + 4, cursorY + 4, 4).fill(item.color);
    doc.font(FONTS.regular).fontSize(7).fillColor(COLORS.muted);
    fixedText(doc, `${item.label}: ${item.value} (${percentage(item.value, total)}%)`, x + 14, cursorY - 1, { width: 145 });
    cursorY += 13;
  });
}

module.exports = {
  drawDonutChart,
  drawDonutLegend,
  drawHorizontalChart,
  drawRiskGauge,
  drawSeverityBars
};
