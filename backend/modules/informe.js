const { resumenSeveridad } = require('./normalizacion');
const HARDENING_TYPES = new Set([
  'missing_security_header',
  'insecure_cookie',
  'missing_https_redirect',
  'tls_certificate_issue'
]);

function agruparPorHerramienta(findings) {
  return findings.reduce((grupos, finding) => {
    const tool = finding.tool || 'otra';
    if (!grupos[tool]) grupos[tool] = [];
    grupos[tool].push(finding);
    return grupos;
  }, {});
}

function esConfirmada(finding) {
  return finding.isVulnerability === true &&
    finding.confidence === 'high' &&
    !HARDENING_TYPES.has(finding.type) &&
    finding.isFalsePositiveLikely !== true;
}

function esPosible(finding) {
  return finding.isVulnerability === true &&
    finding.confidence === 'medium' &&
    !HARDENING_TYPES.has(finding.type) &&
    finding.isFalsePositiveLikely !== true;
}

function lineaFinding(finding) {
  const relaciones = Array.isArray(finding.correlation_notes) && finding.correlation_notes.length
    ? `\n- Relaciones: ${finding.correlation_notes.join(' | ')}`
    : '';

  return [
    `### ${finding.title}`,
    '',
    `- Herramienta: ${finding.tool}`,
    `- Activo: ${finding.affected_url || finding.affected_asset || 'sin activo'}`,
    `- Severidad: ${finding.severity}`,
    `- Confianza: ${finding.confidence}`,
    `- Evidencia: ${finding.evidence || 'Sin evidencia detallada.'}`,
    `- Impacto: ${finding.impact || 'Requiere validacion segun el contexto del activo.'}`,
    `- Recomendacion: ${finding.recommendation || 'Aplicar la remediacion especifica tras validar el hallazgo.'}${relaciones}`
  ].join('\n');
}

function listaAnexo(findings, fallback) {
  if (!findings.length) return fallback;

  return findings.map(finding =>
    `- [${finding.tool}] ${finding.title} - ${finding.affected_url || finding.affected_asset || 'sin activo'}`
  ).join('\n');
}

function generarResumenEjecutivo(target, confirmadas, posibles, superficie, reconocimiento, descartados, contexto = {}) {
  const reportables = [...confirmadas, ...posibles];
  const summary = resumenSeveridad(reportables);
  const herramientas = Object.keys(contexto.toolResults || {}).join(', ') || 'herramientas automatizadas configuradas';

  const score = contexto.risk_score === null || contexto.risk_score === undefined
    ? 'N/D'
    : `${contexto.risk_score}/100`;
  const riskLevel = contexto.risk_level || 'N/D';
  const riskGrade = contexto.risk_grade || 'N/D';

  return `# Informe de analisis de seguridad web

## Resumen ejecutivo

Objetivo analizado: ${target}

Riesgo final: ${score} [${String(riskLevel).toUpperCase()}] - grado ${riskGrade}.

Se han identificado ${reportables.length} vulnerabilidades reportables: ${confirmadas.length} confirmadas y ${posibles.length} posibles.

Distribucion por severidad de vulnerabilidades reportables: critical=${summary.critical}, high=${summary.high}, medium=${summary.medium}, low=${summary.low}.

Herramientas utilizadas: ${herramientas}.

La cobertura se amplio con fuentes historicas y fuerza bruta controlada cuando estaban disponibles, manteniendo esos resultados separados de las vulnerabilidades.

La superficie descubierta (${superficie.length}), el reconocimiento informativo (${reconocimiento.length}) y los falsos positivos o descartados (${descartados.length}) se incluyen solo como anexos y no forman parte del conteo principal de vulnerabilidades.
`;
}

function generarSeccionScore(contexto = {}) {
  const score = contexto.risk_score === null || contexto.risk_score === undefined
    ? 'N/D'
    : `${contexto.risk_score}/100`;
  return `## Score final de riesgo

Risk score: ${score}

Nivel: ${contexto.risk_level || 'N/D'}

Grado: ${contexto.risk_grade || 'N/D'}

El score usa riesgo acumulado: 0 representa ausencia de riesgo significativo y 100 representa riesgo critico.
`;
}

function generarTimeline(contexto = {}) {
  const items = Array.isArray(contexto.pipelineTimeline) ? contexto.pipelineTimeline : [];
  if (!items.length) return '## Pipeline de ejecucion\n\nNo hay timeline registrado.\n';

  return `## Pipeline de ejecucion

${items.map(item => `- [${String(item.status || '--').toUpperCase()}] ${item.tool}: ${item.detail || '--'} (${item.duration_ms ? `${item.duration_ms} ms` : '--'})`).join('\n')}
`;
}

function generarCorrelaciones(contexto = {}) {
  const correlations = Array.isArray(contexto.correlations) ? contexto.correlations : [];
  if (!correlations.length) return '## Correlaciones detectadas\n\nNo se detectaron correlaciones automaticas destacables.\n';

  return `## Correlaciones detectadas

${correlations.map(correlation => [
    `- [${String(correlation.severity || 'info').toUpperCase()}] ${correlation.title}`,
    `  - Cadena: ${(correlation.chain || []).join(' -> ') || '--'}`,
    `  - ${correlation.description || '-'}`
  ].join('\n')).join('\n')}
`;
}

function generarSeccion(titulo, findings, vacio) {
  if (!findings.length) return `## ${titulo}\n\n${vacio}\n`;
  return `## ${titulo}\n\n${findings.map(lineaFinding).join('\n\n')}\n`;
}

function generarRecomendacionesPrioritarias(confirmadas, posibles) {
  const reportables = [...confirmadas, ...posibles];

  if (!reportables.length) {
    return '## Recomendaciones prioritarias\n\nNo hay vulnerabilidades reportables que priorizar.\n';
  }

  const orden = ['critical', 'high', 'medium', 'low', 'info'];
  const lineas = reportables
    .slice()
    .sort((a, b) => orden.indexOf(a.severity) - orden.indexOf(b.severity))
    .map(finding => `- [${finding.severity.toUpperCase()}] ${finding.title}: ${finding.recommendation || 'Validar y corregir segun evidencia.'}`);

  return `## Recomendaciones prioritarias\n\n${lineas.join('\n')}\n`;
}

function generarAnexoGf(gfCandidates = {}) {
  const entradas = Object.entries(gfCandidates);
  if (!entradas.length) return '## Anexo: candidatos priorizados por GF\n\nNo hay candidatos GF registrados.\n';

  const lineas = entradas.map(([tipo, urls]) => {
    const listado = (Array.isArray(urls) ? urls : [])
      .slice(0, 20)
      .map(url => `  - ${url}`)
      .join('\n') || '  - Sin candidatos';
    return `- ${tipo}\n${listado}`;
  });

  return `## Anexo: candidatos priorizados por GF\n\nGF se usa para priorizacion y no confirma vulnerabilidades.\n\n${lineas.join('\n')}\n`;
}

function generarAnexoHerramienta(titulo, findings, fallback) {
  if (!findings.length) return `## ${titulo}\n\n${fallback}\n`;

  const lineas = findings.slice(0, 50).map(finding => [
    `- ${finding.title}`,
    `  - Activo: ${finding.affected_url || finding.affected_asset || 'sin activo'}`,
    `  - Tipo: ${finding.type || 'n/a'}`,
    `  - Severidad/confianza: ${finding.severity}/${finding.confidence}`,
    `  - Evidencia: ${finding.evidence || 'Sin evidencia detallada.'}`
  ].join('\n'));

  return `## ${titulo}\n\n${lineas.join('\n')}\n`;
}

async function generarInformeDesdeFindings(target, findings, contexto = {}) {
  const confirmadas = findings.filter(esConfirmada);
  const posibles = findings.filter(esPosible);
  const superficie = findings.filter(f => f.type === 'surface');
  const reconocimiento = findings.filter(f =>
    (f.isVulnerability === false || f.type === 'reconocimiento') &&
    !['surface', 'discarded'].includes(f.type)
  );
  const descartados = findings.filter(f =>
    f.type === 'discarded' ||
    f.isFalsePositiveLikely ||
    (f.isVulnerability === true && f.confidence === 'low')
  );
  const hardening = findings.filter(f => HARDENING_TYPES.has(f.type));
  const feroxFindings = findings.filter(f => f.tool === 'feroxbuster');
  const gauFindings = findings.filter(f => f.tool === 'gau');
  const gfFindings = findings.filter(f => f.tool === 'gf');
  const trufflehogFindings = findings.filter(f => f.tool === 'trufflehog');
  const passiveFindings = findings.filter(f =>
    ['headers', 'cookies', 'httpsredirect', 'tls', 'robotssitemap', 'ports'].includes(f.tool)
  );

  const secciones = [
    generarResumenEjecutivo(target, confirmadas, posibles, superficie, reconocimiento, descartados, contexto),
    generarSeccionScore(contexto),
    generarTimeline(contexto),
    generarCorrelaciones(contexto),
    generarSeccion('Vulnerabilidades confirmadas', confirmadas, 'No se identificaron vulnerabilidades confirmadas.'),
    generarSeccion('Posibles vulnerabilidades', posibles, 'No se identificaron posibles vulnerabilidades con evidencia suficiente.'),
    generarSeccion('Hardening y configuracion defensiva', hardening, 'No se identificaron problemas de hardening destacables.'),
    generarRecomendacionesPrioritarias(confirmadas, posibles),
    generarAnexoHerramienta('Anexo: analisis pasivo defensivo', passiveFindings, 'No hay hallazgos pasivos defensivos registrados.'),
    generarAnexoHerramienta('Anexo: Feroxbuster - rutas descubiertas y sensibles', feroxFindings, 'Feroxbuster no registro rutas destacables o no se ejecuto.'),
    generarAnexoHerramienta('Anexo: GAU - URLs historicas y parametrizadas', gauFindings, 'GAU no registro URLs historicas destacables o no se ejecuto.'),
    generarAnexoGf(contexto.gfCandidates || {}),
    generarAnexoHerramienta('Anexo: GF - candidatos por patron', gfFindings, 'GF no registro candidatos o no se ejecuto.'),
    generarAnexoHerramienta('Anexo: TruffleHog - secretos detectados', trufflehogFindings, 'TruffleHog no detecto secretos o no se ejecuto. Los valores completos de secretos nunca se incluyen en el informe.'),
    `## Anexo: superficie descubierta\n\n${listaAnexo(superficie, 'No se identifico superficie sensible destacable.')}\n`,
    `## Anexo: reconocimiento informativo\n\n${listaAnexo(reconocimiento, 'No se identificaron hallazgos informativos relevantes.')}\n`,
    `## Anexo: falsos positivos o descartados\n\n${listaAnexo(descartados, 'No hay elementos descartados relevantes.')}\n`
  ];

  return secciones.join('\n\n');
}

module.exports = {
  generarInformeDesdeFindings,
  agruparPorHerramienta
};
