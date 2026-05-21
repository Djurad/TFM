const { resumenSeveridad } = require('./normalizacion');

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
    finding.isFalsePositiveLikely !== true;
}

function esPosible(finding) {
  return finding.isVulnerability === true &&
    finding.confidence === 'medium' &&
    finding.isFalsePositiveLikely !== true;
}

function lineaFinding(finding) {
  return [
    `### ${finding.title}`,
    '',
    `- Herramienta: ${finding.tool}`,
    `- Activo: ${finding.affected_url || finding.affected_asset || 'sin activo'}`,
    `- Severidad: ${finding.severity}`,
    `- Confianza: ${finding.confidence}`,
    `- Evidencia: ${finding.evidence || 'Sin evidencia detallada.'}`,
    `- Impacto: ${finding.impact || 'Requiere validacion segun el contexto del activo.'}`,
    `- Recomendacion: ${finding.recommendation || 'Aplicar la remediacion especifica tras validar el hallazgo.'}`
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

  return `# Informe de analisis de seguridad web

## Resumen ejecutivo

Objetivo analizado: ${target}

Se han identificado ${reportables.length} vulnerabilidades reportables: ${confirmadas.length} confirmadas y ${posibles.length} posibles.

Distribucion por severidad de vulnerabilidades reportables: critical=${summary.critical}, high=${summary.high}, medium=${summary.medium}, low=${summary.low}.

Herramientas utilizadas: ${herramientas}.

La cobertura se amplio con fuentes historicas y fuerza bruta controlada cuando estaban disponibles, manteniendo esos resultados separados de las vulnerabilidades.

La superficie descubierta (${superficie.length}), el reconocimiento informativo (${reconocimiento.length}) y los falsos positivos o descartados (${descartados.length}) se incluyen solo como anexos y no forman parte del conteo principal de vulnerabilidades.
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

  const secciones = [
    generarResumenEjecutivo(target, confirmadas, posibles, superficie, reconocimiento, descartados, contexto),
    generarSeccion('Vulnerabilidades confirmadas', confirmadas, 'No se identificaron vulnerabilidades confirmadas.'),
    generarSeccion('Posibles vulnerabilidades', posibles, 'No se identificaron posibles vulnerabilidades con evidencia suficiente.'),
    generarRecomendacionesPrioritarias(confirmadas, posibles),
    generarAnexoGf(contexto.gfCandidates || {}),
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
