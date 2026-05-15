const { generarSeccionInformeIA } = require('./ia');
const { resumenSeveridad } = require('./normalizacion');

function agruparPorHerramienta(findings) {
  return findings.reduce((grupos, finding) => {
    const tool = finding.tool || 'otra';
    if (!grupos[tool]) grupos[tool] = [];
    grupos[tool].push(finding);
    return grupos;
  }, {});
}

function generarResumenEjecutivo(target, findings) {
  const summary = resumenSeveridad(findings);
  const total = findings.length;

  return `# Informe de analisis de seguridad web

## Resumen ejecutivo

Objetivo analizado: ${target}

Se han incluido ${total} hallazgos en el informe. Distribucion por severidad: critical=${summary.critical}, high=${summary.high}, medium=${summary.medium}, low=${summary.low}, info=${summary.info}.

El informe se genera exclusivamente a partir de los hallazgos estructurados obtenidos durante la fase de analisis. No se han vuelto a ejecutar herramientas para esta fase.
`;
}

function generarPriorizacion(findings) {
  if (!findings.length) {
    return '## Priorizacion\n\nNo hay hallazgos que priorizar.\n';
  }

  const orden = ['critical', 'high', 'medium', 'low', 'info'];
  const lineas = findings
    .slice()
    .sort((a, b) => orden.indexOf(a.severity) - orden.indexOf(b.severity))
    .map(finding => `- [${finding.severity.toUpperCase()}] ${finding.title} (${finding.tool}) - ${finding.affected_url || finding.affected_asset}`);

  return `## Priorizacion\n\n${lineas.join('\n')}\n`;
}

async function generarInformeDesdeFindings(target, findings) {
  const grupos = agruparPorHerramienta(findings);
  const secciones = [];

  secciones.push(generarResumenEjecutivo(target, findings));

  for (const [tool, hallazgos] of Object.entries(grupos)) {
    try {
      const seccion = await generarSeccionInformeIA(target, tool, hallazgos);
      secciones.push(seccion.trim());
    } catch (error) {
      secciones.push(`## ${tool}\n\nNo se pudo generar la seccion con IA: ${error.message}\n`);
    }
  }

  secciones.push(generarPriorizacion(findings));
  secciones.push('## Conclusion\n\nLa remediacion debe priorizar los hallazgos de mayor severidad y confianza, validando manualmente los casos probables o posibles antes de aplicar cambios en produccion.\n');

  return secciones.join('\n\n');
}

module.exports = {
  generarInformeDesdeFindings,
  agruparPorHerramienta
};
