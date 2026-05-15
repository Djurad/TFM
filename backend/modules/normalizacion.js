const CONFIDENCES = ['confirmed', 'probable', 'possible'];
const FALSE_POSITIVE_RISKS = ['low', 'medium', 'high'];

function limpiarTexto(valor, fallback = '') {
  if (valor === null || valor === undefined) return fallback;
  return String(valor).trim() || fallback;
}

function normalizarSeveridad(valor) {
  const lower = limpiarTexto(valor, 'info').toLowerCase();
  const mapa = {
    critico: 'critical',
    critica: 'critical',
    critical: 'critical',
    alto: 'high',
    alta: 'high',
    high: 'high',
    medio: 'medium',
    media: 'medium',
    medium: 'medium',
    bajo: 'low',
    baja: 'low',
    low: 'low',
    informativo: 'info',
    informativa: 'info',
    informational: 'info',
    info: 'info'
  };

  return mapa[lower] || 'info';
}

function normalizarEnum(valor, permitidos, fallback) {
  const lower = limpiarTexto(valor, fallback).toLowerCase();
  return permitidos.includes(lower) ? lower : fallback;
}

function normalizarCvss(valor) {
  if (valor === null || valor === undefined || valor === '') return null;
  const numero = Number(valor);
  if (Number.isNaN(numero)) return null;
  return Math.max(0, Math.min(10, numero));
}

function crearId(tool, index, base = '') {
  const limpio = limpiarTexto(base)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 50);

  return limpio || `${tool}-${index + 1}`;
}

function normalizarFinding(item = {}, tool = 'otra', index = 0, target = '') {
  const severity = normalizarSeveridad(item.severity || item.severidad || item.criticidad);
  const title = limpiarTexto(item.title || item.titulo || item.name || item.nombre, 'Hallazgo de seguridad');
  const affectedUrl = limpiarTexto(item.affected_url || item.url || item.endpoint, null);

  return {
    id: limpiarTexto(item.id, crearId(tool, index, title)),
    tool: limpiarTexto(item.tool || item.herramienta, tool).toLowerCase(),
    title,
    description: limpiarTexto(item.description || item.descripcion, 'Hallazgo identificado durante el analisis automatizado.'),
    severity,
    confidence: normalizarEnum(item.confidence || item.confianza, CONFIDENCES, 'possible'),
    cvss: normalizarCvss(item.cvss),
    cwe: limpiarTexto(item.cwe, null),
    affected_asset: limpiarTexto(item.affected_asset || item.asset || item.activo || target, target),
    affected_url: affectedUrl,
    evidence: limpiarTexto(item.evidence || item.evidencia, 'Sin evidencia detallada disponible.'),
    impact: limpiarTexto(item.impact || item.impacto, ''),
    recommendation: limpiarTexto(item.recommendation || item.recomendacion, ''),
    false_positive_risk: normalizarEnum(
      item.false_positive_risk || item.riesgo_falso_positivo,
      FALSE_POSITIVE_RISKS,
      'medium'
    ),
    raw_reference: limpiarTexto(item.raw_reference || item.raw, null)
  };
}

function normalizarFindings(items, tool, target = '') {
  if (!Array.isArray(items)) return [];

  return items
    .filter(Boolean)
    .map((item, index) => normalizarFinding(item, tool, index, target));
}

function resumenSeveridad(findings) {
  const resumen = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  findings.forEach(finding => {
    if (resumen[finding.severity] !== undefined) {
      resumen[finding.severity]++;
    }
  });

  return resumen;
}

function repararJsonBasico(texto) {
  return limpiarTexto(texto)
    .replace(/```json/gi, '')
    .replace(/```/g, '')
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/,\s*([}\]])/g, '$1')
    .trim();
}

function extraerJsonBalanceado(texto, apertura, cierre) {
  const inicio = texto.indexOf(apertura);
  if (inicio < 0) return null;

  let profundidad = 0;
  let dentroString = false;
  let escapado = false;

  for (let i = inicio; i < texto.length; i++) {
    const char = texto[i];

    if (escapado) {
      escapado = false;
      continue;
    }

    if (char === '\\') {
      escapado = true;
      continue;
    }

    if (char === '"') {
      dentroString = !dentroString;
      continue;
    }

    if (dentroString) continue;

    if (char === apertura) profundidad++;
    if (char === cierre) profundidad--;

    if (profundidad === 0) return texto.slice(inicio, i + 1);
  }

  return null;
}

function intentarParsear(candidato) {
  if (!candidato) return null;

  try {
    return JSON.parse(candidato);
  } catch {
    return null;
  }
}

function parsearJsonIA(texto) {
  const limpio = repararJsonBasico(texto);

  const candidatos = [
    limpio,
    extraerJsonBalanceado(limpio, '{', '}'),
    extraerJsonBalanceado(limpio, '[', ']')
  ].filter(Boolean);

  for (const candidato of candidatos) {
    const parsed = intentarParsear(candidato);
    if (parsed !== null) return parsed;
  }

  throw new Error(`La IA no devolvio JSON valido. Respuesta recibida: ${limpio.slice(0, 300)}`);
}

function parsearJsonIAFlexible(texto) {
  const parsed = parsearJsonIA(texto);

  if (typeof parsed === 'string') {
    return parsearJsonIA(parsed);
  }

  return parsed;
}

function obtenerArrayFindings(parsed) {
  if (Array.isArray(parsed)) return parsed;

  const candidato = parsed.findings ||
    parsed.hallazgos ||
    parsed.vulnerabilities ||
    parsed.vulnerabilidades ||
    parsed.results ||
    parsed.resultados;

  if (Array.isArray(candidato)) return candidato;
  if (candidato && typeof candidato === 'object') return [candidato];

  const singular = parsed.finding ||
    parsed.hallazgo ||
    parsed.vulnerability ||
    parsed.vulnerabilidad;

  if (singular && typeof singular === 'object') return [singular];

  if (parsed && typeof parsed === 'object' && (
    parsed.title ||
    parsed.titulo ||
    parsed.description ||
    parsed.descripcion ||
    parsed.severity ||
    parsed.severidad
  )) {
    return [parsed];
  }

  return [];
}

function extraerFindingsDesdeRespuestaIA(texto, tool, target = '') {
  const parsed = parsearJsonIAFlexible(texto);
  return normalizarFindings(obtenerArrayFindings(parsed), tool, target);
}

module.exports = {
  normalizarFinding,
  normalizarFindings,
  resumenSeveridad,
  extraerFindingsDesdeRespuestaIA,
  parsearJsonIA,
  parsearJsonIAFlexible
};
