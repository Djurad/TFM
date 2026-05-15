const { normalizarFindings } = require('./normalizacion');

function obtenerPath(url) {
  try {
    return new URL(url).pathname.toLowerCase();
  } catch {
    return String(url || '').toLowerCase();
  }
}

function obtenerOrigenYRuta(url) {
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return String(url || '').split('?')[0];
  }
}

function parsearNucleiLinea(linea, index, target) {
  const limpia = String(linea || '').trim();
  const match = limpia.match(/\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)/);

  if (!match) return null;

  const [, id, tipo, severity, url] = match;

  return {
    id: `nuclei-${id}-${index + 1}`,
    tool: 'nuclei',
    title: id.replace(/[-_]/g, ' '),
    description: `Nuclei detecto el hallazgo ${id} de tipo ${tipo}.`,
    severity,
    confidence: severity === 'info' ? 'possible' : 'probable',
    cvss: null,
    cwe: null,
    affected_asset: target,
    affected_url: url,
    evidence: limpia,
    impact: '',
    recommendation: '',
    false_positive_risk: severity === 'info' ? 'medium' : 'low',
    raw_reference: limpia
  };
}

function findingsNuclei(toolResult, target) {
  const lineas = Array.isArray(toolResult.parsed)
    ? toolResult.parsed
    : String(toolResult.raw || '').split('\n').filter(Boolean);

  return normalizarFindings(
    lineas
      .map((linea, index) => parsearNucleiLinea(linea, index, target))
      .filter(Boolean),
    'nuclei',
    target
  );
}

function findingsDalfox(toolResult, target) {
  const items = Array.isArray(toolResult.parsed) ? toolResult.parsed : [];
  const grupos = new Map();

  items
    .filter(item => {
      const parsed = normalizarItemDalfox(item);
      const raw = JSON.stringify(parsed).toLowerCase();
      return raw.includes('xss') ||
        raw.includes('vulnerable') ||
        raw.includes('poc') ||
        raw.includes('payload') ||
        raw.includes('proof');
    })
    .forEach(item => {
      const parsed = normalizarItemDalfox(item);
      const url = parsed.url || parsed.target || parsed.data || null;
      const param = parsed.param || obtenerPrimerParametro(url);
      const payload = limpiarValorDalfox(parsed.payload || parsed.poc || '');
      const evidence = limpiarValorDalfox(parsed.evidence || parsed.message_str || '');
      const injectType = parsed.inject_type || parsed.type || 'desconocido';
      const severity = normalizarSeveridadDalfox(parsed.severity, parsed.type);
      const confirmed = String(parsed.type || '').toUpperCase() === 'V';
      const rawReference = JSON.stringify(parsed);
      const groupKey = [
        obtenerOrigenYRuta(url || target),
        param || '',
        injectType,
        confirmed ? 'confirmed' : 'probable'
      ].join('|');

      if (!grupos.has(groupKey)) {
        grupos.set(groupKey, {
          url,
          param,
          injectType,
          severity,
          confirmed,
          payloads: [],
          evidences: [],
          rawReferences: []
        });
      }

      const grupo = grupos.get(groupKey);

      if (severity === 'high') grupo.severity = 'high';
      if (confirmed) grupo.confirmed = true;
      if (payload && grupo.payloads.length < 4 && !grupo.payloads.includes(payload)) grupo.payloads.push(payload);
      if (evidence && grupo.evidences.length < 4 && !grupo.evidences.includes(evidence)) grupo.evidences.push(evidence);
      if (rawReference && grupo.rawReferences.length < 4) grupo.rawReferences.push(rawReference);
    });

  return normalizarFindings(
    Array.from(grupos.values()).map((grupo, index) => {
      const readableEvidence = [
        `URL base: ${obtenerOrigenYRuta(grupo.url || target)}`,
        grupo.url ? `Ejemplo vulnerable: ${grupo.url}` : null,
        grupo.param ? `Parametro: ${grupo.param}` : null,
        `Tipo de inyeccion: ${grupo.injectType}`,
        grupo.payloads.length ? `Payloads observados:\n- ${grupo.payloads.join('\n- ')}` : null,
        grupo.evidences.length ? `Evidencias observadas:\n- ${grupo.evidences.join('\n- ')}` : null
      ].filter(Boolean).join('\n');

      return {
        id: `dalfox-xss-${index + 1}`,
        tool: 'dalfox',
        title: grupo.confirmed ? 'XSS confirmado por Dalfox' : 'Payload XSS reflejado por Dalfox',
        description: `Dalfox detecto un posible XSS en el parametro ${grupo.param || 'identificado'} usando payloads reflejados en contexto ${grupo.injectType}.`,
        severity: grupo.confirmed ? 'high' : grupo.severity,
        confidence: grupo.confirmed ? 'confirmed' : 'probable',
        cvss: null,
        cwe: 'CWE-79',
        affected_asset: target,
        affected_url: grupo.url,
        evidence: readableEvidence,
        impact: '',
        recommendation: '',
        false_positive_risk: grupo.confirmed ? 'low' : 'medium',
        raw_reference: grupo.rawReferences.join('\n').slice(0, 1600)
      };
    }),
    'dalfox',
    target
  );
}

function parseJsonFlexible(texto) {
  if (!texto || typeof texto !== 'string') return null;

  const candidatos = [
    texto.trim(),
    texto.trim().replace(/,\s*$/, ''),
    texto.trim().replace(/,\s*}$/, '}')
  ];

  for (const candidato of candidatos) {
    try {
      return JSON.parse(candidato);
    } catch {
      // Se intenta el siguiente candidato.
    }
  }

  return null;
}

function normalizarItemDalfox(item) {
  if (!item || typeof item !== 'object') return {};

  if (item.raw) {
    const parsedRaw = parseJsonFlexible(item.raw);
    if (parsedRaw) return parsedRaw;
  }

  return item;
}

function limpiarValorDalfox(valor) {
  return String(valor || '')
    .replace(/\\u003c/g, '<')
    .replace(/\\u003e/g, '>')
    .replace(/\\u0026/g, '&')
    .replace(/\\r/g, ' ')
    .replace(/\\n/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function obtenerPrimerParametro(url) {
  try {
    return Array.from(new URL(url).searchParams.keys())[0] || null;
  } catch {
    return null;
  }
}

function normalizarSeveridadDalfox(severity, type) {
  if (String(type || '').toUpperCase() === 'V') return 'high';

  const lower = String(severity || '').toLowerCase();
  if (lower.includes('critical')) return 'critical';
  if (lower.includes('high')) return 'high';
  if (lower.includes('medium')) return 'medium';
  if (lower.includes('low')) return 'low';
  return 'medium';
}

function findingsSqlmap(toolResult, target) {
  const items = Array.isArray(toolResult.parsed) ? toolResult.parsed : [];

  return normalizarFindings(
    items
      .filter(item => item.vulnerable)
      .map((item, index) => ({
        id: `sqlmap-sqli-${index + 1}`,
        tool: 'sqlmap',
        title: 'SQL Injection detectada por sqlmap',
        description: 'Sqlmap ha identificado indicios de inyeccion SQL en un parametro analizado.',
        severity: 'critical',
        confidence: 'confirmed',
        cvss: null,
        cwe: 'CWE-89',
        affected_asset: target,
        affected_url: item.url,
        evidence: [item.evidencia, ...(item.resumen || [])].filter(Boolean).join('\n'),
        impact: '',
        recommendation: '',
        false_positive_risk: 'low',
        raw_reference: JSON.stringify(item).slice(0, 1200)
      })),
    'sqlmap',
    target
  );
}

function extraerFindingsDeterministas(tool, toolResult, target) {
  if (tool === 'katana') return findingsKatana(toolResult, target);
  if (tool === 'nuclei') return findingsNuclei(toolResult, target);
  if (tool === 'dalfox') return findingsDalfox(toolResult, target);
  if (tool === 'sqlmap') return findingsSqlmap(toolResult, target);
  return [];
}

function clasificarEndpointSensible(url) {
  const lower = String(url || '').toLowerCase();
  const path = obtenerPath(url);

  if (lower.includes('swagger') || lower.includes('/api-doc') || lower.includes('openapi')) {
    return {
      title: 'Documentacion de API expuesta',
      severity: 'medium',
      evidence: 'Ruta compatible con Swagger/OpenAPI descubierta por Katana.',
      impact: '',
      recommendation: ''
    };
  }

  if (path.includes('admin')) {
    return {
      title: 'Ruta administrativa expuesta',
      severity: 'medium',
      evidence: 'Ruta con patron administrativo descubierta por Katana.',
      impact: '',
      recommendation: ''
    };
  }

  if (path.includes('login') || path.includes('signin')) {
    return {
      title: 'Formulario de autenticacion identificado',
      severity: 'low',
      evidence: 'Ruta de autenticacion descubierta durante el rastreo.',
      impact: '',
      recommendation: ''
    };
  }

  return null;
}

function findingsKatana(toolResult, target) {
  const urls = Array.isArray(toolResult.parsed) ? toolResult.parsed : [];
  const vistos = new Set();
  const findings = [];

  urls.forEach(url => {
    const clasificacion = clasificarEndpointSensible(url);

    if (!clasificacion || vistos.has(url)) return;
    vistos.add(url);

    findings.push({
      id: `katana-surface-${findings.length + 1}`,
      tool: 'katana',
      title: clasificacion.title,
      description: `${clasificacion.title} en ${url}.`,
      severity: clasificacion.severity,
      confidence: 'possible',
      cvss: null,
      cwe: null,
      affected_asset: target,
      affected_url: url,
      evidence: clasificacion.evidence,
      impact: clasificacion.impact,
      recommendation: clasificacion.recommendation,
      false_positive_risk: 'medium',
      raw_reference: url
    });
  });

  return normalizarFindings(findings.slice(0, 20), 'katana', target);
}

module.exports = {
  extraerFindingsDeterministas
};
