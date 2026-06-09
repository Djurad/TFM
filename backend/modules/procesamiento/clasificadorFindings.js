const RUIDOSOS_NUCLEI = [
  'waf-detect',
  'wildcard-dns-detect',
  'tech-detect',
  'favicon',
  'cdn-detect'
];

const EXTENSIONES_STATIC = [
  '.js',
  '.css',
  '.map',
  '.svg',
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.woff',
  '.woff2',
  '.ttf',
  '.ico',
  '.jsx',
  '.tsx',
  '.less',
  '.scss'
];

const RUTAS_STATIC = [
  '/assets/',
  '/static/',
  '/dist/',
  '/build/',
  '/vendor/',
  '/node_modules/',
  '/fonts/',
  '/images/',
  '/img/',
  '/css/',
  '/js/'
];

const { normalizeFindingClassification } = require('./findingGroups');

const SEVERITY_MAP = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
  critica: 'critical',
  alta: 'high',
  media: 'medium',
  baja: 'low'
};

function normalizarSeveridad(valor) {
  return SEVERITY_MAP[String(valor || 'info').toLowerCase()] || 'info';
}

function normalizarConfianza(valor, fallback = 'low') {
  const lower = String(valor || fallback).toLowerCase();
  if (['high', 'medium', 'low'].includes(lower)) return lower;
  if (lower === 'confirmed') return 'high';
  if (lower === 'probable') return 'medium';
  return 'low';
}

function textoFinding(finding) {
  return [
    finding.id,
    finding.templateID,
    finding.template_id,
    finding.title,
    finding.name,
    finding.type,
    finding.raw_reference,
    finding.evidence,
    finding.raw
  ].filter(Boolean).join(' ').toLowerCase();
}

function obtenerUrlFinding(finding = {}) {
  return finding.affected_url || finding.url || finding.endpoint || finding.raw_reference || '';
}

function esAssetEstatico(url = '') {
  const raw = String(url || '').toLowerCase().split('#')[0].split('?')[0];
  let pathname = raw;

  try {
    pathname = new URL(url).pathname.toLowerCase();
  } catch {
    // Puede ser una ruta relativa o texto crudo.
  }

  return EXTENSIONES_STATIC.some(ext => pathname.endsWith(ext)) ||
    RUTAS_STATIC.some(segmento => pathname.includes(segmento)) ||
    pathname.includes('swagger-ui.css') ||
    pathname.includes('swagger-ui.js') ||
    pathname.includes('swagger-ui-bundle.js');
}

function esReconocimientoNuclei(finding) {
  const texto = textoFinding(finding);
  return RUIDOSOS_NUCLEI.some(token => texto.includes(token)) ||
    texto.includes('[info]') ||
    texto.includes('[dns]') ||
    texto.includes('[tech]');
}

function tieneEvidenciaExplotable(finding) {
  const texto = textoFinding(finding);
  return [
    'matched-at',
    'extracted-results',
    'payload',
    'injection',
    'rce',
    'sqli',
    'xss',
    'cve-'
  ].some(token => texto.includes(token));
}

function recomendacionPorTipo(type, tool) {
  if (type === 'reconocimiento') {
    return 'Usar este dato como contexto de superficie/fingerprinting, no como vulnerabilidad explotable.';
  }

  if (tool === 'sqlmap') {
    return 'Validar el parametro afectado y corregir la consulta usando consultas parametrizadas o un ORM seguro.';
  }

  if (type === 'hardening' || [
    'missing_security_header',
    'insecure_cookie',
    'missing_https_redirect',
    'tls_certificate_issue'
  ].includes(type)) {
    return 'Revisar la cabecera o configuracion indicada y aplicar hardening segun el contexto de la aplicacion.';
  }

  if (type === 'surface') {
    return 'Revisar manualmente si este endpoint requiere controles adicionales.';
  }

  return 'Validar manualmente la evidencia y aplicar la remediacion especifica del hallazgo confirmado.';
}

function clasificarFinding(raw = {}) {
  const tool = String(raw.tool || raw.herramienta || 'otra').toLowerCase();
  const severityOriginal = normalizarSeveridad(raw.severity || raw.severidad || raw.criticidad);
  const id = raw.id || raw.templateID || raw.template_id || `${tool}-${Date.now()}`;
  const texto = textoFinding({ ...raw, id });
  const assetEstatico = esAssetEstatico(obtenerUrlFinding(raw));

  let type = raw.type || raw.tipo || 'vulnerability';
  let severity = severityOriginal;
  let confidence = normalizarConfianza(raw.confidence || raw.confianza, severity === 'info' ? 'low' : 'medium');
  let isVulnerability = typeof raw.isVulnerability === 'boolean' ? raw.isVulnerability : severity !== 'info';
  let isFalsePositiveLikely = Boolean(raw.isFalsePositiveLikely);
  let falsePositiveReason = raw.falsePositiveReason || '';

  if (tool === 'subfinder' || tool === 'httpx') {
    type = 'reconocimiento';
    severity = 'info';
    confidence = 'low';
    isVulnerability = false;
    isFalsePositiveLikely = false;
    falsePositiveReason = '';
  }

  if (tool === 'gau') {
    type = raw.type === 'surface' ? 'surface' : 'historical-url';
    severity = raw.type === 'surface' ? 'low' : 'info';
    confidence = 'low';
    isVulnerability = false;
    isFalsePositiveLikely = false;
    falsePositiveReason = '';
  }

  if (tool === 'gf') {
    type = 'gf_candidate';
    severity = ['medium', 'low'].includes(severityOriginal) ? severityOriginal : 'low';
    confidence = 'low';
    isVulnerability = false;
    isFalsePositiveLikely = false;
    falsePositiveReason = 'GF prioriza candidatos por patron; no confirma explotabilidad.';
  }

  if (['headers', 'cookies', 'httpsredirect', 'tls'].includes(tool)) {
    type = raw.type || type;
    severity = severityOriginal;
    confidence = normalizarConfianza(raw.confidence || raw.confianza, severity === 'info' ? 'low' : 'medium');
    isVulnerability = typeof raw.isVulnerability === 'boolean' ? raw.isVulnerability : severity !== 'info';
    isFalsePositiveLikely = raw.false_positive_risk === 'high' && confidence === 'low';
    falsePositiveReason = isFalsePositiveLikely
      ? 'Hallazgo de hardening de baja confianza o bajo impacto; requiere validacion contextual.'
      : '';
  }

  if (tool === 'robotssitemap') {
    type = raw.type || 'reconocimiento';
    severity = severityOriginal;
    confidence = normalizarConfianza(raw.confidence || raw.confianza, 'low');
    isVulnerability = false;
    isFalsePositiveLikely = false;
    falsePositiveReason = '';
  }

  if (tool === 'ports') {
    type = raw.type || type;
    severity = severityOriginal;
    confidence = normalizarConfianza(raw.confidence || raw.confianza, severity === 'info' ? 'low' : 'medium');
    isVulnerability = typeof raw.isVulnerability === 'boolean' ? raw.isVulnerability : ['high', 'critical'].includes(severity);
    isFalsePositiveLikely = false;
    falsePositiveReason = '';
  }

  if (assetEstatico && tool !== 'trufflehog') {
    console.log(`[Clasificador] descartado por ruta irrelevante: ${obtenerUrlFinding(raw)}`);
    type = 'discarded';
    severity = 'info';
    confidence = 'low';
    isVulnerability = false;
    isFalsePositiveLikely = true;
    falsePositiveReason = 'Asset estatico descartado: no representa una vulnerabilidad por si solo.';
  }

  if (tool === 'katana' && !assetEstatico) {
    type = raw.category === 'suspicious' || raw.category === 'swagger-json'
      ? 'surface'
      : 'reconocimiento';
    severity = raw.category === 'suspicious' || raw.category === 'swagger-json' ? 'low' : 'info';
    confidence = 'low';
    isVulnerability = false;
    isFalsePositiveLikely = false;
    falsePositiveReason = '';
  }

  if (tool === 'feroxbuster') {
    if (raw.exposure === true) {
      type = 'vulnerability';
      severity = 'medium';
      confidence = 'medium';
      isVulnerability = true;
      isFalsePositiveLikely = false;
      falsePositiveReason = '';
    } else {
      type = 'surface';
      severity = 'low';
      confidence = 'low';
      isVulnerability = false;
      isFalsePositiveLikely = false;
    }
  }

  if (severity === 'info') {
    type = ['discarded', 'surface', 'exposed_server_banner', 'exposed_port'].includes(type) ? type : 'reconocimiento';
    isVulnerability = false;
    confidence = 'low';
    isFalsePositiveLikely = type === 'discarded';
    falsePositiveReason = falsePositiveReason || 'Severidad informativa: no representa una vulnerabilidad por si sola.';
  }

  if (tool === 'nuclei' && esReconocimientoNuclei(raw)) {
    type = 'reconocimiento';
    severity = 'info';
    confidence = 'low';
    isVulnerability = false;
    isFalsePositiveLikely = true;
    falsePositiveReason = 'Template de fingerprinting/reconocimiento excluido de vulnerabilidades.';
  }

  if (texto.includes('missing-security-header')) {
    type = 'hardening';
    severity = 'low';
    isVulnerability = true;
    confidence = 'low';
    isFalsePositiveLikely = true;
    falsePositiveReason = 'Cabecera de seguridad ausente: es hardening de bajo impacto salvo evidencia adicional.';
  }

  if (tool === 'sqlmap') {
    const evidenciaConcluyente = Boolean(raw.payload || raw.dbms || raw.parametro || raw.parameter);
    if ((raw.status === 'confirmed_sqli' || raw.vulnerable === true) && evidenciaConcluyente) {
      type = 'confirmed_vulnerability';
      severity = 'critical';
      confidence = 'high';
      isVulnerability = true;
      isFalsePositiveLikely = false;
      falsePositiveReason = '';
    } else if (raw.status === 'possible_sqli') {
      type = 'possible_vulnerability';
      severity = 'high';
      confidence = 'medium';
      isVulnerability = true;
      isFalsePositiveLikely = false;
      falsePositiveReason = '';
    } else if (raw.status === 'confirmed_sqli' || raw.vulnerable === true) {
      type = 'confirmed_vulnerability';
      severity = 'medium';
      confidence = 'medium';
      isVulnerability = true;
      isFalsePositiveLikely = true;
      falsePositiveReason = 'Sqlmap marco el resultado como vulnerable, pero falta evidencia tecnica concluyente.';
    } else {
      type = raw.status === 'error' ? 'error' : 'reconocimiento';
      severity = 'info';
      confidence = 'low';
      isVulnerability = false;
      isFalsePositiveLikely = true;
      falsePositiveReason = raw.error || 'Sqlmap no confirmo inyeccion SQL.';
    }
  }

  if (tool === 'trufflehog') {
    type = 'exposed-secret';
    severity = raw.verified ? 'high' : 'medium';
    confidence = raw.verified ? 'high' : 'medium';
    isVulnerability = true;
    isFalsePositiveLikely = false;
    falsePositiveReason = '';
  }

  if (tool === 'nuclei' && ['high', 'critical'].includes(severity)) {
    confidence = 'high';
    isVulnerability = true;
  }

  if (tool === 'nuclei' && ['low', 'medium'].includes(severity) && !tieneEvidenciaExplotable(raw)) {
    confidence = 'low';
    isFalsePositiveLikely = true;
    falsePositiveReason = falsePositiveReason || 'Hallazgo sin evidencia clara de explotabilidad.';
  }

  return normalizeFindingClassification({
    ...raw,
    id,
    tool,
    type,
    severity,
    confidence,
    isVulnerability,
    isFalsePositiveLikely,
    falsePositiveReason,
    evidence: raw.evidence || raw.evidencia || raw.raw_reference || raw.raw || '',
    recommendation: raw.recommendation || raw.recomendacion || recomendacionPorTipo(type, tool)
  });
}

function clasificarFindings(findings = []) {
  return Array.isArray(findings) ? findings.map(clasificarFinding) : [];
}

module.exports = {
  clasificarFinding,
  clasificarFindings,
  esAssetEstatico
};
