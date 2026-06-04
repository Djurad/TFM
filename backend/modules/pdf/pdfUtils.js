const {
  buildDashboardMetrics,
  buildFindingGroups,
  canonicalToolName,
  normalizeSeverity,
  percentage,
  safeArray,
  sortFindings
} = require('../findingGroups');

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SENSITIVE_PATH_RE = /(admin|login|upload|api|swagger|openapi|graphql|debug|backup|config|secret|token)/i;

function repairMojibake(value) {
  const raw = String(value);
  if (!/[ÃÂâ][\u0080-\u00FF]/.test(raw)) return raw;

  try {
    const repaired = Buffer.from(raw, 'latin1').toString('utf8');
    const rawBad = (raw.match(/\uFFFD|Ã|Â|â/g) || []).length;
    const repairedBad = (repaired.match(/\uFFFD|Ã|Â|â/g) || []).length;
    return repairedBad < rawBad ? repaired : raw;
  } catch {
    return raw;
  }
}

function text(value, fallback = 'No disponible') {
  if (value === null || value === undefined || value === '') return fallback;
  return repairMojibake(value);
}

function truncate(value, max = 220) {
  const raw = text(value, '');
  if (raw.length <= max) return raw;
  return `${raw.slice(0, Math.max(0, max - 3))}...`;
}

function severityRank(value) {
  const index = SEVERITY_ORDER.indexOf(normalizeSeverity(value));
  return index < 0 ? 99 : index;
}

function isGfCandidate(finding = {}) {
  return String(finding.tool || '').toLowerCase() === 'gf' ||
    ['gf-candidate', 'gf_candidate'].includes(String(finding.type || '').toLowerCase());
}

function getAsset(finding = {}) {
  return finding.affected_url || finding.affected_asset || finding.raw_reference || 'No disponible';
}

function countBy(findings = [], keyGetter) {
  return findings.reduce((acc, item) => {
    const key = keyGetter(item) || 'otra';
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
}

function mapCountObject(obj = {}) {
  return Object.entries(obj)
    .map(([label, value]) => ({ label, value }))
    .sort((a, b) => b.value - a.value || a.label.localeCompare(b.label));
}

function scoreLabel(score, level) {
  if (score === null || score === undefined) return 'Riesgo no disponible';
  const normalized = String(level || '').toLowerCase();
  if (normalized === 'critico') return 'Riesgo Critico';
  if (normalized === 'alto') return 'Riesgo Alto';
  if (normalized === 'medio' || normalized === 'moderado') return 'Riesgo Medio';
  if (normalized === 'bajo') return 'Riesgo Bajo';
  return `Riesgo ${text(level, 'N/D')}`;
}

function formatDate(value = new Date()) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return 'No disponible';
  return new Intl.DateTimeFormat('es-ES', {
    dateStyle: 'medium',
    timeStyle: 'short'
  }).format(date);
}

function metric(label, value, accent = 'info') {
  return {
    label,
    value: value === null || value === undefined ? 'N/D' : value,
    accent
  };
}

function counter(context, path, fallback = 0) {
  const parts = path.split('.');
  let current = context.toolCounters || context.tool_counters || {};
  for (const part of parts) {
    if (!current || current[part] === undefined) return fallback;
    current = current[part];
  }
  return current ?? fallback;
}

function deriveMetrics(groups, context) {
  const secrets = Number(counter(context, 'trufflehog.secretos_confirmados')) +
    Number(counter(context, 'trufflehog.secretos_posibles'));

  return [
    metric('Critical', groups.severityReportable.critical, 'critical'),
    metric('High', groups.severityReportable.high, 'high'),
    metric('Medium', groups.severityReportable.medium, 'medium'),
    metric('Low', groups.severityReportable.low, 'low'),
    metric('Info', groups.severityReportable.info, 'info'),
    metric('Confirmadas', groups.confirmed.length, 'critical'),
    metric('Posibles', groups.possible.length, 'medium'),
    metric('Candidatos GF', groups.gfCandidates.length, 'info'),
    metric('Hardening', groups.hardening.length, 'low'),
    metric('Superficie', groups.attackSurface.length, 'info'),
    metric('Endpoints', Math.max(counter(context, 'katana.endpoints_encontrados'), counter(context, 'gau.endpoints_encontrados')), 'info'),
    metric('Subdominios', counter(context, 'subfinder.subdominios_encontrados'), 'info'),
    metric('Activos vivos', counter(context, 'httpx.activos_vivos'), 'low'),
    metric('Puertos abiertos', counter(context, 'ports.puertos_abiertos'), 'high'),
    metric('Secretos', secrets, secrets > 0 ? 'critical' : 'info')
  ];
}

function categoryDistribution(groups) {
  return [
    { label: 'Vulnerabilidad', value: groups.confirmed.length + groups.possible.length },
    { label: 'GF', value: groups.gfCandidates.length },
    { label: 'Hardening', value: groups.hardening.length },
    { label: 'Superficie', value: groups.attackSurface.length },
    { label: 'Informativo', value: groups.informational.length },
    { label: 'Descartado', value: groups.discarded.length }
  ];
}

function buildGroups(findings = []) {
  const groups = buildFindingGroups(findings);
  groups.severity = groups.severityGlobal;
  return groups;
}

function summarizeTools(toolResults = {}, findings = []) {
  const fromResults = Object.entries(toolResults).map(([tool, result]) => ({
    label: canonicalToolName(tool),
    value: safeArray(result.findings).length || Number(result.parsed_count || 0)
  }));
  const fromFindings = mapCountObject(countBy(findings, f => canonicalToolName(f.tool || 'otra')));
  const merged = new Map();

  [...fromResults, ...fromFindings].forEach(item => {
    merged.set(item.label, Math.max(Number(merged.get(item.label) || 0), Number(item.value || 0)));
  });

  return Array.from(merged.entries())
    .map(([label, value]) => ({ label, value }))
    .filter(item => item.value > 0)
    .sort((a, b) => b.value - a.value || a.label.localeCompare(b.label));
}

function interestingSurface(groups, context = {}) {
  const fromFindings = groups.attackSurface
    .filter(f => SENSITIVE_PATH_RE.test(`${f.title} ${getAsset(f)} ${f.evidence || ''}`))
    .slice(0, 30);

  return sortFindings(fromFindings).slice(0, 45);
}

function buildRecommendations(groups) {
  const critical = groups.confirmed.filter(f => ['critical', 'high'].includes(normalizeSeverity(f.severity)));
  const shortTerm = [...groups.confirmed, ...groups.possible]
    .filter(f => ['medium', 'high', 'critical'].includes(normalizeSeverity(f.severity)));
  const manual = [...groups.possible, ...groups.gfCandidates]
    .filter(f => isGfCandidate(f) || String(f.confidence || '').toLowerCase() === 'medium' || f.requiresManualValidation);

  return {
    critical: critical.length
      ? critical.map(f => `${f.title}: ${f.recommendation || 'Corregir con prioridad y verificar explotabilidad tras el cambio.'}`)
      : ['No hay acciones criticas inmediatas basadas en vulnerabilidades confirmadas.'],
    shortTerm: shortTerm.length
      ? shortTerm.slice(0, 12).map(f => `${f.title}: ${f.recommendation || 'Validar el hallazgo y aplicar la remediacion tecnica correspondiente.'}`)
      : ['No hay vulnerabilidades reportables de corto plazo con la evidencia actual.'],
    hardening: groups.hardening.length
      ? groups.hardening.slice(0, 12).map(f => `${f.title}: ${f.recommendation || 'Aplicar la configuracion defensiva recomendada y repetir validacion.'}`)
      : ['No se identificaron mejoras de hardening destacables.'],
    manual: manual.length
      ? manual.slice(0, 12).map(f => `${f.title}: validar manualmente en ${getAsset(f)}.`)
      : ['No hay candidatos que requieran validacion manual prioritaria.']
  };
}

function buildCompleteTimeline(timeline = [], toolResults = {}, toolCounters = {}) {
  const expected = [
    'subfinder',
    'httpx',
    'headers',
    'cookies',
    'httpsRedirect',
    'tls',
    'robotsSitemap',
    'ports',
    'feroxbuster',
    'katana',
    'gau',
    'gf',
    'nuclei',
    'dalfox',
    'sqlmap',
    'trufflehog',
    'correlacion',
    'score final',
    'analisis ia'
  ];
  const byTool = new Map();

  safeArray(timeline).forEach(item => {
    if (item && item.tool) byTool.set(String(item.tool), item);
  });

  return expected.map(tool => {
    const existing = byTool.get(tool);
    if (existing) return existing;

    const result = toolResults[tool] || {};
    const counters = toolCounters[tool] || {};
    const status = result.status || (Object.keys(counters).length ? 'success' : 'skipped');
    const count = safeArray(result.findings).length || Number(result.parsed_count || 0);
    const detail = Object.keys(counters).length
      ? Object.entries(counters).slice(0, 3).map(([key, value]) => `${key}=${value}`).join(', ')
      : `${count} hallazgos`;

    return {
      tool,
      status,
      detail,
      duration_ms: result.metrics?.duration_ms || null,
      important: status === 'error' || status === 'partial' || count > 0
    };
  });
}

function prepareReportData(target, findings = [], context = {}) {
  const groups = buildGroups(safeArray(findings));
  const generatedAt = new Date();
  const toolResults = context.toolResults || context.tool_results || {};
  const toolCounters = context.toolCounters || context.tool_counters || {};
  const timeline = buildCompleteTimeline(context.pipelineTimeline || context.pipeline_timeline, toolResults, toolCounters);
  const dashboardMetrics = buildDashboardMetrics(findings, toolResults);

  return {
    target: text(target, 'No disponible'),
    generatedAt,
    generatedAtLabel: formatDate(generatedAt),
    risk: {
      score: context.risk_score,
      level: context.risk_level || 'N/D',
      grade: context.risk_grade || 'N/D',
      label: scoreLabel(context.risk_score, context.risk_level)
    },
    groups,
    metrics: deriveMetrics(groups, context),
    dashboardMetrics,
    toolChart: summarizeTools(toolResults, safeArray(findings)).slice(0, 10),
    categoryChart: categoryDistribution(groups),
    correlations: safeArray(context.correlations),
    timeline,
    toolResults,
    toolCounters,
    gfCandidates: context.gfCandidates || context.gf_candidates || {},
    interestingSurface: interestingSurface(groups, context),
    recommendations: buildRecommendations(groups),
    allFindings: safeArray(findings),
    notices: [context.sqlmap_notice, context.ai_notice].filter(Boolean)
  };
}

module.exports = {
  SEVERITY_ORDER,
  getAsset,
  isGfCandidate,
  normalizeSeverity,
  percentage,
  prepareReportData,
  safeArray,
  text,
  truncate
};
