const {
  buildDashboardMetrics,
  buildFindingGroups,
  canonicalToolName,
  normalizeSeverity,
  percentage,
  safeArray,
  sortFindings
} = require('../procesamiento/findingGroups');

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SENSITIVE_PATH_RE = /(admin|login|upload|api|swagger|openapi|graphql|debug|backup|config|secret|token)/i;
const PIPELINE_ORDER = [
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

function canonicalPipelineTool(tool = '') {
  const raw = String(tool || '').trim();
  const lower = raw.toLowerCase().replace(/[_-]+/g, ' ').replace(/\s+/g, ' ');
  if (!lower) return '';
  if (lower === 'httpsredirect' || lower === 'https redirect') return 'httpsRedirect';
  if (lower === 'robotssitemap' || lower === 'robots sitemap') return 'robotsSitemap';
  if (lower === 'score' || lower === 'score final' || lower === 'final score') return 'score final';
  if (lower === 'analisis ia' || lower === 'analysis ia' || lower === 'ia' || lower.startsWith('ia/')) return 'analisis ia';
  if (lower === 'informe') return 'analisis ia';
  return PIPELINE_ORDER.find(item => item.toLowerCase() === lower) || raw;
}

function getToolResult(toolResults = {}, tool = '') {
  const wanted = canonicalPipelineTool(tool);
  return toolResults[wanted] ||
    toolResults[tool] ||
    Object.entries(toolResults).find(([key]) => canonicalPipelineTool(key) === wanted)?.[1] ||
    {};
}

function getToolCounter(toolCounters = {}, tool = '') {
  const wanted = canonicalPipelineTool(tool);
  return toolCounters[wanted] ||
    toolCounters[tool] ||
    Object.entries(toolCounters).find(([key]) => canonicalPipelineTool(key) === wanted)?.[1] ||
    {};
}

function number(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parsedLength(result = {}) {
  return safeArray(result.parsed).length || number(result.parsed_count);
}

function statusFromResult(tool, result = {}, counters = {}, context = {}, existing = {}) {
  if (tool === 'correlacion') return safeArray(context.correlations).length >= 0 ? 'success' : 'pending';
  if (tool === 'score final') return context.risk_score === null || context.risk_score === undefined ? 'pending' : 'success';
  if (tool === 'analisis ia') return context.ai_notice ? 'partial' : 'success';

  let status = result.status || existing.status || (Object.keys(counters).length ? 'success' : 'pending');

  if (tool === 'trufflehog') {
    const candidates = number(result.metrics?.recursos_candidatos ?? counters.recursos_candidatos);
    const downloaded = number(result.metrics?.recursos_descargados ?? counters.recursos_descargados);
    const failed = number(result.metrics?.recursos_fallidos ?? counters.recursos_fallidos);
    if ((candidates > 0 && downloaded < candidates) || failed > 0 || result.warning) status = 'partial';
  }

  return status;
}

function httpxSummary(result = {}, counters = {}) {
  const parsed = safeArray(result.parsed);
  const responses = number(counters.respuestas_httpx ?? result.metrics?.respuestas_httpx, parsed.length || number(result.parsed_count));
  const assets = new Set(parsed.map(item => item.finalUrl || item.final_url || item.url || item.input).filter(Boolean));
  const metricAssets = number(result.metrics?.activos_vivos ?? counters.activos_vivos);

  if (metricAssets > 0 && responses > metricAssets) return `${responses} respuestas / ${metricAssets} activo${metricAssets === 1 ? '' : 's'} vivo${metricAssets === 1 ? '' : 's'}`;
  if (assets.size > 0 && responses > assets.size) return `${responses} respuestas / ${assets.size} activo${assets.size === 1 ? '' : 's'} vivo${assets.size === 1 ? '' : 's'}`;
  if (assets.size > 0) return `${assets.size} activo${assets.size === 1 ? '' : 's'} vivo${assets.size === 1 ? '' : 's'}`;
  if (metricAssets > 0) return `${metricAssets} activo${metricAssets === 1 ? '' : 's'} vivo${metricAssets === 1 ? '' : 's'}`;
  if (responses > 0) return `${responses} respuestas`;
  return '0 activos vivos';
}

function toolDetail(tool, result = {}, counters = {}, context = {}) {
  if (tool === 'subfinder') return `${number(counters.subdominios_encontrados || parsedLength(result))} subdominios`;
  if (tool === 'httpx') return httpxSummary(result, counters);
  if (tool === 'headers') return `${number(counters.cabeceras_ausentes ?? result.metrics?.cabeceras_ausentes)} ausentes / ${number(counters.banners_expuestos ?? result.metrics?.banners_expuestos)} banner${number(counters.banners_expuestos ?? result.metrics?.banners_expuestos) === 1 ? '' : 's'}`;
  if (tool === 'cookies') return `${number(counters.cookies_inseguras ?? result.metrics?.cookies_inseguras)} insegura${number(counters.cookies_inseguras ?? result.metrics?.cookies_inseguras) === 1 ? '' : 's'} / ${number(counters.cookies_sesion ?? result.metrics?.cookies_sesion)} sesion`;
  if (tool === 'httpsRedirect') return `${number(counters.redirecciona_https ?? result.metrics?.redirecciona_https)} HTTPS ok / ${number(counters.http_sin_redirect ?? result.metrics?.http_sin_redirect)} HTTP abierto`;
  if (tool === 'tls') return `${number(counters.certificados_analizados ?? result.metrics?.certificados_analizados)} cert / ${number(counters.expirados ?? result.metrics?.expirados)} expirados / ${number(counters.proximos_expirar ?? result.metrics?.proximos_expirar)} proximo${number(counters.proximos_expirar ?? result.metrics?.proximos_expirar) === 1 ? '' : 's'} a expirar`;
  if (tool === 'robotsSitemap') return `${number(counters.recursos_encontrados ?? result.metrics?.recursos_encontrados)} recursos / ${number(counters.rutas_sensibles ?? result.metrics?.rutas_sensibles)} sensibles`;
  if (tool === 'ports') return `${number(counters.puertos_abiertos ?? result.metrics?.puertos_abiertos)} abiertos${counters.source || result.metrics?.source ? ` / ${counters.source || result.metrics.source}` : ''}`;
  if (tool === 'feroxbuster') return `${number(counters.rutas_descubiertas ?? result.metrics?.endpoints_encontrados)} rutas / ${number(counters.rutas_sensibles ?? result.metrics?.rutas_interesantes)} sensibles`;
  if (tool === 'katana') return `${number(counters.endpoints_encontrados ?? result.metrics?.endpoints_normalizados ?? parsedLength(result))} endpoints / ${number(counters.superficie_util ?? result.metrics?.superficie_util)} superficie`;
  if (tool === 'gau') {
    const raw = number(counters.raw_urls ?? result.metrics?.raw_urls);
    const selected = number(counters.seleccionadas_final ?? result.metrics?.seleccionadas_final ?? counters.endpoints_encontrados ?? result.metrics?.endpoints_encontrados ?? parsedLength(result));
    const params = number(counters.con_parametros ?? result.metrics?.con_parametros);
    return `${raw} analizadas / ${selected} seleccionadas / ${params} con parametros`;
  }
  if (tool === 'gf') {
    const xss = number(counters.xss ?? result.metrics?.xss);
    const sqli = number(counters.sqli ?? result.metrics?.sqli);
    const ssrf = number(counters.ssrf ?? result.metrics?.ssrf);
    const total = xss + sqli + ssrf + number(counters.redirect ?? result.metrics?.redirect) + number(counters.lfi ?? result.metrics?.lfi) + number(counters.rce ?? result.metrics?.rce);
    return total ? `${total} candidatos` : '0 candidatos';
  }
  if (tool === 'nuclei') return `${number(counters.vulnerabilidades_reales ?? result.metrics?.vulnerabilidades_reales)} vulnerabilidades`;
  if (tool === 'dalfox') {
    const confirmed = number(result.metrics?.confirmadas);
    return confirmed ? `${confirmed} XSS confirmado${confirmed === 1 ? '' : 's'}` : `${safeArray(result.findings).length || parsedLength(result)} hallazgos`;
  }
  if (tool === 'sqlmap') return counters.no_ejecutada ? 'no ejecutada' : `${number(counters.confirmadas)} confirmadas / ${number(counters.posibles)} posible${number(counters.posibles) === 1 ? '' : 's'}`;
  if (tool === 'trufflehog') {
    const secrets = number(counters.secretos_confirmados ?? result.metrics?.secretos_verificados) + number(counters.secretos_posibles ?? result.metrics?.secretos_posibles);
    const candidates = number(counters.recursos_candidatos ?? result.metrics?.recursos_candidatos);
    const downloaded = number(counters.recursos_descargados ?? result.metrics?.recursos_descargados);
    if (candidates > 0 && downloaded < candidates) return `${secrets} secretos / cobertura parcial: ${downloaded} de ${candidates} recursos descargados`;
    return `${secrets} secretos`;
  }
  if (tool === 'correlacion') return `${safeArray(context.correlations).length} correlaciones`;
  if (tool === 'score final') return context.risk_score === null || context.risk_score === undefined ? 'pendiente' : `${context.risk_score}/100 ${scoreLabel(context.risk_score, context.risk_level)}`;
  if (tool === 'analisis ia') return context.ai_notice || 'enriquecimiento completado';
  return parsedLength(result) ? `${parsedLength(result)} resultados` : 'sin datos';
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

function buildCompleteTimeline(timeline = [], toolResults = {}, toolCounters = {}, context = {}) {
  const byTool = new Map();

  safeArray(timeline).forEach(item => {
    if (item && item.tool) byTool.set(canonicalPipelineTool(item.tool), item);
  });

  return PIPELINE_ORDER.map(tool => {
    const existing = byTool.get(tool);
    const result = getToolResult(toolResults, tool);
    const counters = getToolCounter(toolCounters, tool);
    const status = statusFromResult(tool, result, counters, context, existing);
    const hasData = Object.keys(result).length > 0 || Object.keys(counters).length > 0;
    const detail = hasData || ['correlacion', 'score final', 'analisis ia'].includes(tool)
      ? toolDetail(tool, result, counters, context)
      : (existing?.detail || 'pendiente');

    return {
      tool,
      status: status || 'pending',
      detail,
      warning: result.warning || existing?.warning || null,
      error: result.error || existing?.error || null,
      duration_ms: existing?.duration_ms || result.metrics?.duration_ms || null,
      important: ['error', 'partial'].includes(status) || safeArray(result.findings).length > 0 || existing?.important === true
    };
  });
}

function dedupeCorrelations(correlations = []) {
  const swagger = [];
  const others = [];

  safeArray(correlations).forEach(correlation => {
    if (/swagger|openapi/i.test(`${correlation.title || ''} ${correlation.description || ''}`)) {
      swagger.push(correlation);
    } else {
      others.push(correlation);
    }
  });

  const grouped = [];
  if (swagger.length) {
    const relatedIds = Array.from(new Set(swagger.flatMap(c => safeArray(c.related_ids))));
    grouped.push({
      severity: 'info',
      title: 'Swagger/OpenAPI expone superficie API',
      chain: ['katana'],
      description: swagger.length === 1
        ? swagger[0].description
        : `Se agruparon ${swagger.length} correlaciones de Swagger/OpenAPI para evitar duplicados. Revisar recursos API expuestos en la seccion de superficie.`,
      related_ids: relatedIds
    });
  }

  const prepared = [];
  const seen = new Set();
  [...others, ...grouped].forEach(correlation => {
    const key = [
      correlation.title,
      safeArray(correlation.chain).join('>'),
      safeArray(correlation.related_ids).join(',')
    ].join('|').toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    prepared.push(correlation);
  });

  return prepared;
}

function analysisLimitations(context = {}) {
  const result = getToolResult(context.toolResults || context.tool_results || {}, 'trufflehog');
  const counters = getToolCounter(context.toolCounters || context.tool_counters || {}, 'trufflehog');
  const candidates = number(result.metrics?.recursos_candidatos ?? counters.recursos_candidatos);
  const downloaded = number(result.metrics?.recursos_descargados ?? counters.recursos_descargados);
  const failed = number(result.metrics?.recursos_fallidos ?? counters.recursos_fallidos);
  const limitations = [];

  if ((candidates > 0 && downloaded < candidates) || failed > 0) {
    limitations.push(`La busqueda de secretos tuvo cobertura parcial: ${downloaded}/${candidates} recursos descargados correctamente.`);
  }

  return limitations;
}

function prepareReportData(target, findings = [], context = {}) {
  const groups = buildGroups(safeArray(findings));
  const generatedAt = new Date();
  const toolResults = context.toolResults || context.tool_results || {};
  const toolCounters = context.toolCounters || context.tool_counters || {};
  const correlations = dedupeCorrelations(context.correlations);
  const timeline = buildCompleteTimeline(context.pipelineTimeline || context.pipeline_timeline, toolResults, toolCounters, {
    ...context,
    correlations
  });
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
    correlations,
    timeline,
    toolResults,
    toolCounters,
    gfCandidates: context.gfCandidates || context.gf_candidates || {},
    interestingSurface: interestingSurface(groups, context),
    recommendations: buildRecommendations(groups),
    allFindings: safeArray(findings),
    notices: [context.sqlmap_notice, context.ai_notice].filter(Boolean),
    limitations: analysisLimitations({ ...context, toolResults, toolCounters })
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
