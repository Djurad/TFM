const btnAnalizar = document.getElementById('btnAnalizar');
const btnGenerarInforme = document.getElementById('btnGenerarInforme');
const btnNuevoAnalisis = document.getElementById('btnNuevoAnalisis');
const promptInput = document.getElementById('prompt');
const estado = document.getElementById('estado');
const resultados = document.getElementById('resultados');

let ultimoAnalisis = null;
let filtroCategoria = 'todos';
let filtroSeveridad = 'todos';
let progressEvents = [];
let livePipeline = [];
let pasosCompletados = new Set();
let progresoActual = 0;

const pipelineOrder = [
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
  'score final'
];

const IA_PHASE = 'analisis ia';
const pipelineVisualOrder = [...pipelineOrder, IA_PHASE];
const TOTAL_PASOS = pipelineVisualOrder.length;

const PIPELINE_TOOL_DESCRIPTIONS = {
  subfinder: 'Descubrimiento de subdominios.',
  httpx: 'Identificacion de activos vivos y servicios HTTP/HTTPS.',
  headers: 'Revision de cabeceras de seguridad HTTP.',
  cookies: 'Analisis de cookies y flags defensivos.',
  httpsRedirect: 'Comprobacion de redireccion de HTTP a HTTPS.',
  tls: 'Analisis de certificados y configuracion TLS.',
  robotsSitemap: 'Revision de robots.txt y sitemap.xml.',
  ports: 'Deteccion de puertos y servicios expuestos.',
  feroxbuster: 'Descubrimiento de rutas ocultas o sensibles.',
  katana: 'Crawling para descubrir endpoints.',
  gau: 'Recuperacion de URLs historicas.',
  gf: 'Priorizacion de candidatos por patrones. No confirma vulnerabilidades.',
  nuclei: 'Deteccion por plantillas de vulnerabilidades conocidas.',
  dalfox: 'Validacion automatizada de XSS.',
  sqlmap: 'Validacion automatizada de SQL Injection.',
  trufflehog: 'Deteccion de secretos expuestos.',
  correlacion: 'Correlacion entre hallazgos de distintas herramientas.',
  'score final': 'Calculo del score de riesgo final.',
  [IA_PHASE]: 'Enriquecimiento del analisis con IA.'
};

const PIPELINE_LABELS = {
  subfinder: 'subfinder',
  httpx: 'httpx',
  headers: 'headers',
  cookies: 'cookies',
  httpsRedirect: 'https',
  tls: 'tls',
  robotsSitemap: 'robots',
  ports: 'ports',
  feroxbuster: 'ferox',
  katana: 'katana',
  gau: 'gau',
  gf: 'gf',
  nuclei: 'nuclei',
  dalfox: 'dalfox',
  sqlmap: 'sqlmap',
  trufflehog: 'secrets',
  correlacion: 'corr',
  'score final': 'score',
  [IA_PHASE]: 'ia'
};

const hardeningTypes = ['missing_security_header', 'insecure_cookie', 'missing_https_redirect', 'tls_certificate_issue', 'hardening'];
const gfTypes = ['gf-candidate', 'gf_candidate'];

const severityLabels = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO'
};

function setEstado(texto, tipo = '') {
  estado.textContent = texto;
  estado.className = tipo ? `status ${tipo}` : 'status';
}

function slugHerramienta(nombreHerramienta = '') {
  return String(nombreHerramienta || '')
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9_-]/g, '');
}

function actualizarProgreso(completadas, total = TOTAL_PASOS) {
  const totalSeguro = Math.max(Number(total) || 1, 1);
  const completadasSeguras = Math.min(Math.max(Number(completadas) || 0, 0), totalSeguro);
  const porcentaje = Math.round((completadasSeguras / totalSeguro) * 100);

  if (porcentaje < progresoActual) return;
  progresoActual = porcentaje;
}

function activarProgresoIndeterminado() {
  progresoActual = 0;
}

function esEstadoFinal(status = '') {
  return ['success', 'error', 'partial', 'skipped'].includes(normalizarEstadoPipeline(status));
}

function completarPaso(nombrePaso) {
  if (!nombrePaso || pasosCompletados.has(nombrePaso)) return;
  pasosCompletados.add(nombrePaso);
  actualizarProgreso(pasosCompletados.size, TOTAL_PASOS);
}

function sincronizarProgresoDesdePipeline() {
  livePipeline
    .filter(item => pipelineOrder.includes(item.tool) && esEstadoFinal(item.status))
    .forEach(item => completarPaso(item.tool));
}

function crearPipelineInicial() {
  return pipelineVisualOrder.map(tool => ({
    tool,
    status: 'pending',
    detail: 'pendiente',
    duration_ms: null,
    important: false
  }));
}

function normalizarToolTimeline(tool = '') {
  const raw = String(tool || '').trim();
  const lower = raw.toLowerCase().replace(/[_-]+/g, ' ').replace(/\s+/g, ' ');

  if (!lower) return '';
  if (lower === 'score' || lower === 'score final' || lower === 'score risk' || lower === 'final score') return 'score final';
  if (lower === 'analisis ia' || lower === 'analysis ia' || lower === 'analisis ai' || lower === 'ai analysis' || lower === 'ia') return IA_PHASE;
  if (lower.startsWith('ia/')) return IA_PHASE;
  if (lower === 'analisis') return 'subfinder';
  if (lower === 'httpsredirect' || lower === 'https redirect') return 'httpsRedirect';
  if (lower === 'robotssitemap' || lower === 'robots sitemap') return 'robotsSitemap';

  return pipelineVisualOrder.find(item => item.toLowerCase() === lower) || raw;
}

function detalleProgreso(evento = {}) {
  if (evento.count !== undefined && evento.count !== null) return `${evento.count} resultados`;
  return evento.message || 'ejecutando';
}

function actualizarPipelineVivo(evento = {}) {
  const tool = normalizarToolTimeline(evento.tool);
  if (!livePipeline.length) livePipeline = crearPipelineInicial();

  if (tool === IA_PHASE) {
    livePipeline = livePipeline.map(item => item.tool === IA_PHASE
      ? { ...item, status: evento.status || 'running', detail: detalleProgreso(evento) }
      : item
    );
    if (esEstadoFinal(evento.status)) completarPaso(IA_PHASE);
    setEstado(evento.message || '[*] analisis IA en curso...', esEstadoFinal(evento.status) ? 'success' : 'loading');
    resultados.innerHTML = renderPipelineTimeline(livePipeline);
    return;
  }

  const index = livePipeline.findIndex(item => item.tool === tool);
  if (index < 0) return;

  livePipeline = livePipeline.map((item, itemIndex) => {
    if (itemIndex < index && item.status === 'pending') {
      return { ...item, status: 'success', detail: item.detail === 'pendiente' ? 'completado' : item.detail };
    }
    if (itemIndex === index) {
      return {
        ...item,
        status: evento.status || 'running',
        detail: detalleProgreso(evento),
        important: item.important || ['error', 'failed', 'partial', 'timeout'].includes(String(evento.status || '').toLowerCase())
      };
    }
    return item;
  });

  sincronizarProgresoDesdePipeline();
  resultados.innerHTML = renderPipelineTimeline(livePipeline);
}

function renderProgreso(evento = {}) {
  const tool = evento.tool || 'analisis';
  const message = evento.message || 'Ejecutando analisis';
  const status = evento.status || 'running';
  progressEvents = [
    { tool, message, status },
    ...progressEvents
  ].slice(0, 8);

  actualizarPipelineVivo(evento);
  setEstado('');
}

async function leerAnalisisStream(response) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let resultado = null;

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';

    for (const line of lines) {
      if (!line.trim()) continue;
      const event = JSON.parse(line);

      if (event.type === 'progress') {
        renderProgreso(event);
      } else if (event.type === 'result') {
        resultado = event.data;
      } else if (event.type === 'error') {
        throw new Error(event.error || 'Error desconocido');
      }
    }
  }

  if (buffer.trim()) {
    const event = JSON.parse(buffer);
    if (event.type === 'result') resultado = event.data;
    if (event.type === 'error') throw new Error(event.error || 'Error desconocido');
  }

  if (!resultado) throw new Error('El servidor no devolvio resultado final.');
  return resultado;
}

function escaparHtml(valor) {
  return String(valor ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function fallback(valor, texto = '-') {
  if (valor === null || valor === undefined || valor === '') return texto;
  return valor;
}

function normalizarEstadoPipeline(status = '') {
  const lower = String(status || '').trim().toLowerCase();
  if (['pending', 'pendiente', 'wait', 'waiting', '..', '--'].includes(lower)) return 'pending';
  if (['run', 'running', 'ejecutando', 'loading', 'in_progress', 'in progress'].includes(lower)) return 'running';
  if (['ok', 'success', 'done', 'completed', 'complete', 'ready'].includes(lower)) return 'success';
  if (['error', 'fail', 'failed', 'failure'].includes(lower)) return 'error';
  if (['skipped', 'skip', 'omitido', 'omitted'].includes(lower)) return 'skipped';
  if (['partial', 'warning', 'warn', 'timeout'].includes(lower)) return 'partial';
  if (lower.includes('ejecut')) return 'running';
  if (lower.includes('error') || lower.includes('fail')) return 'error';
  return lower ? 'running' : 'pending';
}

function statusCorto(status = '') {
  const normalizado = normalizarEstadoPipeline(status);
  if (normalizado === 'success') return 'OK';
  if (normalizado === 'error') return 'FAIL';
  if (normalizado === 'skipped') return 'SKIP';
  if (normalizado === 'partial') return 'WARN';
  if (normalizado === 'pending') return '..';
  return 'RUN';
}

function normalizarGrupos(data = {}) {
  const findings = Array.isArray(data.findings) ? data.findings : [];
  const groups = data.groups || {};
  const pick = (...keys) => {
    for (const key of keys) {
      if (Array.isArray(groups[key])) return groups[key];
    }
    return null;
  };

  const confirmed = pick('confirmed', 'confirmadas') || findings.filter(f => f.type === 'confirmed_vulnerability' || (f.isVulnerability && f.confidence === 'high' && !f.isFalsePositiveLikely && !hardeningTypes.includes(f.type) && !gfTypes.includes(f.type)));
  const possible = pick('possible', 'posibles') || findings.filter(f => f.type === 'possible_vulnerability' || (f.isVulnerability && f.confidence === 'medium' && !f.isFalsePositiveLikely && !hardeningTypes.includes(f.type) && !gfTypes.includes(f.type)));
  const gfCandidates = pick('gfCandidates', 'gf_candidates') || findings.filter(f => f.tool === 'gf' || gfTypes.includes(f.type));
  const hardening = pick('hardening') || findings.filter(f => f.type === 'hardening' || hardeningTypes.includes(f.type) || f.category === 'hardening');
  const attackSurface = pick('attackSurface', 'superficie', 'surface') || findings.filter(f => f.type === 'attack_surface' || f.type === 'surface' || f.category === 'attack_surface');
  const informational = pick('informational', 'reconocimiento', 'recon') || findings.filter(f => f.type === 'informational' || f.type === 'reconocimiento' || (!f.isVulnerability && !gfCandidates.includes(f) && !attackSurface.includes(f) && !hardening.includes(f) && f.type !== 'discarded' && f.type !== 'false_positive'));
  const discarded = pick('discarded', 'descartados') || findings.filter(f => f.type === 'discarded');
  const falsePositives = pick('falsePositives', 'baja_confianza') || findings.filter(f => f.type === 'false_positive');

  return {
    confirmed,
    possible,
    gfCandidates,
    hardening,
    attackSurface,
    informational,
    discarded,
    falsePositives,
    confirmadas: confirmed,
    posibles: possible,
    gf_candidates: gfCandidates,
    superficie: attackSurface,
    reconocimiento: informational,
    descartados: discarded,
    baja_confianza: falsePositives
  };
}


function estadoHerramienta(status = '') {
  const lower = String(status || '').toLowerCase();
  if (['success', 'partial', 'timeout'].includes(lower)) {
    return { label: lower === 'success' ? '[ OK ]' : '[ WARN ]', className: lower === 'success' ? 'status-ok' : 'status-skipped' };
  }
  if (lower === 'skipped') return { label: '[ SKIP ]', className: 'status-skipped' };
  if (lower === 'error') return { label: '[ FAIL ]', className: 'status-error' };
  return { label: `[ ${String(status || '--').toUpperCase()} ]`, className: 'status-skipped' };
}

function obtenerDetalleHerramienta(tool, result, counter = {}) {
  if (tool === 'subfinder') return `${counter.subdominios_encontrados || result.parsed_count || 0} subdominios`;
  if (tool === 'httpx') {
    const parsedCount = Array.isArray(result.parsed) ? result.parsed.length : 0;
    const activos = counter.activos_vivos || result.metrics?.activos_vivos || result.parsed_count || parsedCount || 0;
    const respuestas = counter.respuestas_httpx || result.metrics?.respuestas_httpx || 0;
    return respuestas > activos && activos > 0
      ? `${respuestas} respuestas / ${activos} unico${activos === 1 ? '' : 's'}`
      : `${activos} vivos`;
  }
  if (tool === 'headers') return `${counter.cabeceras_ausentes || 0} ausentes / ${counter.banners_expuestos || 0} banners`;
  if (tool === 'cookies') return `${counter.cookies_inseguras || 0} inseguras / ${counter.cookies_sesion || 0} sesion / ${counter.cookies_analizadas || 0} total`;
  if (tool === 'httpsRedirect') return `${counter.redirecciona_https || 0} HTTPS ok / ${counter.http_sin_redirect || 0} HTTP abierto`;
  if (tool === 'tls') return `${counter.certificados_analizados || 0} certs / ${counter.expirados || 0} expirados / ${counter.proximos_expirar || 0} proximos`;
  if (tool === 'robotsSitemap') return `${counter.recursos_encontrados || 0} recursos / ${counter.rutas_sensibles || 0} sensibles`;
  if (tool === 'ports') return `${counter.puertos_abiertos || 0} abiertos / ${counter.puertos_datos || 0} datos${counter.source ? ` / ${counter.source}` : ''}`;
  if (tool === 'katana') return `${counter.endpoints_encontrados || result.parsed_count || 0} normalizados / ${counter.superficie_util || 0} superficie`;
  if (tool === 'gau') {
    const raw = counter.raw_urls || result.metrics?.raw_urls || 0;
    const selected = counter.seleccionadas_final || counter.endpoints_encontrados || result.parsed_count || 0;
    return `${raw} analizadas / ${selected} seleccionadas / ${counter.con_parametros || 0} params`;
  }
  if (tool === 'gf') return `${counter.xss || 0} XSS / ${counter.sqli || 0} SQLi / ${counter.ssrf || 0} SSRF / ${counter.redirect || 0} Redirect`;
  if (tool === 'feroxbuster') return `${counter.rutas_descubiertas || 0} rutas / ${counter.rutas_sensibles || 0} sensibles`;
  if (tool === 'trufflehog') return `${counter.secretos_confirmados || 0} confirmados / ${counter.secretos_posibles || 0} posibles / ${counter.recursos_fallidos || 0} fallidos`;
  if (tool === 'nuclei') return `${counter.vulnerabilidades_reales || 0} vulnerabilidades`;
  if (tool === 'sqlmap') return counter.no_ejecutada ? 'no ejecutada' : `${counter.confirmadas || 0} confirmadas / ${counter.posibles || 0} posibles`;
  return `${(result.findings || []).length} hallazgos`;
}

function categoriaFinding(finding = {}) {
  const type = String(finding.type || '').toLowerCase();
  const category = String(finding.category || '').toLowerCase();
  if (type === 'false_positive') return 'FALSO_POSITIVO';
  if (type === 'discarded' || finding.isFalsePositiveLikely) return 'DESCARTADO';
  if (gfTypes.includes(finding.type) || finding.tool === 'gf') return 'GF';
  if (type === 'hardening' || category === 'hardening' || hardeningTypes.includes(finding.type)) return 'HARDENING';
  if (type === 'attack_surface' || type === 'surface' || category === 'attack_surface') return 'SUPERFICIE';
  if (type === 'confirmed_vulnerability') return 'EXPLOTABLE';
  if (type === 'possible_vulnerability') return 'POSIBLE';
  if (!finding.isVulnerability || type === 'reconocimiento' || type === 'informational') return 'INFO';
  if (finding.confidence !== 'high') return 'POSIBLE';
  return 'EXPLOTABLE';
}

function buildAiReason(finding = {}) {
  const categoria = categoriaFinding(finding);
  const title = fallback(finding.title, 'este hallazgo');
  const impact = String(fallback(finding.impact, '')).trim();
  const description = String(fallback(finding.description, '')).trim();

  if (finding.ai_reason || finding.why_it_matters || finding.explicacion_ia) {
    return finding.ai_reason || finding.why_it_matters || finding.explicacion_ia;
  }

  if (finding.tool === 'gf' || gfTypes.includes(finding.type)) {
    return `IA: GF solo prioriza este endpoint por patron; requiere validacion manual o confirmacion con otra herramienta antes de reportarlo.`;
  }
  if (categoria === 'HARDENING') {
    return `IA: ${impact || description || 'Debilita una capa defensiva y puede aumentar el impacto de otras vulnerabilidades.'}`;
  }
  if (categoria === 'SUPERFICIE') {
    return `IA: Expone una zona util para revision manual; no implica explotacion directa, pero amplia la superficie de ataque.`;
  }
  if (categoria === 'INFO') {
    return `IA: Sirve como dato de inventario tecnico y ayuda a contextualizar la exposicion del objetivo.`;
  }
  if (categoria === 'DESCARTADO') {
    return `IA: Se mantiene con baja prioridad porque la evidencia no alcanza para tratarlo como hallazgo reportable.`;
  }
  if (finding.confidence === 'high') {
    return `IA: Se prioriza porque la herramienta reporta evidencia de alta confianza. ${impact || description || title}`;
  }
  return `IA: Es un posible problema que requiere validacion. ${impact || description || title}`;
}

function prioridadCategoria(categoria) {
  return {
    EXPLOTABLE: 0,
    POSIBLE: 1,
    HARDENING: 2,
    SUPERFICIE: 3,
    GF: 4,
    INFO: 5,
    DESCARTADO: 6,
    FALSO_POSITIVO: 7
  }[categoria] ?? 9;
}

function prioridadSeveridad(severity = 'info') {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[String(severity).toLowerCase()] ?? 5;
}

function prioridadHallazgo(finding = {}) {
  const categoria = categoriaFinding(finding);
  const severity = String(finding.severity || 'info').toLowerCase();
  if (categoria === 'EXPLOTABLE' && ['critical', 'high'].includes(severity)) return 0;
  if (categoria === 'POSIBLE' && severity === 'high') return 1;
  if (['EXPLOTABLE', 'POSIBLE'].includes(categoria) && severity === 'medium') return 2;
  if (categoria === 'HARDENING' && severity === 'medium') return 3;
  if (categoria === 'HARDENING' && severity === 'low') return 4;
  if (categoria === 'SUPERFICIE') return 5;
  if (categoria === 'GF') return 6;
  if (categoria === 'INFO') return 7;
  if (categoria === 'DESCARTADO' || categoria === 'FALSO_POSITIVO') return 8;
  return 8;
}

function claveFindingPriorizado(finding = {}) {
  const activo = finding.affected_url || finding.affected_asset || '';
  const parametro = finding.parametro || finding.parameter || finding.param || '';
  return [
    finding.type || '',
    activo,
    parametro,
    String(finding.title || '').replace(/candidato.*gf/i, '').toLowerCase()
  ].join('|').toLowerCase();
}

function deduplicarFindingsPriorizados(findings = []) {
  const mapa = new Map();
  const confirmadosPorActivo = new Set(
    findings
      .filter(f => ['dalfox', 'sqlmap'].includes(f.tool) && f.confidence === 'high')
      .map(f => f.affected_url || f.affected_asset || '')
      .filter(Boolean)
  );

  sortFindingsByPriority(findings).forEach(finding => {
    const activo = finding.affected_url || finding.affected_asset || '';
    if ((finding.tool === 'gf' || gfTypes.includes(finding.type)) && confirmadosPorActivo.has(activo)) return;
    const key = claveFindingPriorizado(finding);
    if (!mapa.has(key)) mapa.set(key, finding);
  });

  return Array.from(mapa.values());
}

function sortFindingsByPriority(findings = []) {
  return findings.slice().sort((a, b) => {
    const catA = categoriaFinding(a);
    const catB = categoriaFinding(b);
    return prioridadHallazgo(a) - prioridadHallazgo(b) ||
      prioridadSeveridad(a.severity) - prioridadSeveridad(b.severity) ||
      prioridadCategoria(catA) - prioridadCategoria(catB) ||
      String(a.tool || '').localeCompare(String(b.tool || ''));
  });
}

function aplicarFiltros(findings = []) {
  return findings.filter(finding => {
    const categoria = categoriaFinding(finding).toLowerCase();
    const severity = String(finding.severity || 'info').toLowerCase();
    const catOk = filtroCategoria === 'todos' ||
      (filtroCategoria === 'explotables' && categoria === 'explotable') ||
      (filtroCategoria === 'posibles' && categoria === 'posible') ||
      filtroCategoria === categoria;
    const sevOk = filtroSeveridad === 'todos' ||
      filtroSeveridad === severity ||
      (filtroSeveridad === 'high' && severity === 'critical');
    return catOk && sevOk;
  });
}

function renderFiltros() {
  const cats = ['todos', 'explotables', 'posibles', 'gf', 'hardening', 'superficie', 'info', 'descartado'];
  const sevs = ['todos', 'high', 'medium', 'low', 'info'];
  return `
    <div class="filter-row" data-filter-group="categoria">
      ${cats.map(cat => `<button type="button" class="filter-btn ${filtroCategoria === cat ? 'active' : ''}" data-filter-type="categoria" data-filter-value="${cat}">[ ${cat.toUpperCase()} ]</button>`).join('')}
    </div>
    <div class="filter-row" data-filter-group="severidad">
      ${sevs.map(sev => `<button type="button" class="filter-btn ${filtroSeveridad === sev ? 'active' : ''}" data-filter-type="severidad" data-filter-value="${sev}">[ ${sev.toUpperCase()} ]</button>`).join('')}
    </div>
  `;
}

function textoFinding(finding = {}) {
  return [
    finding.title,
    finding.description,
    finding.evidence,
    finding.type,
    finding.tool,
    finding.impact
  ].filter(Boolean).join(' ').toLowerCase();
}

function nivelVisualFinding(finding = {}) {
  const severity = String(finding.severity || '').toLowerCase();
  const categoria = categoriaFinding(finding);
  const texto = textoFinding(finding);

  if (categoria === 'GF') {
    if (severity === 'medium') return { key: 'medium', label: 'MEDIA', icon: 'fa-crosshairs' };
    return { key: 'low', label: 'BAJA', icon: 'fa-crosshairs' };
  }
  if (categoria === 'POSIBLE') {
    if (severity === 'high' || severity === 'critical') return { key: 'high', label: 'ALTA', icon: 'fa-bug' };
    if (severity === 'medium') return { key: 'medium', label: 'MEDIA', icon: 'fa-bug' };
    return { key: 'low', label: 'BAJA', icon: 'fa-bug' };
  }
  if (['critical'].includes(severity) || (finding.confidence === 'high' && categoria === 'EXPLOTABLE') || (categoria === 'EXPLOTABLE' && /\b(rce|sql injection|sqlmap|xss|dalfox|nuclei|secret|credential|trufflehog)\b/.test(texto))) {
    return { key: 'critical', label: 'CRITICA', icon: 'fa-triangle-exclamation' };
  }
  if (['high'].includes(severity) || categoria === 'POSIBLE' || /\b(posible|explotable|redirect|ssrf|sqli)\b/.test(texto)) {
    return { key: 'high', label: 'ALTA', icon: 'fa-bug' };
  }
  if (['medium'].includes(severity) || categoria === 'GF' || /\b(gf|candidate|candidato)\b/.test(texto)) {
    return { key: 'medium', label: 'MEDIA', icon: 'fa-eye' };
  }
  if (['low'].includes(severity) || ['SUPERFICIE', 'HARDENING'].includes(categoria) || /\b(missing header|header|cookie|tls|https|robots|sitemap|surface|hardening)\b/.test(texto)) {
    return { key: 'low', label: 'BAJA', icon: 'fa-shield-halved' };
  }
  return { key: 'info', label: 'INFO', icon: 'fa-circle-info' };
}

function grupoVisualFinding(finding = {}) {
  const categoria = categoriaFinding(finding);
  if (categoria === 'EXPLOTABLE') return 'confirmadas';
  if (categoria === 'POSIBLE') return 'posibles';
  if (categoria === 'GF') return 'gfCandidates';
  if (categoria === 'SUPERFICIE' || finding.type === 'surface') return 'superficie';
  if (categoria === 'HARDENING') return 'hardening';
  if (categoria === 'DESCARTADO' || categoria === 'FALSO_POSITIVO') return 'descartados';
  return 'info';
}

function descripcionCorta(finding = {}) {
  return fallback(finding.description || finding.impact || buildAiReason(finding), 'Sin descripcion disponible.');
}

function evidenciaFinding(finding = {}) {
  return finding.evidence || finding.raw_reference || finding.affected_url || finding.affected_asset || '';
}

function renderFindingDetail(label, icon, value, fallbackText) {
  const content = fallback(value, fallbackText);
  return `
    <div class="finding-detail">
      <strong><i class="fas ${escaparHtml(icon)}"></i> ${escaparHtml(label)}</strong>
      <p>${escaparHtml(content)}</p>
    </div>
  `;
}

function renderFindingCard(finding = {}) {
  const nivel = nivelVisualFinding(finding);
  const categoria = categoriaFinding(finding);
  return `
    <article class="finding-card finding-${escaparHtml(nivel.key)}">
      <header>
        <span class="finding-severity"><i class="fas ${escaparHtml(nivel.icon)}"></i> ${escaparHtml(nivel.label)}</span>
        <span class="terminal-badge">[${escaparHtml(fallback(finding.tool, 'tool'))}]</span>
      </header>
      <h3>${escaparHtml(fallback(finding.title, 'Hallazgo sin titulo'))}</h3>
      <p>${escaparHtml(descripcionCorta(finding))}</p>
      <div class="finding-meta">
        <span><i class="fas fa-layer-group"></i> ${escaparHtml(categoria)}</span>
        <span><i class="fas fa-crosshairs"></i> ${escaparHtml(fallback(finding.affected_url || finding.affected_asset || ultimoAnalisis?.target, '-'))}</span>
      </div>
      <div class="finding-analysis">
        ${renderFindingDetail('Impacto', 'fa-bolt', finding.impact, 'No disponible. Requiere revision tecnica segun el contexto del activo.')}
        ${renderFindingDetail('Recomendacion', 'fa-screwdriver-wrench', finding.recommendation, 'No disponible. Validar el hallazgo y aplicar la remediacion correspondiente.')}
      </div>
      ${evidenciaFinding(finding) ? `<pre class="finding-evidence">${escaparHtml(evidenciaFinding(finding))}</pre>` : ''}
    </article>
  `;
}

function renderGrupoHallazgos(titulo, icono, findings = [], abierto = false) {
  return `
    <details class="finding-group" ${abierto ? 'open' : ''}>
      <summary>
        <span><i class="fas ${escaparHtml(icono)}"></i> ${escaparHtml(titulo)}</span>
        <strong>${escaparHtml(findings.length)}</strong>
      </summary>
      <div class="finding-grid">
        ${findings.length ? findings.map(renderFindingCard).join('') : '<p class="empty">Sin hallazgos en esta categoria.</p>'}
      </div>
    </details>
  `;
}

function renderNotaGf() {
  return `
    <div class="finding-note">
      Estos elementos no son vulnerabilidades confirmadas. GF solo prioriza URLs que coinciden con patrones habituales. Requieren validacion manual o confirmacion por herramientas como Dalfox, SQLMap o Nuclei.
    </div>
  `;
}

function renderListaPriorizada(findings = []) {
  const filtrados = aplicarFiltros(deduplicarFindingsPriorizados(findings));
  const grupos = {
    confirmadas: [],
    posibles: [],
    gfCandidates: [],
    superficie: [],
    hardening: [],
    info: [],
    descartados: []
  };

  filtrados.forEach(finding => {
    grupos[grupoVisualFinding(finding)].push(finding);
  });

  return `
    <section class="terminal-card prioritized-section">
      <div class="group-header">
        <h2>HALLAZGOS OBTENIDOS</h2>
        <span>${escaparHtml(filtrados.length)}</span>
      </div>
      ${renderFiltros()}
      <div class="finding-groups">
        ${renderGrupoHallazgos('Vulnerabilidades confirmadas', 'fa-triangle-exclamation', grupos.confirmadas, true)}
        ${renderGrupoHallazgos('Posibles vulnerabilidades', 'fa-bug', grupos.posibles, true)}
        ${grupos.gfCandidates.length ? renderNotaGf() : ''}
        ${renderGrupoHallazgos('Candidatos priorizados por GF', 'fa-crosshairs', grupos.gfCandidates, grupos.gfCandidates.length > 0)}
        ${renderGrupoHallazgos('Superficie expuesta', 'fa-eye', grupos.superficie)}
        ${renderGrupoHallazgos('Hardening / Configuracion', 'fa-shield-halved', grupos.hardening)}
        ${renderGrupoHallazgos('Informativo', 'fa-circle-info', grupos.info)}
        ${renderGrupoHallazgos('Descartados / no concluyentes', 'fa-ban', grupos.descartados)}
      </div>
    </section>
  `;
}

function barraAsciiRiesgo(score) {
  if (score === null || score === undefined) return '[--------------------] N/D';
  const bloques = 20;
  const llenos = Math.round((Number(score) / 100) * bloques);
  return `[${'#'.repeat(llenos)}${'-'.repeat(bloques - llenos)}]`;
}

function clampPercent(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return 0;
  return Math.max(0, Math.min(100, number));
}

function contadorTool(data = {}, path, fallbackValue = 0) {
  const parts = String(path || '').split('.');
  let current = data.tool_counters || {};
  for (const part of parts) {
    if (!current || current[part] === undefined) return fallbackValue;
    current = current[part];
  }
  return current ?? fallbackValue;
}

function canonicalToolName(tool = '') {
  const lower = String(tool || 'otra').toLowerCase();
  const names = {
    httpsredirect: 'httpsRedirect',
    robotssitemap: 'robotsSitemap',
    ferox: 'feroxbuster'
  };
  return names[lower] || lower;
}

function buildSeverityCounts(grupos = {}) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  [
    ...(grupos.confirmadas || []),
    ...(grupos.posibles || []),
    ...(grupos.gfCandidates || []),
    ...(grupos.hardening || []),
    ...(grupos.superficie || []),
    ...(grupos.reconocimiento || []),
    ...(grupos.descartados || [])
  ].forEach(finding => {
    const severity = String(finding.severity || 'info').toLowerCase();
    if (counts[severity] !== undefined) counts[severity] += 1;
  });
  return counts;
}

function buildToolCounts(data = {}, findings = []) {
  const resultCounts = {};
  Object.entries(data.tool_results || {}).forEach(([tool, result]) => {
    const name = canonicalToolName(tool);
    const value = Array.isArray(result.findings) && result.findings.length
      ? result.findings.length
      : Number(result.parsed_count || 0);
    resultCounts[name] = Math.max(resultCounts[name] || 0, value);
  });
  const findingCounts = {};
  findings.forEach(finding => {
    const name = canonicalToolName(finding.tool || 'otra');
    findingCounts[name] = (findingCounts[name] || 0) + 1;
  });
  const counts = { ...resultCounts };
  Object.entries(findingCounts).forEach(([tool, value]) => {
    counts[tool] = Math.max(counts[tool] || 0, value);
  });
  return Object.entries(counts)
    .map(([label, value]) => ({ label, value }))
    .filter(item => item.value > 0)
    .sort((a, b) => b.value - a.value || a.label.localeCompare(b.label))
    .slice(0, 8);
}

function renderMetricStrip(data = {}, grupos = {}) {
  const httpxResult = getToolResult(data, 'httpx');
  const httpxParsedCount = Array.isArray(httpxResult.parsed) ? httpxResult.parsed.length : 0;
  const httpxCounter = Number(contadorTool(data, 'httpx.activos_vivos', 0) || 0);
  const activosVivos =
    httpxCounter ||
    Number(httpxResult.metrics?.activos_vivos || 0) ||
    (Number(httpxResult.parsed_count || 0) || httpxParsedCount);

  const metrics = [
    { label: 'Confirmadas', value: grupos.confirmadas?.length || 0, className: 'metric-critical' },
    { label: 'Posibles', value: grupos.posibles?.length || 0, className: 'metric-medium' },
    { label: 'Candidatos GF', value: grupos.gfCandidates?.length || 0, className: 'metric-info' },
    { label: 'Hardening', value: grupos.hardening?.length || 0, className: 'metric-low' },
    { label: 'Superficie', value: grupos.superficie?.length || 0, className: 'metric-info' },
    { label: 'Informativos', value: grupos.reconocimiento?.length || 0, className: 'metric-cyan' },
    { label: 'Descartados', value: (grupos.descartados?.length || 0) + (grupos.baja_confianza?.length || 0), className: 'metric-info' },
    { label: 'Endpoints', value: Math.max(contadorTool(data, 'katana.endpoints_encontrados'), contadorTool(data, 'gau.endpoints_encontrados')), className: 'metric-cyan' },
    { label: 'Activos vivos', value: activosVivos, className: 'metric-cyan' },
    { label: 'Puertos', value: contadorTool(data, 'ports.puertos_abiertos'), className: 'metric-amber' },
    { label: 'Secretos', value: Number(contadorTool(data, 'trufflehog.secretos_confirmados')) + Number(contadorTool(data, 'trufflehog.secretos_posibles')), className: 'metric-critical' }
  ];

  return `
    <div class="metric-strip">
      ${metrics.map(metric => `
        <div class="metric-tile ${escaparHtml(metric.className)}">
          <strong>${escaparHtml(metric.value)}</strong>
          <span>${escaparHtml(metric.label)}</span>
        </div>
      `).join('')}
    </div>
  `;
}

function renderSeverityChart(counts = {}) {
  const rows = [
    ['critical', 'Critical'],
    ['high', 'High'],
    ['medium', 'Medium'],
    ['low', 'Low'],
    ['info', 'Info']
  ];
  const max = Math.max(1, ...rows.map(([key]) => Number(counts[key] || 0)));

  return `
    <div class="chart-bars severity-chart">
      ${rows.map(([key, label]) => {
        const value = Number(counts[key] || 0);
        const width = Math.max(value > 0 ? 4 : 0, Math.round((value / max) * 100));
        return `
          <div class="chart-row severity-${escaparHtml(key)}">
            <span>${escaparHtml(label)}</span>
            <div class="chart-track"><i style="width:${escaparHtml(width)}%"></i></div>
            <strong>${escaparHtml(value)}</strong>
          </div>
        `;
      }).join('')}
    </div>
  `;
}

function renderToolChart(items = []) {
  const max = Math.max(1, ...items.map(item => Number(item.value || 0)));
  return `
    <div class="chart-bars tool-chart">
      ${items.length ? items.map((item, index) => {
        const width = Math.max(4, Math.round((Number(item.value || 0) / max) * 100));
        return `
          <div class="chart-row tool-row tool-accent-${index % 4}">
            <span>${escaparHtml(item.label)}</span>
            <div class="chart-track"><i style="width:${escaparHtml(width)}%"></i></div>
            <strong>${escaparHtml(item.value)}</strong>
          </div>
        `;
      }).join('') : '<p class="empty">Sin datos de herramientas disponibles.</p>'}
    </div>
  `;
}

function renderDashboard(data = {}, grupos = {}, findings = []) {
  const score = data.risk_score;
  const level = data.risk_level || 'N/D';
  const grade = data.risk_grade || 'N/D';
  const scoreText = score === null || score === undefined ? 'N/D' : `${score}/100`;
  const scorePercent = score === null || score === undefined ? 0 : clampPercent(score);
  const severityCounts = buildSeverityCounts(grupos);
  const toolCounts = buildToolCounts(data, findings);

  return `
    <section class="security-dashboard">
      <div class="dashboard-head">
        <div>
          <h2>Dashboard de riesgo</h2>
          <p>Vista sintetica del analisis, severidades y actividad por herramienta.</p>
        </div>
        <span class="terminal-badge status-ok">[ LIVE REPORT ]</span>
      </div>
      ${renderMetricStrip(data, grupos)}
      <div class="dashboard-grid">
        <article class="terminal-card risk-visual-card">
          <div class="group-header">
            <h2>RIESGO FINAL</h2>
            <span>${escaparHtml(grade)}</span>
          </div>
          <div class="risk-score-value">${escaparHtml(scoreText)} <span>[${escaparHtml(String(level).toUpperCase())}]</span></div>
          <div class="risk-progress" aria-label="Score global de riesgo">
            <i style="width:${escaparHtml(scorePercent)}%"></i>
          </div>
          <div class="risk-scale"><span>0</span><span>25</span><span>50</span><span>75</span><span>100</span></div>
        </article>
        <article class="terminal-card chart-card">
          <div class="group-header">
            <h2>SEVERIDAD GLOBAL</h2>
            <span>${escaparHtml(Object.values(severityCounts).reduce((sum, value) => sum + value, 0))}</span>
          </div>
          ${renderSeverityChart(severityCounts)}
        </article>
        <article class="terminal-card chart-card">
          <div class="group-header">
            <h2>HALLAZGOS POR HERRAMIENTA</h2>
            <span>${escaparHtml(toolCounts.length)}</span>
          </div>
          ${renderToolChart(toolCounts)}
        </article>
      </div>
    </section>
  `;
}

function renderScore(data = {}) {
  const score = data.risk_score;
  const level = data.risk_level || 'N/D';
  const grade = data.risk_grade || 'N/D';
  const scoreText = score === null || score === undefined ? 'N/D' : `${score}/100`;
  return `
    <section class="terminal-card risk-score-card">
      <div class="group-header">
        <h2>RIESGO FINAL</h2>
        <span>${escaparHtml(grade)}</span>
      </div>
      <div class="risk-score-value">${escaparHtml(scoreText)} <span>[${escaparHtml(String(level).toUpperCase())}]</span></div>
      <div class="risk-bar">${escaparHtml(barraAsciiRiesgo(score))}</div>
      <p class="terminal-subtle">risk_score usa riesgo acumulado: 0 es bajo, 100 es critico.</p>
    </section>
  `;
}

function pluralizar(value, singular, plural = `${singular}s`) {
  return `${value} ${Number(value) === 1 ? singular : plural}`;
}

function scoreToolData(data = {}) {
  if (!data || typeof data !== 'object') return 0;
  let score = 0;
  if (Array.isArray(data.parsed)) score += data.parsed.length * 3;
  if (Array.isArray(data.findings)) score += data.findings.length * 3;
  if (Number(data.parsed_count || 0) > 0) score += Number(data.parsed_count || 0) * 2;
  if (data.metrics && typeof data.metrics === 'object') score += Object.keys(data.metrics).length;
  if (data.raw) score += 1;
  if (data.status) score += 1;
  return score;
}

function getToolStores(scanResult = {}) {
  return [
    scanResult.toolResults || {},
    scanResult.tool_results || {},
    scanResult.herramientas || {}
  ].filter(store => store && typeof store === 'object');
}

function getToolResult(scanResult = {}, toolKey = '') {
  const wanted = normalizarToolTimeline(toolKey);
  const candidates = [];

  getToolStores(scanResult).forEach(store => {
    if (store[toolKey]) candidates.push(store[toolKey]);
    if (store[wanted]) candidates.push(store[wanted]);
    Object.entries(store).forEach(([key, value]) => {
      if (normalizarToolTimeline(key) === wanted) candidates.push(value);
    });
  });

  return candidates
    .filter(item => item && typeof item === 'object')
    .sort((a, b) => scoreToolData(b) - scoreToolData(a))[0] || {};
}

function getToolCounter(scanResult = {}, toolKey = '') {
  const stores = [
    scanResult.toolCounters || {},
    scanResult.tool_counters || {}
  ];
  const wanted = normalizarToolTimeline(toolKey);
  const candidates = [];

  stores.forEach(counters => {
    if (!counters || typeof counters !== 'object') return;
    if (counters[toolKey]) candidates.push(counters[toolKey]);
    if (counters[wanted]) candidates.push(counters[wanted]);
    Object.entries(counters).forEach(([key, value]) => {
      if (normalizarToolTimeline(key) === wanted) candidates.push(value);
    });
  });

  return candidates
    .filter(item => item && typeof item === 'object')
    .sort((a, b) => Object.keys(b).length - Object.keys(a).length)[0] || {};
}

function timelineDetailValido(detail = '') {
  const lower = String(detail || '').trim().toLowerCase();
  return lower && !['pendiente', '--', '-', 'pending'].includes(lower);
}

function timelineSummaryValido(summary = '') {
  const lower = String(summary || '').trim().toLowerCase();
  if (!lower) return false;
  if (['pendiente', '--', '-', 'pending'].includes(lower)) return false;
  if (/^(ejecutando|buscando|analizando|validando|calculando|enriqueciendo)/i.test(lower)) return false;
  if (/finalizad[oa]$/.test(lower)) return false;
  return true;
}

function getTimelineSummary(timelineItem = {}) {
  const candidates = [
    timelineItem.summary,
    timelineItem.resumen,
    timelineItem.resultado,
    timelineItem.result,
    timelineItem.detail
  ];

  return candidates.find(timelineSummaryValido) || '';
}

function arrayDirectoHerramienta(scanResult = {}, toolKey = '') {
  const direct = scanResult[toolKey];
  if (Array.isArray(direct)) return direct;
  const herramientas = scanResult.herramientas || {};
  const fromHerramientas = herramientas[toolKey] || herramientas[normalizarToolTimeline(toolKey)];
  if (Array.isArray(fromHerramientas)) return fromHerramientas;
  return [];
}

function getHttpxSummary(scanResult = {}, toolData = {}, timelineItem = {}) {
  const timelineSummary = getTimelineSummary(timelineItem);
  const parsed = Array.isArray(toolData.parsed)
    ? toolData.parsed
    : arrayDirectoHerramienta(scanResult, 'httpx');
  const countResponses = parsed.length;
  const metricAssets = Number(toolData.metrics?.activos_vivos || 0);
  const metricResponses = Number(toolData.metrics?.respuestas_httpx || 0);
  const parsedCount = Number(toolData.parsed_count || 0);
  const uniqueAssets = new Set(
    parsed
      .map(item => item?.finalUrl || item?.final_url || item?.url || item?.input)
      .filter(Boolean)
  );

  if (metricAssets > 0 && metricResponses > metricAssets) {
    return `${metricResponses} respuestas / ${metricAssets} activo${metricAssets === 1 ? '' : 's'} vivo${metricAssets === 1 ? '' : 's'}`;
  }
  if (uniqueAssets.size > 0 && countResponses > uniqueAssets.size) {
    return `${countResponses} respuestas / ${uniqueAssets.size} activo${uniqueAssets.size === 1 ? '' : 's'} vivo${uniqueAssets.size === 1 ? '' : 's'}`;
  }
  if (uniqueAssets.size > 0) return pluralizar(uniqueAssets.size, 'activo vivo', 'activos vivos');
  if (countResponses > 0) return pluralizar(countResponses, 'respuesta');
  if (metricAssets > 0) return pluralizar(metricAssets, 'activo vivo', 'activos vivos');
  if (parsedCount > 0) return pluralizar(parsedCount, 'respuesta');
  if (timelineSummary) return timelineSummary;
  return '0 activos vivos';
}

function getToolSummary(toolKey, timelineItem = {}, scanResult = {}) {
  const result = getToolResult(scanResult, toolKey);
  const counter = getToolCounter(scanResult, toolKey);
  const status = normalizarEstadoPipeline(timelineItem.status || result.status);
  const timelineSummary = getTimelineSummary(timelineItem);

  if (toolKey === 'httpx') return getHttpxSummary(scanResult, result, timelineItem);
  if (timelineSummary) return timelineSummary;
  if (status === 'running' && timelineDetailValido(timelineItem.detail)) return timelineItem.detail;

  if (toolKey === 'subfinder') {
    const parsedCount = Array.isArray(result.parsed) ? result.parsed.length : 0;
    const directCount = arrayDirectoHerramienta(scanResult, 'subfinder').length;
    const count = counter.subdominios_encontrados ?? result.parsed_count ?? (parsedCount || directCount || 0);
    return count ? pluralizar(count, 'subdominio') : '0 resultados';
  }
  if (toolKey === 'headers') {
    const missing = counter.cabeceras_ausentes ?? result.metrics?.cabeceras_ausentes ?? 0;
    const banners = counter.banners_expuestos ?? result.metrics?.banners_expuestos ?? 0;
    return missing || banners ? `${missing} ausentes / ${banners} banners` : 'sin hallazgos';
  }
  if (toolKey === 'cookies') {
    const insecure = counter.cookies_inseguras ?? result.metrics?.cookies_inseguras ?? 0;
    const session = counter.cookies_sesion ?? result.metrics?.cookies_sesion ?? 0;
    return insecure || session ? `${insecure} inseguras / ${session} sesion` : 'sin hallazgos';
  }
  if (toolKey === 'httpsRedirect') {
    const missing = counter.http_sin_redirect ?? result.metrics?.http_sin_redirect ?? 0;
    const ok = counter.redirecciona_https ?? result.metrics?.redirecciona_https ?? 0;
    if (missing) return `${missing} HTTP sin redirect`;
    if (ok) return 'redirige a HTTPS';
    return 'sin datos';
  }
  if (toolKey === 'tls') {
    const certs = counter.certificados_analizados ?? result.metrics?.certificados_analizados ?? 0;
    const expired = counter.expirados ?? result.metrics?.expirados ?? 0;
    const near = counter.proximos_expirar ?? result.metrics?.proximos_expirar ?? 0;
    if (near) return `${certs} cert / ${near} proximos a expirar`;
    return `${certs} cert / ${expired} expirados`;
  }
  if (toolKey === 'robotsSitemap') {
    const resources = counter.recursos_encontrados ?? result.metrics?.recursos_encontrados ?? 0;
    const sensitive = counter.rutas_sensibles ?? result.metrics?.rutas_sensibles ?? 0;
    return `${resources} recursos / ${sensitive} sensibles`;
  }
  if (toolKey === 'ports') {
    const open = counter.puertos_abiertos ?? result.metrics?.puertos_abiertos ?? 0;
    return pluralizar(open, 'abierto', 'abiertos');
  }
  if (toolKey === 'feroxbuster') {
    const routes = counter.rutas_descubiertas ?? result.metrics?.endpoints_encontrados ?? 0;
    const sensitive = counter.rutas_sensibles ?? result.metrics?.rutas_interesantes ?? 0;
    return `${routes} rutas / ${sensitive} sensibles`;
  }
  if (toolKey === 'katana') {
    const parsedCount = Array.isArray(result.parsed) ? result.parsed.length : 0;
    const endpoints = counter.endpoints_encontrados ?? result.metrics?.endpoints_normalizados ?? result.parsed_count ?? parsedCount;
    return pluralizar(endpoints, 'endpoint');
  }
  if (toolKey === 'gau') {
    const parsedCount = Array.isArray(result.parsed) ? result.parsed.length : 0;
    const raw = counter.raw_urls ?? result.metrics?.raw_urls ?? 0;
    const urls = counter.seleccionadas_final ?? result.metrics?.seleccionadas_final ?? counter.endpoints_encontrados ?? result.metrics?.endpoints_encontrados ?? result.parsed_count ?? parsedCount;
    const params = counter.con_parametros ?? result.metrics?.con_parametros ?? 0;
    return `${raw} analizadas / ${urls} seleccionadas / ${params} params`;
  }
  if (toolKey === 'gf') {
    const xss = counter.xss ?? result.metrics?.xss ?? 0;
    const sqli = counter.sqli ?? result.metrics?.sqli ?? 0;
    const ssrf = counter.ssrf ?? result.metrics?.ssrf ?? 0;
    const total = xss + sqli + ssrf + (counter.redirect || 0) + (counter.lfi || 0) + (counter.rce || 0);
    return xss || sqli || ssrf ? `${xss} XSS / ${sqli} SQLi / ${ssrf} SSRF` : pluralizar(total, 'candidato');
  }
  if (toolKey === 'nuclei') {
    const vulns = counter.vulnerabilidades_reales ?? result.metrics?.vulnerabilidades_reales ?? 0;
    return pluralizar(vulns, 'vulnerabilidad', 'vulnerabilidades');
  }
  if (toolKey === 'dalfox') {
    const findings = Array.isArray(result.findings) ? result.findings : [];
    const parsedCount = Array.isArray(result.parsed) ? result.parsed.length : Number(result.parsed_count || 0);
    const confirmed = result.metrics?.confirmadas ?? findings.filter(f =>
      f.type === 'confirmed_vulnerability' ||
      f.confirmed === true ||
      f.confidence === 'high'
    ).length;
    if (confirmed) return `${confirmed} XSS confirmado${Number(confirmed) === 1 ? '' : 's'}`;
    return `${findings.length || parsedCount || 0} hallazgos`;
  }
  if (toolKey === 'sqlmap') {
    if (counter.no_ejecutada) return 'no ejecutada';
    const confirmed = counter.confirmadas ?? 0;
    const possible = counter.posibles ?? 0;
    return `${confirmed} confirmadas / ${possible} posible${Number(possible) === 1 ? '' : 's'}`;
  }
  if (toolKey === 'trufflehog') {
    const secrets = Number(counter.secretos_confirmados || 0) + Number(counter.secretos_posibles || 0);
    return pluralizar(secrets, 'secreto');
  }
  if (toolKey === 'correlacion') {
    const count = Array.isArray(scanResult.correlations) ? scanResult.correlations.length : 0;
    return pluralizar(count, 'relacion', 'relaciones');
  }
  if (toolKey === 'score final') {
    if (scanResult.risk_score === null || scanResult.risk_score === undefined) return timelineItem.detail || 'pendiente';
    return `${scanResult.risk_score}/100 riesgo ${scanResult.risk_level || 'N/D'}`;
  }
  if (toolKey === IA_PHASE) {
    if (scanResult.ai_notice) return scanResult.ai_notice;
    if (scanResult.status === 'completed') return 'analisis completado';
    return timelineItem.detail || 'pendiente';
  }

  if (timelineDetailValido(timelineItem.detail)) return timelineItem.detail;
  return `${Array.isArray(result.findings) ? result.findings.length : result.parsed_count || 0} hallazgos`;
}

function inferPipelineStatus(toolKey, timelineItem = {}, scanResult = {}) {
  const result = getToolResult(scanResult, toolKey);
  if (timelineItem.status) return normalizarEstadoPipeline(timelineItem.status);
  if (result.status) return normalizarEstadoPipeline(result.status);
  if (toolKey === 'correlacion' && Array.isArray(scanResult.correlations)) return 'success';
  if (toolKey === 'score final' && scanResult.risk_score !== undefined && scanResult.risk_score !== null) return 'success';
  if (toolKey === IA_PHASE && scanResult.status === 'completed') return scanResult.ai_notice ? 'partial' : 'success';
  return 'pending';
}

function buildPipelineSteps(items = [], scanResult = {}) {
  const sourceItems = Array.isArray(items)
    ? items
    : Array.isArray(items?.pipeline_timeline)
      ? items.pipeline_timeline
      : [];
  const byKey = new Map();

  sourceItems.forEach(item => {
    const key = normalizarToolTimeline(item.tool || item.key || item.name);
    if (pipelineVisualOrder.includes(key)) byKey.set(key, item);
  });

  return pipelineVisualOrder.map(key => {
    const item = byKey.get(key) || {};
    const status = inferPipelineStatus(key, item, scanResult);
    const summary = getToolSummary(key, item, scanResult);
    const rawStatus = item.status || getToolResult(scanResult, key).status || status;

    return {
      key,
      label: PIPELINE_LABELS[key] || key,
      fullName: key,
      description: PIPELINE_TOOL_DESCRIPTIONS[key] || 'Paso del pipeline.',
      status,
      summary,
      rawStatus,
      duration_ms: item.duration_ms || null,
      important: item.important === true
    };
  });
}

function renderPipelineTooltip(step) {
  return `
    <div class="pipeline-tooltip" role="tooltip">
      <strong>${escaparHtml(step.fullName || step.label)}</strong>
      <p>${escaparHtml(step.description)}</p>
      <dl>
        <div><dt>Estado</dt><dd>${escaparHtml(step.status)}</dd></div>
        <div><dt>Resultado</dt><dd>${escaparHtml(step.summary || 'pendiente')}</dd></div>
        ${step.duration_ms ? `<div><dt>Tiempo</dt><dd>${escaparHtml(step.duration_ms)} ms</dd></div>` : ''}
      </dl>
    </div>
  `;
}

function renderPipelineStep(step, index, total) {
  const edgeClass = index === 0 ? 'is-first' : index === total - 1 ? 'is-last' : '';
  const aria = `${step.fullName || step.label}: ${step.description} Estado: ${step.status}. Resultado: ${step.summary || 'pendiente'}`;

  return `
    <div id="node-${escaparHtml(slugHerramienta(step.key))}" role="listitem" class="pipeline-step ${edgeClass} pipeline-${escaparHtml(step.status)} ${step.important ? 'is-important' : ''}">
      <button type="button" class="pipeline-dot step-dot ${escaparHtml(step.status)}" aria-label="${escaparHtml(aria)}" title="${escaparHtml(aria)}">
        <span>${escaparHtml(statusCorto(step.status))}</span>
      </button>
      <span class="pipeline-step-label">${escaparHtml(step.label)}</span>
      ${renderPipelineTooltip(step)}
    </div>
  `;
}

function renderPipelineTimeline(items = [], scanResult = {}) {
  const steps = buildPipelineSteps(items, scanResult);
  const completed = steps.filter(step => ['success', 'error', 'partial', 'skipped'].includes(step.status)).length;

  return `
    <section class="terminal-card pipeline-card">
      <div class="group-header">
        <h2>PIPELINE DE EJECUCION</h2>
        <span>${escaparHtml(completed)}/${escaparHtml(steps.length)}</span>
      </div>
      <div class="pipeline-timeline-scroll">
        <div class="pipeline-stepper" role="list" aria-label="Pipeline de ejecucion">
          ${steps.map((step, index) => renderPipelineStep(step, index, steps.length)).join('')}
        </div>
      </div>
    </section>
  `;
}

function renderCorrelaciones(correlations = []) {
  return `
    <section class="terminal-card correlations-card">
      <div class="group-header">
        <h2>CORRELACIONES DETECTADAS</h2>
        <span>${escaparHtml(correlations.length)}</span>
      </div>
      ${correlations.length ? `
        <div class="correlation-list">
          ${correlations.map(correlation => `
            <article class="correlation-row severity-${escaparHtml(correlation.severity || 'info')}">
              <header>
                <span class="terminal-badge severity-${escaparHtml(correlation.severity || 'info')}">[${escaparHtml(String(correlation.severity || 'info').toUpperCase())}]</span>
                <strong>${escaparHtml(correlation.title || 'Correlacion')}</strong>
              </header>
              <p>${escaparHtml(correlation.description || '-')}</p>
              <div class="priority-meta">CADENA: ${escaparHtml((correlation.chain || []).join(' -> ') || '--')}</div>
            </article>
          `).join('')}
        </div>
      ` : '<p class="empty">Sin correlaciones automaticas destacables.</p>'}
    </section>
  `;
}

function renderFindings(findings = [], groups = null) {
  resultados.innerHTML = '';
  const data = ultimoAnalisis || { findings, groups };
  const grupos = normalizarGrupos(data);
  const infoFindings = grupos.reconocimiento || [];
  const allFindings = [
    ...grupos.confirmadas,
    ...grupos.posibles,
    ...grupos.gfCandidates,
    ...grupos.hardening,
    ...grupos.superficie,
    ...infoFindings,
    ...grupos.baja_confianza,
    ...grupos.descartados
  ];

  const notices = [
    data.sqlmap_notice ? `[i] ${data.sqlmap_notice}` : null,
    data.ai_notice ? `[i] ${data.ai_notice}` : null
  ].filter(Boolean);

  resultados.innerHTML = `
    ${renderDashboard(data, grupos, allFindings)}
    ${renderPipelineTimeline(livePipeline.length ? livePipeline : (data.pipeline_timeline || []), data)}
    ${renderCorrelaciones(data.correlations || [])}
    ${renderListaPriorizada(allFindings)}
    ${notices.map(n => `<p class="notice">${escaparHtml(n)}</p>`).join('')}
  `;

  resultados.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.dataset.filterType === 'categoria') filtroCategoria = btn.dataset.filterValue;
      if (btn.dataset.filterType === 'severidad') filtroSeveridad = btn.dataset.filterValue;
      renderFindings(data.findings || [], data.groups || null);
    });
  });
}

btnAnalizar.addEventListener('click', async () => {
  const prompt = promptInput.value.trim();

  if (!prompt) {
    setEstado('[!] escribe una URL o dominio.', 'error');
    return;
  }

  ultimoAnalisis = null;
  filtroCategoria = 'todos';
  filtroSeveridad = 'todos';
  progressEvents = [];
  livePipeline = crearPipelineInicial();
  pasosCompletados = new Set();
  progresoActual = 0;
  btnGenerarInforme.disabled = true;
  activarProgresoIndeterminado();
  resultados.innerHTML = renderPipelineTimeline(livePipeline);
  renderProgreso({ tool: 'analisis', status: 'running', message: `Preparando analisis para ${prompt}` });

  try {
    const response = await fetch('/analizar-stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: prompt })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || 'Error desconocido');
    }

    const data = await leerAnalisisStream(response);

    ultimoAnalisis = data;
    const timelineFinal = Array.isArray(data.pipeline_timeline) ? data.pipeline_timeline : [];
    livePipeline = pipelineVisualOrder.map(tool => {
      const fromBackend = timelineFinal.find(item => normalizarToolTimeline(item.tool) === tool);
      const fromLive = livePipeline.find(item => normalizarToolTimeline(item.tool) === tool);
      const base = fromBackend || fromLive || { tool, detail: 'completado', duration_ms: null, important: false };
      return {
        ...base,
        tool,
        status: esEstadoFinal(base.status) ? base.status : 'success',
        detail: tool === IA_PHASE ? 'analisis completado' : (base.detail === 'pendiente' ? 'completado' : base.detail)
      };
    });
    pipelineOrder.forEach(completarPaso);
    completarPaso(IA_PHASE);
    renderFindings(data.findings || [], data.groups || null);
    btnGenerarInforme.disabled = false;
    setEstado(`[*] analisis finalizado\n[+] objetivo: ${data.target}`, 'success');
  } catch (error) {
    setEstado(`[!] error: ${error.message}`, 'error');
  }
});

btnGenerarInforme.addEventListener('click', async () => {
  if (!ultimoAnalisis) {
    setEstado('[!] primero ejecuta un analisis.', 'error');
    return;
  }

  btnGenerarInforme.disabled = true;
  setEstado('[*] generando informe PDF...', 'loading');

  try {
    const response = await fetch('/generar-informe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: ultimoAnalisis.target,
        findings: ultimoAnalisis.findings || [],
        gf_candidates: ultimoAnalisis.gf_candidates || {},
        tool_results: ultimoAnalisis.tool_results || {},
        tool_counters: ultimoAnalisis.tool_counters || {},
        correlations: ultimoAnalisis.correlations || [],
        pipeline_timeline: ultimoAnalisis.pipeline_timeline || [],
        risk_score: ultimoAnalisis.risk_score,
        risk_level: ultimoAnalisis.risk_level,
        risk_grade: ultimoAnalisis.risk_grade,
        sqlmap_notice: ultimoAnalisis.sqlmap_notice,
        ai_notice: ultimoAnalisis.ai_notice
      })
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'No se pudo generar el informe');
    }

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'informe-seguridad.pdf';
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);

    setEstado('[+] informe generado correctamente.', 'success');
  } catch (error) {
    setEstado(`[!] error: ${error.message}`, 'error');
  } finally {
    btnGenerarInforme.disabled = false;
  }
});

if (btnNuevoAnalisis) {
  btnNuevoAnalisis.addEventListener('click', () => {
    ultimoAnalisis = null;
    filtroCategoria = 'todos';
    filtroSeveridad = 'todos';
    progressEvents = [];
    livePipeline = [];
    pasosCompletados = new Set();
    progresoActual = 0;
    promptInput.value = '';
    btnGenerarInforme.disabled = true;
    resultados.innerHTML = '';
    actualizarProgreso(0, TOTAL_PASOS);
    setEstado('');
    promptInput.focus();
  });
}
