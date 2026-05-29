const btnAnalizar = document.getElementById('btnAnalizar');
const btnGenerarInforme = document.getElementById('btnGenerarInforme');
const btnNuevoAnalisis = document.getElementById('btnNuevoAnalisis');
const promptInput = document.getElementById('prompt');
const estado = document.getElementById('estado');
const resultados = document.getElementById('resultados');
const pipelineProgress = document.getElementById('pipelineProgress');
const pipelineProgressPercent = document.getElementById('pipelineProgressPercent');
const pipelineProgressFill = document.getElementById('pipelineProgressFill');
const pipelineProgressTrack = document.querySelector('.pipeline-progress-track');

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

const hardeningTypes = ['missing_security_header', 'insecure_cookie', 'missing_https_redirect', 'tls_certificate_issue'];
const gfTypes = ['gf-candidate'];

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

  if (pipelineProgress && (completadasSeguras > 0 || porcentaje === 100)) {
    pipelineProgress.classList.remove('is-indeterminate');
  }
  if (pipelineProgressPercent) pipelineProgressPercent.textContent = `${porcentaje}%`;
  if (pipelineProgressFill) pipelineProgressFill.style.width = `${porcentaje}%`;
  if (pipelineProgressTrack) pipelineProgressTrack.setAttribute('aria-valuenow', String(porcentaje));
}

function activarProgresoIndeterminado() {
  if (pipelineProgress) pipelineProgress.classList.add('is-indeterminate');
  if (pipelineProgressPercent) pipelineProgressPercent.textContent = '0%';
  if (pipelineProgressFill) pipelineProgressFill.style.width = '0%';
  if (pipelineProgressTrack) pipelineProgressTrack.setAttribute('aria-valuenow', '0');
}

function esEstadoFinal(status = '') {
  return ['success', 'done', 'completed', 'ok', 'ready', 'error', 'fail', 'failed', 'partial', 'timeout', 'skipped', 'skip'].includes(String(status || '').toLowerCase());
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
  const raw = String(tool || '');
  if (raw === 'score') return 'score final';
  if (raw === 'analisis') return 'subfinder';
  if (raw.startsWith('ia/')) return IA_PHASE;
  return raw;
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

function statusCorto(status = '') {
  const lower = String(status || '').toLowerCase();
  if (['success', 'done', 'completed', 'ok', 'ready'].includes(lower)) return 'OK';
  if (['error', 'fail', 'failed'].includes(lower)) return 'FAIL';
  if (['skipped', 'skip', 'partial', 'timeout', 'warning'].includes(lower)) return 'FAIL';
  if (['pending', 'wait'].includes(lower)) return '..';
  return 'RUN';
}

function normalizarGrupos(data = {}) {
  const findings = Array.isArray(data.findings) ? data.findings : [];
  const groups = findings.length ? {} : (data.groups || {});

  return {
    confirmadas: groups.confirmadas || findings.filter(f => f.isVulnerability && f.confidence === 'high' && !f.isFalsePositiveLikely && !hardeningTypes.includes(f.type) && !gfTypes.includes(f.type)),
    posibles: groups.posibles || findings.filter(f => f.isVulnerability && f.confidence === 'medium' && !f.isFalsePositiveLikely && !hardeningTypes.includes(f.type) && !gfTypes.includes(f.type)),
    hardening: groups.hardening || findings.filter(f => hardeningTypes.includes(f.type)),
    baja_confianza: groups.baja_confianza || findings.filter(f => f.isVulnerability && (f.confidence === 'low' || f.isFalsePositiveLikely || gfTypes.includes(f.type)) && !hardeningTypes.includes(f.type)),
    superficie: groups.superficie || findings.filter(f => f.type === 'surface'),
    reconocimiento: groups.reconocimiento || findings.filter(f => (!f.isVulnerability || f.type === 'reconocimiento') && f.type !== 'surface' && f.type !== 'discarded'),
    descartados: groups.descartados || findings.filter(f => f.type === 'discarded')
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
  if (tool === 'httpx') return `${counter.activos_vivos || result.parsed_count || 0} vivos`;
  if (tool === 'headers') return `${counter.cabeceras_ausentes || 0} ausentes / ${counter.banners_expuestos || 0} banners`;
  if (tool === 'cookies') return `${counter.cookies_inseguras || 0} inseguras / ${counter.cookies_sesion || 0} sesion / ${counter.cookies_analizadas || 0} total`;
  if (tool === 'httpsRedirect') return `${counter.redirecciona_https || 0} HTTPS ok / ${counter.http_sin_redirect || 0} HTTP abierto`;
  if (tool === 'tls') return `${counter.certificados_analizados || 0} certs / ${counter.expirados || 0} expirados / ${counter.proximos_expirar || 0} proximos`;
  if (tool === 'robotsSitemap') return `${counter.recursos_encontrados || 0} recursos / ${counter.rutas_sensibles || 0} sensibles`;
  if (tool === 'ports') return `${counter.puertos_abiertos || 0} abiertos / ${counter.puertos_datos || 0} datos${counter.source ? ` / ${counter.source}` : ''}`;
  if (tool === 'katana') return `${counter.endpoints_encontrados || result.parsed_count || 0} normalizados / ${counter.superficie_util || 0} superficie`;
  if (tool === 'gau') return `${counter.endpoints_encontrados || result.parsed_count || 0} historicas / ${counter.con_parametros || 0} params`;
  if (tool === 'gf') return `${counter.xss || 0} XSS / ${counter.sqli || 0} SQLi / ${counter.ssrf || 0} SSRF / ${counter.redirect || 0} Redirect`;
  if (tool === 'feroxbuster') return `${counter.rutas_descubiertas || 0} rutas / ${counter.rutas_sensibles || 0} sensibles`;
  if (tool === 'trufflehog') return `${counter.secretos_confirmados || 0} confirmados / ${counter.secretos_posibles || 0} posibles / ${counter.recursos_fallidos || 0} fallidos`;
  if (tool === 'nuclei') return `${counter.vulnerabilidades_reales || 0} vulnerabilidades`;
  if (tool === 'sqlmap') return counter.no_ejecutada ? 'no ejecutada' : `${counter.confirmadas || 0} confirmadas / ${counter.posibles || 0} posibles`;
  return `${(result.findings || []).length} hallazgos`;
}

function categoriaFinding(finding = {}) {
  if (finding.type === 'discarded' || finding.isFalsePositiveLikely) return 'DESCARTADO';
  if (gfTypes.includes(finding.type) || finding.tool === 'gf') return 'GF';
  if (hardeningTypes.includes(finding.type)) return 'HARDENING';
  if (finding.type === 'surface') return 'SUPERFICIE';
  if (!finding.isVulnerability || finding.type === 'reconocimiento') return 'INFO';
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
    DESCARTADO: 6
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
  if (categoria === 'DESCARTADO') return 8;
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
  const cats = ['todos', 'explotables', 'posibles', 'hardening', 'superficie', 'gf', 'info'];
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

  if (['critical'].includes(severity) || (finding.confidence === 'high' && categoria === 'EXPLOTABLE') || /\b(rce|sql injection|sqlmap|xss|dalfox|nuclei|secret|credential|trufflehog)\b/.test(texto)) {
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
  if (categoria === 'POSIBLE' || categoria === 'GF') return 'posibles';
  if (categoria === 'SUPERFICIE' || finding.type === 'surface') return 'superficie';
  if (categoria === 'HARDENING') return 'hardening';
  return 'info';
}

function descripcionCorta(finding = {}) {
  return fallback(finding.description || finding.impact || buildAiReason(finding), 'Sin descripcion disponible.');
}

function evidenciaFinding(finding = {}) {
  return finding.evidence || finding.raw_reference || finding.affected_url || finding.affected_asset || '';
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

function renderListaPriorizada(findings = []) {
  const filtrados = aplicarFiltros(deduplicarFindingsPriorizados(findings));
  const grupos = {
    confirmadas: [],
    posibles: [],
    superficie: [],
    hardening: [],
    info: []
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
        ${renderGrupoHallazgos('Posibles vectores', 'fa-bug', grupos.posibles, true)}
        ${renderGrupoHallazgos('Superficie expuesta', 'fa-eye', grupos.superficie)}
        ${renderGrupoHallazgos('Hardening / Configuracion', 'fa-shield-halved', grupos.hardening)}
        ${renderGrupoHallazgos('Informativo', 'fa-circle-info', grupos.info)}
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

function statusClaseTimeline(status = '') {
  if (String(status || '').toLowerCase() === 'pending') return 'timeline-pending';
  const corto = statusCorto(status).toLowerCase();
  if (corto === 'ok') return 'timeline-ok';
  if (corto === 'fail') return 'timeline-fail';
  if (corto === 'skip') return 'timeline-skip';
  if (corto === 'warn') return 'timeline-warn';
  return 'timeline-run';
}

function renderPipelineTimeline(items = []) {
  if (!items.length) return '';
  const visibles = items.filter(item => pipelineVisualOrder.includes(item.tool));
  return `
    <section class="terminal-card pipeline-card">
      <div class="group-header">
        <h2>PIPELINE DE EJECUCION</h2>
        <span>${escaparHtml(visibles.length)}</span>
      </div>
      <div class="pipeline-timeline">
        ${visibles.map(item => `
          <div id="node-${escaparHtml(slugHerramienta(item.tool))}" class="pipeline-node ${statusClaseTimeline(item.status)} ${item.important ? 'timeline-important' : ''}">
            <span class="terminal-badge ${statusClaseTimeline(item.status)}">[${escaparHtml(statusCorto(item.status))}]</span>
            <strong>${escaparHtml(item.tool)}</strong>
            <span>${escaparHtml(item.detail || '--')}</span>
            <small>${item.duration_ms ? `${escaparHtml(item.duration_ms)} ms` : '--'}</small>
          </div>
        `).join('')}
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
    ${renderScore(data)}
    ${renderPipelineTimeline(livePipeline.length ? livePipeline : (data.pipeline_timeline || []))}
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
      const fromBackend = timelineFinal.find(item => item.tool === tool);
      const fromLive = livePipeline.find(item => item.tool === tool);
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
    if (pipelineProgress) pipelineProgress.classList.remove('is-indeterminate');
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
        correlations: ultimoAnalisis.correlations || [],
        pipeline_timeline: ultimoAnalisis.pipeline_timeline || [],
        risk_score: ultimoAnalisis.risk_score,
        risk_level: ultimoAnalisis.risk_level,
        risk_grade: ultimoAnalisis.risk_grade
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
