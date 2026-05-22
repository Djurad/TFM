const btnAnalizar = document.getElementById('btnAnalizar');
const btnGenerarInforme = document.getElementById('btnGenerarInforme');
const btnNuevoAnalisis = document.getElementById('btnNuevoAnalisis');
const promptInput = document.getElementById('prompt');
const estado = document.getElementById('estado');
const resumen = document.getElementById('resumen');
const resultados = document.getElementById('resultados');
const herramientas = document.getElementById('herramientas');

let ultimoAnalisis = null;
let filtroCategoria = 'todos';
let filtroSeveridad = 'todos';
let progressEvents = [];
let livePipeline = [];

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
  'score final',
  'informe'
];

const hardeningTypes = ['missing_security_header', 'insecure_cookie', 'missing_https_redirect', 'tls_certificate_issue'];
const gfTypes = ['gf-candidate'];

const severityLabels = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO'
};

const groupLabels = {
  confirmadas: '[!] CONFIRMADAS',
  posibles: '[?] POSIBLES',
  total_vulnerabilidades: '[+] REPORTABLES',
  hardening: '[#] HARDENING',
  superficie: '[+] SUPERFICIE',
  reconocimiento: '[i] INFO',
  descartados: '[x] DESCARTADOS'
};

function setEstado(texto, tipo = '') {
  estado.textContent = texto;
  estado.className = tipo ? `status ${tipo}` : 'status';
}

function crearPipelineInicial() {
  return pipelineOrder.map(tool => ({
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
  if (raw.startsWith('ia/')) return raw.replace(/^ia\//, '');
  return raw;
}

function detalleProgreso(evento = {}) {
  if (evento.count !== undefined && evento.count !== null) return `${evento.count} resultados`;
  return evento.message || 'ejecutando';
}

function actualizarPipelineVivo(evento = {}) {
  const tool = normalizarToolTimeline(evento.tool);
  if (!livePipeline.length) livePipeline = crearPipelineInicial();

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
  if (['skipped', 'skip'].includes(lower)) return 'SKIP';
  if (['partial', 'timeout', 'warning'].includes(lower)) return 'WARN';
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

function calcularRiesgo(summary = {}) {
  const total = ['confirmadas', 'posibles', 'hardening', 'superficie', 'reconocimiento']
    .reduce((sum, key) => sum + Number(summary[key] || 0), 0);
  if (!total) return { score: null, rating: 'N/D', label: 'Sin datos suficientes' };

  const penalty = Math.min(85,
    (summary.confirmadas || 0) * 18 +
    (summary.posibles || 0) * 7 +
    (summary.hardening || 0) * 2 +
    (summary.superficie || 0)
  );
  const score = Math.max(15, 100 - penalty);
  const rating = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'E';
  const label = score >= 75 ? 'Riesgo Bajo' : score >= 60 ? 'Riesgo Medio' : score >= 40 ? 'Riesgo Alto' : 'Riesgo Critico';
  return { score, rating, label };
}

function barraRiesgo(score) {
  const bloques = 16;
  const llenos = Math.round((score / 100) * bloques);
  return `[${'█'.repeat(llenos)}${'░'.repeat(bloques - llenos)}] ${score}/100`;
}

function renderResumen(summary = {}) {
  if (!resumen) return;
  resumen.innerHTML = '';
  const keys = ['confirmadas', 'posibles', 'hardening', 'superficie', 'reconocimiento', 'descartados', 'total_vulnerabilidades'];

  keys.forEach(key => {
    const item = document.createElement('div');
    item.className = `summary-item summary-${key}`;
    item.innerHTML = `
      <strong>${escaparHtml(summary[key] || 0)}</strong>
      <span>${escaparHtml(groupLabels[key])}</span>
    `;
    resumen.appendChild(item);
  });
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

function renderHerramientas(toolResults = {}) {
  herramientas.innerHTML = '';
  const counters = ultimoAnalisis?.tool_counters || {};
  const warnings = [];

  const header = document.createElement('div');
  header.className = 'tool-row tool-header';
  header.innerHTML = '<strong>HERRAMIENTA</strong><span>RESULTADO</span><span>DETALLES</span><span>TIEMPO</span>';
  herramientas.appendChild(header);

  Object.entries(toolResults).forEach(([tool, result]) => {
    const detalle = obtenerDetalleHerramienta(tool, result, counters[tool]);
    const status = estadoHerramienta(result.status);
    const item = document.createElement('div');
    item.className = 'tool-row';
    item.innerHTML = `
      <strong>${escaparHtml(tool)}</strong>
      <span class="tool-status ${status.className}">${escaparHtml(status.label)}</span>
      <span>${escaparHtml(detalle)}</span>
      <span class="terminal-subtle">--</span>
      ${result.error ? `<small>[!] ${escaparHtml(result.error)}</small>` : ''}
      ${result.warning ? `<small>[i] ${escaparHtml(result.warning)}</small>` : ''}
    `;
    if (result.error || result.warning) warnings.push({ tool, message: result.error || result.warning });
    herramientas.appendChild(item);
  });

  if (warnings.length) {
    const log = document.createElement('div');
    log.className = 'terminal-card';
    log.style.gridColumn = '1 / -1';
    log.innerHTML = `
      <h2>LOGS / WARNINGS</h2>
      <ul class="compact-list">
        ${warnings.slice(0, 8).map(item => `<li><span>[i] ${escaparHtml(item.tool)}: ${escaparHtml(item.message)}</span><span>--</span></li>`).join('')}
      </ul>
    `;
    herramientas.appendChild(log);
  }
}

function badgeFinding(finding) {
  if (finding.type === 'surface') return { label: 'SUPERFICIE', className: 'badge-surface' };
  if (hardeningTypes.includes(finding.type)) return { label: 'HARDENING', className: 'badge-possible' };
  if (finding.type === 'discarded') return { label: 'DESCARTADO', className: 'badge-discarded' };
  if (!finding.isVulnerability || finding.type === 'reconocimiento') return { label: 'INFO', className: 'badge-info' };
  if (finding.confidence === 'high') return { label: 'CONFIRMADA', className: 'badge-confirmed' };
  return { label: 'POSIBLE', className: 'badge-possible' };
}

function crearCardFinding(finding, modo = 'vulnerability') {
  const severity = finding.severity || 'info';
  const card = document.createElement('article');
  const badge = badgeFinding(finding);
  card.className = `finding finding-${modo} severity-${severity}`;
  card.innerHTML = `
    <header>
      <div>
        <span class="badge">${escaparHtml(fallback(finding.tool, 'tool'))}</span>
        <span class="badge ${badge.className}">${escaparHtml(badge.label)}</span>
      </div>
      <span class="severity severity-${escaparHtml(severity)}">${severityLabels[severity] || escaparHtml(severity)}</span>
    </header>
    <h2>${escaparHtml(fallback(finding.title, 'Hallazgo sin titulo'))}</h2>
    <p>${escaparHtml(fallback(finding.description, 'No disponible'))}</p>
    <dl>
      <dt>Severidad</dt>
      <dd>${escaparHtml(severityLabels[severity] || severity)}</dd>
      <dt>Confianza</dt>
      <dd>${escaparHtml(fallback(finding.confidence, '-'))}</dd>
      ${finding.cwe ? `<dt>CWE</dt><dd>${escaparHtml(finding.cwe)}</dd>` : ''}
      <dt>Activo</dt>
      <dd><div class="mono-box">${escaparHtml(fallback(finding.affected_url || finding.affected_asset, '-'))}</div></dd>
      <dt>Evidencia</dt>
      <dd>${escaparHtml(fallback(finding.evidence, 'Sin evidencia detallada'))}</dd>
      <dt>Impacto</dt>
      <dd>${escaparHtml(fallback(finding.impact, 'No disponible'))}</dd>
      <dt>Recomendacion</dt>
      <dd>${escaparHtml(fallback(finding.recommendation, 'No disponible'))}</dd>
      ${finding.isFalsePositiveLikely ? `<dt>Falso positivo</dt><dd>${escaparHtml(fallback(finding.falsePositiveReason, 'Baja confianza o evidencia limitada.'))}</dd>` : ''}
    </dl>
  `;
  return card;
}

function ordenFindings(a, b) {
  const pesos = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return (pesos[a.severity] ?? 9) - (pesos[b.severity] ?? 9);
}

function listaCompacta(findings = [], limite = 8, badgeFn = null) {
  if (!findings.length) return '<p class="empty">Sin datos disponibles.</p>';
  return `
    <ul class="compact-list">
      ${findings.slice(0, limite).map(f => `
        <li>
          <span>${escaparHtml(f.title || f.affected_url || f.affected_asset || '-')}</span>
          <span class="terminal-badge ${f.severity ? `severity-${escaparHtml(f.severity)}` : ''}">${escaparHtml(badgeFn ? badgeFn(f) : (f.severity || f.tool || '--'))}</span>
        </li>
      `).join('')}
    </ul>
  `;
}

function extraerPuertos(findings = []) {
  const vistos = new Set();
  return findings
    .filter(f => f.tool === 'ports')
    .map(f => {
      const raw = f.affected_url || '';
      const match = raw.match(/:(\d+)$/);
      return {
        port: f.port || (match ? Number(match[1]) : null),
        state: 'open',
        service: f.title || f.type || '-'
      };
    })
    .filter(item => item.port)
    .filter(item => {
      const key = `${item.port}/tcp`;
      if (vistos.has(key)) return false;
      vistos.add(key);
      return true;
    });
}

function renderPuertos(puertos = []) {
  if (!puertos.length) return '<p class="empty">Sin puertos abiertos reportados.</p>';
  return `
    <div class="terminal-table-wrap">
      <table class="terminal-table">
        <thead><tr><th>PUERTO</th><th>ESTADO</th><th>SERVICIO</th></tr></thead>
        <tbody>
          ${puertos.map(p => `<tr><td>${escaparHtml(p.port)}/tcp</td><td>${escaparHtml(p.state)}</td><td>${escaparHtml(p.service)}</td></tr>`).join('')}
        </tbody>
      </table>
    </div>
  `;
}

function barraRiesgoTerminal(score) {
  if (score === null || score === undefined) return '[----------------] N/D';
  const bloques = 16;
  const llenos = Math.round((score / 100) * bloques);
  return `[${'#'.repeat(llenos)}${'-'.repeat(bloques - llenos)}] ${score}/100`;
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

function renderHallazgoPriorizado(finding = {}, index = 0) {
  const severity = String(finding.severity || 'info').toLowerCase();
  const categoria = categoriaFinding(finding);
  const activo = finding.affected_url || finding.affected_asset || ultimoAnalisis?.target || '-';
  const cwe = finding.cwe ? ` | ${finding.cwe}` : '';
  return `
    <details class="priority-row severity-${escaparHtml(severity)}" ${index === 0 ? 'open' : ''}>
      <summary>
        <span class="terminal-badge severity-${escaparHtml(severity)}">[${escaparHtml(severityLabels[severity] || severity.toUpperCase())}]</span>
        <span class="terminal-badge category-${escaparHtml(categoria.toLowerCase())}">[${escaparHtml(categoria)}]</span>
        <span class="terminal-badge">[${escaparHtml(fallback(finding.type, 'tipo'))}]</span>
        <span class="priority-title">${escaparHtml(fallback(finding.title, 'Hallazgo sin titulo'))}</span>
        <span class="priority-tool">${escaparHtml(fallback(finding.tool, 'tool'))}</span>
      </summary>
      <div class="priority-body">
        <p class="ai-reason">${escaparHtml(buildAiReason(finding))}</p>
        <div class="priority-meta">Tool: ${escaparHtml(fallback(finding.tool, '-'))} | Confianza: ${escaparHtml(fallback(finding.confidence, 'low'))}${escaparHtml(cwe)}</div>
        <div class="mono-box">Activo: ${escaparHtml(activo)}</div>
        ${Array.isArray(finding.correlation_notes) && finding.correlation_notes.length ? `
          <div>
            <div class="priority-meta">RELACIONADO CON:</div>
            <ul class="compact-list relation-list">
              ${finding.correlation_notes.map(note => `<li><span>${escaparHtml(note)}</span><span>corr</span></li>`).join('')}
            </ul>
          </div>
        ` : ''}
        <dl>
          <dt>Descripcion</dt><dd>${escaparHtml(fallback(finding.description, 'No disponible'))}</dd>
          <dt>Evidencia</dt><dd>${escaparHtml(fallback(finding.evidence, 'Sin evidencia detallada'))}</dd>
          <dt>Impacto</dt><dd>${escaparHtml(fallback(finding.impact, '-'))}</dd>
          <dt>Recomendacion</dt><dd>${escaparHtml(fallback(finding.recommendation, '-'))}</dd>
          ${finding.payload ? `<dt>Payload</dt><dd>${escaparHtml(finding.payload)}</dd>` : ''}
          ${finding.parametro || finding.parameter || finding.param ? `<dt>Parametro</dt><dd>${escaparHtml(finding.parametro || finding.parameter || finding.param)}</dd>` : ''}
          ${finding.raw_reference ? `<dt>Raw</dt><dd>${escaparHtml(finding.raw_reference)}</dd>` : ''}
        </dl>
      </div>
    </details>
  `;
}

function renderListaPriorizada(findings = []) {
  const filtrados = aplicarFiltros(deduplicarFindingsPriorizados(findings));
  return `
    <section class="terminal-card prioritized-section">
      <div class="group-header">
        <h2>HALLAZGOS OBTENIDOS</h2>
        <span>${escaparHtml(filtrados.length)}</span>
      </div>
      ${renderFiltros()}
      <div class="priority-list">
        ${filtrados.length ? filtrados.map(renderHallazgoPriorizado).join('') : '<p class="empty">Sin hallazgos para los filtros seleccionados.</p>'}
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
  return `
    <section class="terminal-card pipeline-card">
      <div class="group-header">
        <h2>PIPELINE DE EJECUCION</h2>
        <span>${escaparHtml(items.length)}</span>
      </div>
      <div class="pipeline-timeline">
        ${items.map(item => `
          <div class="pipeline-node ${statusClaseTimeline(item.status)} ${item.important ? 'timeline-important' : ''}">
            <span class="terminal-badge">[${escaparHtml(statusCorto(item.status))}]</span>
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

function renderDashboardTop(data, grupos, summary) {
  const risk = calcularRiesgo(summary);
  const riskSeverity = risk.score === null ? 'info' : risk.score < 40 ? 'critical' : risk.score < 60 ? 'high' : risk.score < 75 ? 'medium' : 'low';
  const now = new Date().toLocaleString();
  const totalFindings = (data.findings || []).length;
  return `
    <section class="dashboard-top">
      <article class="terminal-card">
        <h2>OBJETIVO</h2>
        <div class="target-value">${escaparHtml(fallback(data.target, 'sin objetivo'))}</div>
        <p class="terminal-subtle">Analisis completado</p>
        <p class="terminal-subtle">Fecha: ${escaparHtml(now)}</p>
        <p class="terminal-subtle">Duracion: --</p>
      </article>
      <article class="terminal-card">
        <h2>RATING</h2>
        <div class="rating-letter">${escaparHtml(risk.rating)}</div>
        <div>${escaparHtml(risk.score === null ? 'N/D' : risk.score)} / 100 puntos</div>
        <div class="terminal-badge severity-${riskSeverity}">${escaparHtml(risk.label)}</div>
      </article>
      <article class="terminal-card">
        <h2>RESUMEN</h2>
        <p class="terminal-subtle">
          ${escaparHtml(totalFindings)} hallazgos correlacionados:
          ${escaparHtml(grupos.confirmadas.length)} confirmadas,
          ${escaparHtml(grupos.posibles.length)} posibles,
          ${escaparHtml(grupos.hardening.length)} de hardening y
          ${escaparHtml(grupos.superficie.length)} de superficie.
        </p>
        <div class="risk-bar">${escaparHtml(barraRiesgoTerminal(risk.score))}</div>
      </article>
    </section>
  `;
}

function renderFindings(findings = [], groups = null) {
  resultados.innerHTML = '';
  const data = ultimoAnalisis || { findings, groups };
  const grupos = normalizarGrupos(data);
  const summary = data.summary_ui || {
    confirmadas: grupos.confirmadas.length,
    posibles: grupos.posibles.length,
    hardening: grupos.hardening.length,
    superficie: grupos.superficie.length,
    reconocimiento: grupos.reconocimiento.length,
    descartados: grupos.descartados.length,
    total_vulnerabilidades: grupos.confirmadas.length + grupos.posibles.length
  };
  const displaySummary = {
    ...summary,
    confirmadas: grupos.confirmadas.length,
    posibles: grupos.posibles.length,
    hardening: grupos.hardening.length,
    superficie: grupos.superficie.length,
    reconocimiento: grupos.reconocimiento.length,
    descartados: grupos.descartados.length,
    total_vulnerabilidades: grupos.confirmadas.length + grupos.posibles.length
  };
  const infoFindings = grupos.reconocimiento || [];
  const puertos = extraerPuertos([...(data.findings || []), ...grupos.superficie, ...infoFindings]);
  const risk = calcularRiesgo(displaySummary);
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
    ${renderPipelineTimeline(data.pipeline_timeline || [])}
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
  btnGenerarInforme.disabled = true;
  renderResumen();
  herramientas.innerHTML = '';
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
    const grupos = normalizarGrupos(data);
    renderFindings(data.findings || [], data.groups || null);
    renderHerramientas(data.tool_results || {});
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
    promptInput.value = '';
    btnGenerarInforme.disabled = true;
    renderResumen();
    herramientas.innerHTML = '';
    resultados.innerHTML = '';
    setEstado('');
    promptInput.focus();
  });
}
