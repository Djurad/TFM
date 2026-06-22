const btnAnalizar = document.getElementById('btnAnalizar');
const btnGenerarInforme = document.getElementById('btnGenerarInforme');
const btnNuevoAnalisis = document.getElementById('btnNuevoAnalisis');
const promptInput = document.getElementById('prompt');
const estado = document.getElementById('estado');
const resultados = document.getElementById('resultados');

let ultimoAnalisis = null;
let filtroCategoria = 'todos';
let filtroSeveridad = 'todos';
let filtroBusqueda = '';
let vistaCompacta = false;
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

function normalizeKey(value = '') {
  return String(value || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[-\s]+/g, '_')
    .trim();
}

function normalizeSeverity(value, fallback = 'info') {
  if ((value === null || value === undefined || value === '') && fallback === '') return '';
  const key = normalizeKey(value || fallback);
  const map = {
    critical: 'critical',
    critica: 'critical',
    critico: 'critical',
    high: 'high',
    alta: 'high',
    alto: 'high',
    medium: 'medium',
    media: 'medium',
    medio: 'medium',
    low: 'low',
    baja: 'low',
    bajo: 'low',
    info: 'info',
    informational: 'info',
    informativo: 'info',
    informativa: 'info'
  };
  return map[key] || (['critical', 'high', 'medium', 'low', 'info'].includes(key) ? key : normalizeSeverity(fallback, 'info'));
}

function normalizeStatus(value, fallback = '') {
  const key = normalizeKey(value || fallback);
  const map = {
    confirmed: 'confirmed',
    confirmada: 'confirmed',
    confirmado: 'confirmed',
    verified: 'confirmed',
    vulnerable: 'confirmed',
    exploitable: 'confirmed',
    confirmed_vulnerability: 'confirmed',
    confirmed_sqli: 'confirmed',
    possible: 'possible',
    posible: 'possible',
    suspicious: 'possible',
    possible_sqli: 'possible',
    possible_vulnerability: 'possible',
    requires_manual_validation: 'possible',
    candidate: 'candidate',
    candidato: 'candidate',
    gf: 'candidate',
    gf_candidate: 'candidate',
    hardening: 'hardening',
    defensive_configuration: 'hardening',
    configuracion: 'hardening',
    surface: 'surface',
    superficie: 'surface',
    attack_surface: 'surface',
    exposed_port: 'surface',
    info: 'informational',
    informational: 'informational',
    informativo: 'informational',
    reconocimiento: 'informational',
    discarded: 'discarded',
    descartado: 'discarded',
    false_positive: 'discarded'
  };
  const normalized = map[key] || key;
  return ['confirmed', 'possible', 'candidate', 'hardening', 'surface', 'informational', 'discarded'].includes(normalized)
    ? normalized
    : '';
}

function inferStatusFromFinding(finding = {}) {
  const type = normalizeKey(finding.type);
  const category = normalizeKey(finding.category);
  const tool = normalizeKey(finding.tool);
  if (type === 'confirmed_vulnerability') return 'confirmed';
  if (type === 'possible_vulnerability') return 'possible';
  if (type === 'gf_candidate' || category === 'candidate' || tool === 'gf') return 'candidate';
  if (type === 'hardening' || category === 'hardening' || hardeningTypes.includes(finding.type)) return 'hardening';
  if (type === 'attack_surface' || type === 'surface' || category === 'attack_surface') return 'surface';
  if (type === 'discarded' || type === 'false_positive' || finding.isFalsePositiveLikely) return 'discarded';
  if (type === 'informational' || type === 'reconocimiento' || !finding.isVulnerability) return 'informational';
  if (finding.confidence === 'high') return 'confirmed';
  if (finding.isVulnerability) return 'possible';
  return 'informational';
}

function getFinalStatus(finding = {}) {
  return normalizeStatus(
    finding.finalStatus ||
    finding.final_status ||
    finding.technicalStatus ||
    finding.technical_status ||
    finding.status ||
    '',
    ''
  ) || inferStatusFromFinding(finding);
}

function getFinalSeverity(finding = {}) {
  return normalizeSeverity(
    finding.finalSeverity ||
    finding.final_severity ||
    finding.potentialSeverity ||
    finding.potential_severity ||
    finding.aiSuggestedSeverity ||
    finding.ai_suggested_severity ||
    finding.baseSeverity ||
    finding.base_severity ||
    finding.severity ||
    finding.severidad ||
    finding.criticidad ||
    'info'
  );
}

function activarInteraccionVisual(scope = document) {
  const selector = '.panel, .terminal-card, .finding-card, .correlation-row';
  scope.querySelectorAll(selector).forEach(card => {
    if (card.dataset.visualBound === 'true') return;
    card.dataset.visualBound = 'true';

    const maxTilt = 1.6;

    card.addEventListener('mousemove', event => {
      const rect = card.getBoundingClientRect();
      const x = event.clientX - rect.left;
      const y = event.clientY - rect.top;
      const percentX = rect.width ? (x / rect.width) * 100 : 50;
      const percentY = rect.height ? (y / rect.height) * 100 : 50;
      const rotateY = ((x / Math.max(rect.width, 1)) - 0.5) * maxTilt;
      const rotateX = -(((y / Math.max(rect.height, 1)) - 0.5) * maxTilt);

      card.style.setProperty('--mouse-x', `${percentX.toFixed(2)}%`);
      card.style.setProperty('--mouse-y', `${percentY.toFixed(2)}%`);
      card.style.setProperty('--tilt-x', `${rotateX.toFixed(2)}deg`);
      card.style.setProperty('--tilt-y', `${rotateY.toFixed(2)}deg`);
    });

    card.addEventListener('mouseleave', () => {
      card.style.setProperty('--mouse-x', '50%');
      card.style.setProperty('--mouse-y', '50%');
      card.style.setProperty('--tilt-x', '0deg');
      card.style.setProperty('--tilt-y', '0deg');
    });
  });
}

function activarHaloCursor() {
  if (document.documentElement.dataset.cursorGlowBound === 'true') return;
  document.documentElement.dataset.cursorGlowBound = 'true';

  const moverHalo = event => {
    document.documentElement.style.setProperty('--cursor-x', `${event.clientX}px`);
    document.documentElement.style.setProperty('--cursor-y', `${event.clientY}px`);
  };

  window.addEventListener('pointermove', moverHalo, { passive: true });
}

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
    activarInteraccionVisual(resultados);
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
  activarInteraccionVisual(resultados);
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

function normalizeSentence(value = '') {
  return normalizeKey(value)
    .replace(/[^a-z0-9]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function lowerFirst(value = '') {
  const clean = String(value || '').trim();
  return clean ? clean.charAt(0).toLowerCase() + clean.slice(1) : clean;
}

function impactSearchText(finding = {}) {
  return [
    finding.title,
    finding.tool,
    finding.type,
    finding.category,
    finding.vulnerability_type,
    finding.evidence,
    finding.impact,
    finding.severityReason,
    finding.aiReasoningSummary,
    finding.affected_url,
    finding.affected_asset
  ].filter(Boolean).join(' ').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

function hasDemonstratedCriticalImpact(finding = {}) {
  const text = impactSearchText(finding);
  return getFinalSeverity(finding) === 'critical' ||
    finding.sessionCompromise === true ||
    finding.session_compromise === true ||
    finding.sensitiveDataAccess === true ||
    finding.sensitive_data_access === true ||
    finding.dataExtraction === true ||
    finding.data_extraction === true ||
    /robo de sesion demostrado|extraccion.*confirmad|datos sensibles.*confirmad|acceso no autorizado demostrado/.test(text);
}

function impactTemplateForFinding(finding = {}) {
  const text = impactSearchText(finding);
  const status = getFinalStatus(finding);
  const severity = getFinalSeverity(finding);
  const tool = String(finding.tool || '').toLowerCase();

  if (status === 'confirmed' && /\bxss\b|dalfox/.test(text) && severity !== 'critical') {
    return 'La vulnerabilidad permite inyectar JavaScript en el parametro afectado. El riesgo es alto porque existe un payload reproducible confirmado por la herramienta y la ausencia de CSP puede aumentar el impacto potencial en usuarios. No se eleva a critica al no existir evidencia de robo de sesion, ejecucion privilegiada o acceso a datos sensibles.';
  }

  if (status === 'possible' && (tool === 'sqlmap' || /possible_sqli|sql injection|sqli/.test(text))) {
    return 'SQLMap identifico indicios compatibles con SQL Injection, pero no confirmo parametro vulnerable, payload, DBMS ni extraccion de datos. Debe tratarse como posible vulnerabilidad de prioridad media y validarse manualmente.';
  }

  if (/content-security-policy|csp/.test(text)) {
    return 'La ausencia de CSP reduce la capacidad del navegador para limitar la ejecucion de scripts no autorizados. Por si sola es un hallazgo de hardening, pero aumenta la prioridad cuando existe un XSS confirmado.';
  }

  if (/cookie/.test(text) && /samesite/.test(text)) {
    return 'La cookie de sesion no define SameSite, lo que puede aumentar la exposicion en ciertos flujos cross-site. No implica compromiso directo por si sola, pero conviene reforzar la configuracion.';
  }

  if (/httpsredirect|http sin redirect|http accesible sin redireccion|redireccion.*https/.test(text)) {
    return 'El sitio responde por HTTP sin redirigir automaticamente a HTTPS. Esto puede exponer a usuarios a trafico no cifrado o ataques de degradacion si acceden por el canal inseguro.';
  }

  if (/tls|certificado/.test(text) && /expirar|caduca|expiry|near/.test(text)) {
    return 'El certificado TLS caduca proximamente, lo que puede provocar errores de confianza o interrupciones si no se renueva a tiempo.';
  }

  if (status === 'candidate' || tool === 'gf') {
    return 'GF ha identificado un patron asociado a este vector, pero no confirma explotacion. Debe utilizarse como priorizacion para validacion manual, no como vulnerabilidad confirmada.';
  }

  if (status === 'surface') {
    return 'Este elemento amplia la superficie de ataque y debe revisarse para confirmar si requiere exposicion publica, autenticacion o restricciones adicionales.';
  }

  return '';
}

function cleanImpactLanguage(value = '', finding = {}) {
  let clean = String(value || '').replace(/\s+/g, ' ').trim();
  if (!clean) return '';

  clean = clean
    .replace(/se\s+clasifica\s+con\s+esta\s+severidad\s+porque\s+la\s+(?:gravedad|criticidad|severidad)[^.,;]*?\s+se\s+debe\s+a\s+que\s+/gi, '')
    .replace(/se\s+clasifica\s+con\s+esta\s+severidad\s+porque\s+/gi, '')
    .replace(/se\s+clasifica\s+como\s+(?:critica|crítica|alta|media|baja|informativa|critical|high|medium|low|info)\s+porque\s+/gi, 'La prioridad se justifica porque ')
    .replace(/la\s+(?:criticidad|gravedad|severidad)\s+(?:critica|crítica|alta|media|baja|informativa|critical|high|medium|low|info)\s+se\s+debe\s+a\s+que\s+/gi, 'La prioridad se justifica porque ')
    .replace(/la\s+(?:criticidad|gravedad|severidad)\s+se\s+establece\s+en\s+[^.,;]*?\s+porque\s+/gi, 'La prioridad se justifica porque ')
    .replace(/\b(?:criticidad|gravedad|severidad)\s+(?:critica|crítica|alta|media|baja)\s+debido\s+a\s+que\s+/gi, 'La prioridad se justifica porque ')
    .replace(/\bdebido\s+a\s+que\s+debido\s+a\s+que\b/gi, 'debido a que')
    .replace(/\bLa prioridad se justifica porque la prioridad se justifica porque\b/gi, 'La prioridad se justifica porque')
    .replace(/\bla evidencia disponible indica que\b/gi, '')
    .replace(/\s+/g, ' ')
    .trim();

  clean = clean
    .replace(/cambio\s+de\s+(?:criticidad|severidad)\s+descartado[^.]*\.?/gi, '')
    .replace(/la\s+evidencia\s+disponible\s+indica\s+que\s+/gi, '')
    .replace(/la\s+prioridad\s+se\s+justifica\s+porque\s+/gi, '')
    .replace(/exploataci[oó]n/gi, 'explotacion')
    .replace(/\s+/g, ' ')
    .trim();

  if (!hasDemonstratedCriticalImpact(finding)) {
    clean = clean
      .replace(/\b(?:la\s+)?toma de control del sistema\b/gi, 'un impacto mayor no demostrado')
      .replace(/\bextracci[oó]n de datos sensibles\b/gi, 'exposicion potencial no demostrada')
      .replace(/\bcompromiso critico\b/gi, 'impacto elevado')
      .replace(/\bcr[ií]tico\b/gi, getFinalSeverity(finding) === 'critical' ? 'critico' : 'alto')
      .replace(/\s+/g, ' ')
      .trim();
  }

  return clean;
}

function mergeWithoutDuplication(base = '', extra = '') {
  const baseText = cleanImpactLanguage(base);
  const extraText = cleanImpactLanguage(extra);
  if (!baseText) return extraText;
  if (!extraText) return baseText;

  const baseNormalized = normalizeSentence(baseText);
  const extraNormalized = normalizeSentence(extraText);
  if (!extraNormalized || baseNormalized.includes(extraNormalized)) return baseText;
  if (!baseNormalized || extraNormalized.includes(baseNormalized)) return extraText;

  const formattedExtra = /^(el\s+riesgo|la\s+prioridad|la\s+evidencia|en\s+este\s+caso|no\s+se\s+eleva|se\s+mantiene|debe\s+tratarse|debe\s+validarse)/i.test(extraText)
    ? extraText
    : `El riesgo es relevante porque ${lowerFirst(extraText)}`;

  return cleanImpactLanguage(`${baseText.replace(/[.。]\s*$/, '')}. ${formattedExtra}`);
}

function requiresAIEnrichment(finding = {}) {
  return ['confirmed', 'possible', 'candidate', 'hardening', 'surface', 'informational'].includes(getFinalStatus(finding)) && (
    finding.aiProcessed !== true ||
    finding.impactSource !== 'ai' ||
    finding.recommendationSource !== 'ai'
  );
}

function buildImpactText(finding = {}) {
  if (requiresAIEnrichment(finding) || finding.aiEnrichmentPending === true || finding.aiStatus === 'failed') {
    return 'Pendiente de enriquecimiento IA. No existe un impacto final validado por IA para este hallazgo.';
  }
  if (finding.impact && finding.impactSource) {
    return cleanImpactLanguage(finding.impact, finding);
  }
  const template = impactTemplateForFinding(finding);
  if (template) return cleanImpactLanguage(template, finding);

  const impactBase = finding.impact ||
    finding.technicalImpact ||
    finding.technical_impact ||
    finding.businessImpact ||
    finding.business_impact ||
    '';
  const severityExplanation = finding.severityReason ||
    finding.severity_reason ||
    finding.classificationReason ||
    finding.classification_reason ||
    finding.severityChangeReason ||
    finding.severity_change_reason ||
    finding.aiReasoningSummary ||
    finding.ai_reasoning_summary ||
    '';

  return cleanImpactLanguage(mergeWithoutDuplication(impactBase, severityExplanation), finding) ||
    'No disponible. Requiere revision tecnica segun el contexto del activo.';
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
  const usarFindings = findings.length > 0;
  const pick = (...keys) => {
    for (const key of keys) {
      if (Array.isArray(groups[key])) return groups[key];
    }
    return null;
  };

  const confirmed = usarFindings ? findings.filter(f => getFinalStatus(f) === 'confirmed') : pick('confirmed', 'confirmadas') || [];
  const possible = usarFindings ? findings.filter(f => getFinalStatus(f) === 'possible') : pick('possible', 'posibles') || [];
  const gfCandidates = usarFindings ? findings.filter(f => getFinalStatus(f) === 'candidate') : pick('gfCandidates', 'gf_candidates') || [];
  const hardening = usarFindings ? findings.filter(f => getFinalStatus(f) === 'hardening') : pick('hardening') || [];
  const attackSurface = usarFindings ? findings.filter(f => getFinalStatus(f) === 'surface') : pick('attackSurface', 'superficie', 'surface') || [];
  const informational = usarFindings ? findings.filter(f => getFinalStatus(f) === 'informational') : pick('informational', 'reconocimiento', 'recon') || [];
  const discarded = usarFindings ? findings.filter(f => getFinalStatus(f) === 'discarded') : pick('discarded', 'descartados') || [];
  const falsePositives = usarFindings ? findings.filter(f => f.type === 'false_positive' || f.isFalsePositiveLikely) : pick('falsePositives', 'baja_confianza') || [];

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
  const status = getFinalStatus(finding);
  if (status === 'confirmed') return 'EXPLOTABLE';
  if (status === 'possible') return 'POSIBLE';
  if (status === 'candidate') return 'GF';
  if (status === 'hardening') return 'HARDENING';
  if (status === 'surface') return 'SUPERFICIE';
  if (status === 'discarded') return normalizeKey(finding.type) === 'false_positive' ? 'FALSO_POSITIVO' : 'DESCARTADO';
  return 'INFO';
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
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[normalizeSeverity(severity)] ?? 5;
}

function prioridadHallazgo(finding = {}) {
  const categoria = categoriaFinding(finding);
  const severity = getFinalSeverity(finding);
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
      prioridadSeveridad(getFinalSeverity(a)) - prioridadSeveridad(getFinalSeverity(b)) ||
      Number(b.practicalRiskScore || 0) - Number(a.practicalRiskScore || 0) ||
      Number(b.realVulnerabilityProbabilityPercent || 0) - Number(a.realVulnerabilityProbabilityPercent || 0) ||
      prioridadCategoria(catA) - prioridadCategoria(catB) ||
      String(a.tool || '').localeCompare(String(b.tool || ''));
  });
}

function aplicarFiltros(findings = []) {
  return findings.filter(finding => {
    const categoria = categoriaFinding(finding).toLowerCase();
    const severity = getFinalSeverity(finding);
    const catOk = filtroCategoria === 'todos' ||
      (filtroCategoria === 'explotables' && categoria === 'explotable') ||
      (filtroCategoria === 'posibles' && categoria === 'posible') ||
      filtroCategoria === categoria;
    const sevOk = filtroSeveridad === 'todos' || filtroSeveridad === severity;
    const texto = textoFinding(finding);
    const searchOk = !filtroBusqueda ||
      texto.includes(filtroBusqueda) ||
      String(finding.affected_url || finding.affected_asset || '').toLowerCase().includes(filtroBusqueda);

    return catOk && sevOk && searchOk;
  });
}

function contarSeveridades(findings = []) {
  return findings.reduce((acc, finding) => {
    const key = getFinalSeverity(finding);
    acc[key] = (acc[key] || 0) + 1;
    acc.total += 1;
    return acc;
  }, { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 });
}

function renderFiltros(findings = [], filtrados = []) {
  const filtrosSeveridad = [
    ['todos', 'Todas'],
    ['critical', 'Criticas'],
    ['high', 'Altas'],
    ['medium', 'Medias'],
    ['low', 'Bajas'],
    ['info', 'Info']
  ];
  const counts = contarSeveridades(filtrados);

  return `
    <div class="findings-toolbar">
      <div class="filter-row severity-filter" data-filter-group="severidad">
        ${filtrosSeveridad.map(([value, label]) => `<button type="button" class="filter-btn ${filtroSeveridad === value ? 'active' : ''}" data-filter-type="severidad" data-filter-value="${value}">${label}</button>`).join('')}
      </div>

      <div class="finding-toolbar-controls">
        <label class="finding-search">
          <i class="fas fa-magnifying-glass"></i>
          <input id="findingSearch" type="search" value="${escaparHtml(filtroBusqueda)}" placeholder="Buscar por titulo, impacto o URL..." autocomplete="off">
        </label>
        <div class="view-toggle" role="group" aria-label="Modo de vista">
          <button type="button" class="view-btn ${!vistaCompacta ? 'active' : ''}" data-view-mode="detailed">Detallada</button>
          <button type="button" class="view-btn ${vistaCompacta ? 'active' : ''}" data-view-mode="compact">Compacta</button>
        </div>
        <button type="button" class="export-visible-csv"><i class="fas fa-file-csv"></i> Exportar CSV</button>
      </div>

      <div class="finding-stats-line">
        <strong>${escaparHtml(filtrados.length)}</strong> de ${escaparHtml(findings.length)} hallazgos visibles
        <span class="stat-critical">Critica: ${escaparHtml(counts.critical)}</span>
        <span class="stat-high">Alta: ${escaparHtml(counts.high)}</span>
        <span class="stat-medium">Media: ${escaparHtml(counts.medium)}</span>
        <span class="stat-low">Baja: ${escaparHtml(counts.low)}</span>
        <span class="stat-info">Info: ${escaparHtml(counts.info)}</span>
      </div>
    </div>
  `;
}

function textoFinding(finding = {}) {
  return [
    finding.title,
    finding.description,
    finding.evidence,
    finding.type,
    finding.displayTool || finding.sourceTool || finding.tool || finding.source,
    buildImpactText(finding)
  ].filter(Boolean).join(' ').toLowerCase();
}

function displayToolFinding(finding = {}) {
  if (finding.displayTool) return finding.displayTool;
  if (Array.isArray(finding.sourceTools) && finding.sourceTools.length > 1) {
    return finding.sourceTools.map(tool => String(tool || '').replace(/^./, char => char.toUpperCase())).join('/');
  }
  const raw = finding.sourceTool || finding.tool || finding.source || 'tool';
  const key = String(raw).split(':')[0].toLowerCase();
  return { gf: 'GF', gau: 'Gau', katana: 'Katana', feroxbuster: 'Feroxbuster', dalfox: 'Dalfox', sqlmap: 'SQLMap', tls: 'TLS' }[key] || raw;
}

function probabilityPercentValue(finding = {}) {
  const values = [
    finding.realVulnerabilityProbabilityPercent,
    finding.probabilityFinal,
    finding.finalProbability,
    finding.probabilityAISuggested
  ];
  for (const value of values) {
    if (value === null || value === undefined || value === '') continue;
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) continue;
    return Math.round(Math.max(0, Math.min(100, parsed <= 1 ? parsed * 100 : parsed)));
  }
  return null;
}

function nivelVisualFinding(finding = {}) {
  const severity = getFinalSeverity(finding);
  const icons = {
    critical: 'fa-triangle-exclamation',
    high: 'fa-bug',
    medium: 'fa-eye',
    low: 'fa-shield-halved',
    info: 'fa-circle-info'
  };
  const labels = {
    critical: 'CRITICA',
    high: 'ALTA',
    medium: 'MEDIA',
    low: 'BAJA',
    info: 'INFO'
  };
  return { key: severity, label: labels[severity] || 'INFO', icon: icons[severity] || 'fa-circle-info' };
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
  return fallback(buildImpactText(finding) || finding.description || buildAiReason(finding), 'Sin impacto disponible.');
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

function probabilityText(finding = {}) {
  const status = getFinalStatus(finding);
  if (['hardening', 'surface', 'informational'].includes(status) || finding.probabilityLabel === 'no_aplica') {
    return 'N/A';
  }
  const percent = probabilityPercentValue(finding);
  if (percent === null) return 'No disponible';
  return `${percent}%`;
}

function probabilityApplicable(finding = {}) {
  return ['confirmed', 'possible', 'candidate'].includes(getFinalStatus(finding)) &&
    probabilityPercentValue(finding) !== null;
}

function renderProbabilityBadge(finding = {}) {
  if (!probabilityApplicable(finding)) return '';
  const percent = probabilityPercentValue(finding);
  return `
    <div class="probability-highlight" aria-label="Probabilidad real ${escaparHtml(percent)} por ciento">
      <div><strong>${escaparHtml(percent)}%</strong><span>PROB. REAL</span></div>
      <i><b style="width:${escaparHtml(percent)}%"></b></i>
    </div>
  `;
}

function renderFindingCard(finding = {}) {
  const nivel = nivelVisualFinding(finding);
  const categoria = categoriaFinding(finding);
  const status = getFinalStatus(finding);
  const verificationText = finding.aiEnrichmentPending === true || finding.aiStatus === 'failed' ? 'Pendiente IA' : 'Observado';
  const recommendationText = requiresAIEnrichment(finding) || finding.aiEnrichmentPending === true || finding.aiStatus === 'failed'
    ? 'Pendiente de enriquecimiento IA. No existe una recomendacion final validada por IA para este hallazgo.'
    : finding.recommendation;
  return `
    <article class="finding-card finding-${escaparHtml(nivel.key)} ${vistaCompacta ? 'compact' : ''}">
      <header>
        <span class="finding-severity" title="Criticidad potencial si el hallazgo se confirma"><i class="fas ${escaparHtml(nivel.icon)}"></i> ${escaparHtml(nivel.label)}</span>
        <span class="terminal-badge finding-status">[${escaparHtml(categoria)}]</span>
        <span class="terminal-badge">[${escaparHtml(displayToolFinding(finding))}]</span>
        ${renderProbabilityBadge(finding)}
      </header>
      <h3>${escaparHtml(fallback(finding.title, 'Hallazgo sin titulo'))}</h3>
      ${vistaCompacta ? '' : `<p>${escaparHtml(descripcionCorta(finding))}</p>`}
      <div class="finding-meta">
        ${probabilityApplicable(finding) ? '' : `<span><i class="fas fa-check-circle"></i> Verificacion: ${escaparHtml(verificationText)}</span>`}
        <span><i class="fas fa-crosshairs"></i> ${escaparHtml(fallback(finding.affected_url || finding.affected_asset || ultimoAnalisis?.target, '-'))}</span>
        ${finding.cvssLikeScore !== null && finding.cvssLikeScore !== undefined ? `<span><i class="fas fa-gauge-high"></i> CVSS-like: ${escaparHtml(Number(finding.cvssLikeScore).toFixed(1))}</span>` : ''}
        ${finding.severityChangedByAI
          ? `<span><i class="fas fa-wand-magic-sparkles"></i> IA: ${escaparHtml(finding.baseSeverity || 'base')} -> ${escaparHtml(getFinalSeverity(finding))}</span>`
          : ''}
      </div>
      ${vistaCompacta ? '' : `
        ${status === 'candidate' ? `
          <div class="finding-note candidate-note">
            Criticidad potencial si se confirma. Este hallazgo es un candidato priorizado por GF, no una vulnerabilidad confirmada, y requiere validacion manual.
          </div>
        ` : ''}
        <div class="finding-analysis">
          ${renderFindingDetail('Impacto', 'fa-bolt', buildImpactText(finding), 'No disponible. Requiere revision tecnica segun el contexto del activo.')}
          ${renderFindingDetail('Solucion recomendada', 'fa-screwdriver-wrench', recommendationText, 'Pendiente de enriquecimiento IA.')}
        </div>
        ${evidenciaFinding(finding) ? `<pre class="finding-evidence">${escaparHtml(evidenciaFinding(finding))}</pre>` : ''}
      `}
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
  const deduplicados = deduplicarFindingsPriorizados(findings);
  const filtrados = aplicarFiltros(deduplicados);
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
      ${renderFiltros(deduplicados, filtrados)}
      <div class="finding-groups">
        ${renderGrupoHallazgos('Vulnerabilidades confirmadas', 'fa-triangle-exclamation', grupos.confirmadas, true)}
        ${renderGrupoHallazgos('Posibles vulnerabilidades', 'fa-bug', grupos.posibles, true)}
        ${grupos.gfCandidates.length ? renderNotaGf() : ''}
        ${renderGrupoHallazgos('Candidatos priorizados por GF', 'fa-crosshairs', grupos.gfCandidates, true)}
        ${renderGrupoHallazgos('Superficie expuesta', 'fa-eye', grupos.superficie)}
        ${renderGrupoHallazgos('Hardening / Configuracion', 'fa-shield-halved', grupos.hardening)}
        ${renderGrupoHallazgos('Informativo', 'fa-circle-info', grupos.info)}
        ${renderGrupoHallazgos('Descartados / no concluyentes', 'fa-ban', grupos.descartados)}
      </div>
    </section>
  `;
}

function csvEscape(value) {
  return `"${String(value ?? '').replace(/"/g, '""')}"`;
}

function exportarFindingsVisiblesCSV() {
  if (!ultimoAnalisis) return;

  const grupos = normalizarGrupos(ultimoAnalisis);
  const allFindings = [
    ...grupos.confirmadas,
    ...grupos.posibles,
    ...grupos.gfCandidates,
    ...grupos.hardening,
    ...grupos.superficie,
    ...(grupos.reconocimiento || []),
    ...grupos.baja_confianza,
    ...grupos.descartados
  ];
  const visibles = aplicarFiltros(deduplicarFindingsPriorizados(allFindings));
  const rows = [
    ['Severidad', 'Probabilidad real', 'Titulo', 'URL', 'Impacto', 'Solucion'],
    ...visibles.map(finding => [
      getFinalSeverity(finding),
      probabilityText(finding),
      finding.title || '',
      finding.affected_url || finding.affected_asset || '',
      buildImpactText(finding) || finding.description || '',
      finding.recommendation || ''
    ])
  ];
  const csv = rows.map(row => row.map(csvEscape).join(',')).join('\r\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'hallazgos-visibles.csv';
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
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

function buildSeverityCountsFromFindings(findings = []) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(finding => {
    const severity = getFinalSeverity(finding);
    if (counts[severity] !== undefined) counts[severity] += 1;
  });
  return counts;
}

function getReportableSeverityCounts(findings = []) {
  return buildSeverityCountsFromFindings(
    findings.filter(finding => ['confirmed', 'possible'].includes(getFinalStatus(finding)))
  );
}

function getTechnicalSeverityCounts(findings = []) {
  return buildSeverityCountsFromFindings(
    findings.filter(finding => getFinalStatus(finding) !== 'discarded')
  );
}

function getStatusCounts(findings = []) {
  return findings.reduce((acc, finding) => {
    const status = getFinalStatus(finding);
    acc[status] = (acc[status] || 0) + 1;
    return acc;
  }, { confirmed: 0, possible: 0, candidate: 0, hardening: 0, surface: 0, informational: 0, discarded: 0 });
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
  const topItems = items.slice(0, 6);
  const rest = items.slice(6).reduce((sum, item) => sum + Number(item.value || 0), 0);
  const donutItems = rest > 0 ? [...topItems, { label: 'otros', value: rest }] : topItems;
  const total = donutItems.reduce((sum, item) => sum + Number(item.value || 0), 0);
  const colors = ['#00FFD1', '#FF6B00', '#FFC247', '#AEB8CB', '#FF0055', '#7DD3FC', '#5F6C84'];
  let offset = 0;
  const segments = donutItems
    .filter(item => Number(item.value || 0) > 0)
    .map((item, index) => {
      const value = Number(item.value || 0);
      const start = offset;
      const end = offset + (value / Math.max(1, total)) * 100;
      offset = end;
      return `${colors[index % colors.length]} ${start.toFixed(2)}% ${end.toFixed(2)}%`;
    });
  const donutBg = total > 0
    ? `conic-gradient(${segments.join(', ')})`
    : 'conic-gradient(rgba(174, 184, 203, 0.24) 0% 100%)';

  return `
    <div class="tool-distribution">
      <div class="tool-donut" style="background:${escaparHtml(donutBg)}" aria-label="Distribucion de hallazgos por herramienta">
        <div class="tool-donut-center">
          <strong>${escaparHtml(total)}</strong>
          <span>total</span>
        </div>
      </div>
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
    </div>
  `;
}

function renderDashboard(data = {}, grupos = {}, findings = []) {
  const score = data.risk_score;
  const level = data.risk_level || 'N/D';
  const grade = data.risk_grade || 'N/D';
  const scoreText = score === null || score === undefined ? 'N/D' : `${score}/100`;
  const scorePercent = score === null || score === undefined ? 0 : clampPercent(score);
  const technicalSeverityCounts = getTechnicalSeverityCounts(findings);
  const statusCounts = getStatusCounts(findings);
  const toolCounts = buildToolCounts(data, findings);
  const riskBreakdown = data.risk_score_breakdown || data.riskScoreBreakdown || {};
  const riskExplanation = riskBreakdown.explanation ||
    'El score prioriza vulnerabilidades confirmadas y evidencia de explotacion. GF, hardening y superficie tienen peso limitado.';

  return `
    <section class="security-dashboard">
      <div class="dashboard-head">
        <div>
          <h2>Resumen visual del analisis</h2>
          <p>Riesgo, distribucion tecnica y hallazgos por herramienta sin mezclarlo con la lista tecnica.</p>
        </div>
        <span class="terminal-badge status-ok">[ LIVE REPORT ]</span>
      </div>
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
          <p class="terminal-subtle">${escaparHtml(riskExplanation)}</p>
        </article>
        <article class="terminal-card chart-card">
          <div class="group-header">
            <h2>DISTRIBUCION TECNICA TOTAL</h2>
            <span>${escaparHtml(Object.values(technicalSeverityCounts).reduce((sum, value) => sum + value, 0))}</span>
          </div>
          <p class="terminal-subtle">Incluye candidatos, hardening y superficie; no todo es explotable.</p>
          ${renderSeverityChart(technicalSeverityCounts)}
          <p class="terminal-subtle">Confirmadas: ${escaparHtml(statusCounts.confirmed)} · Posibles: ${escaparHtml(statusCounts.possible)} · GF: ${escaparHtml(statusCounts.candidate)} · Hardening: ${escaparHtml(statusCounts.hardening)} · Superficie: ${escaparHtml(statusCounts.surface)}</p>
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
  const riskBreakdown = data.risk_score_breakdown || data.riskScoreBreakdown || {};
  return `
    <section class="terminal-card risk-score-card">
      <div class="group-header">
        <h2>RIESGO FINAL</h2>
        <span>${escaparHtml(grade)}</span>
      </div>
      <div class="risk-score-value">${escaparHtml(scoreText)} <span>[${escaparHtml(String(level).toUpperCase())}]</span></div>
      <div class="risk-bar">${escaparHtml(barraAsciiRiesgo(score))}</div>
      <p class="terminal-subtle">Fuente: ${data.finalScoreSource === 'ai_global_review' ? 'revision IA global sobre todos los hallazgos enriquecidos' : 'pendiente de revision IA global'}.</p>
      <p class="terminal-subtle">${escaparHtml(riskBreakdown.explanation || 'El score prioriza evidencia confirmada; candidatos, hardening y superficie tienen peso limitado.')}</p>
      ${(data.aiFinalScoreReason || riskBreakdown.aiFinalScoreReason) ? `<p class="terminal-subtle">Motivo IA: ${escaparHtml(data.aiFinalScoreReason || riskBreakdown.aiFinalScoreReason)}</p>` : ''}
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
    ${renderListaPriorizada(allFindings)}
    ${notices.map(n => `<p class="notice">${escaparHtml(n)}</p>`).join('')}
    ${renderCorrelaciones(data.correlations || [])}
  `;
  activarInteraccionVisual(resultados);

  resultados.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.dataset.filterType === 'categoria') filtroCategoria = btn.dataset.filterValue;
      if (btn.dataset.filterType === 'severidad') filtroSeveridad = btn.dataset.filterValue;
      renderFindings(data.findings || [], data.groups || null);
    });
  });

  const searchInput = resultados.querySelector('#findingSearch');
  if (searchInput) {
    searchInput.addEventListener('input', event => {
      filtroBusqueda = String(event.target.value || '').trim().toLowerCase();
      renderFindings(data.findings || [], data.groups || null);
      const nextSearch = resultados.querySelector('#findingSearch');
      if (nextSearch) {
        nextSearch.focus();
        nextSearch.setSelectionRange(nextSearch.value.length, nextSearch.value.length);
      }
    });
  }

  resultados.querySelectorAll('.view-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      vistaCompacta = btn.dataset.viewMode === 'compact';
      renderFindings(data.findings || [], data.groups || null);
    });
  });

  const exportBtn = resultados.querySelector('.export-visible-csv');
  if (exportBtn) exportBtn.addEventListener('click', exportarFindingsVisiblesCSV);
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
  filtroBusqueda = '';
  vistaCompacta = false;
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
        risk_score_breakdown: ultimoAnalisis.risk_score_breakdown || ultimoAnalisis.riskScoreBreakdown,
        deterministicScoreBeforeAI: ultimoAnalisis.deterministicScoreBeforeAI,
        aiFinalScore100: ultimoAnalisis.aiFinalScore100,
        finalScoreSource: ultimoAnalisis.finalScoreSource,
        aiFinalScoreReason: ultimoAnalisis.aiFinalScoreReason,
        aiFinalRiskLevel: ultimoAnalisis.aiFinalRiskLevel,
        aiFinalScoreStatus: ultimoAnalisis.aiFinalScoreStatus,
        ai_stats: ultimoAnalisis.ai_stats || ultimoAnalisis.ai_personalization_stats,
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
    filtroBusqueda = '';
    vistaCompacta = false;
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

activarInteraccionVisual(document);
activarHaloCursor();
