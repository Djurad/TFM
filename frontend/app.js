const btnAnalizar = document.getElementById('btnAnalizar');
const btnGenerarInforme = document.getElementById('btnGenerarInforme');
const promptInput = document.getElementById('prompt');
const estado = document.getElementById('estado');
const resumen = document.getElementById('resumen');
const resultados = document.getElementById('resultados');
const herramientas = document.getElementById('herramientas');

let ultimoAnalisis = null;

const severityLabels = {
  critical: 'Critica',
  high: 'Alta',
  medium: 'Media',
  low: 'Baja',
  info: 'Info'
};

const groupLabels = {
  confirmadas: 'Vulnerabilidades confirmadas',
  posibles: 'Posibles vulnerabilidades',
  total_vulnerabilidades: 'Total vulnerabilidades reportables',
  superficie: 'Superficie descubierta',
  reconocimiento: 'Reconocimiento informativo',
  descartados: 'Descartados / falsos positivos'
};

function setEstado(texto, tipo = '') {
  estado.textContent = texto;
  estado.className = tipo ? `status ${tipo}` : 'status';
}

function escaparHtml(valor) {
  return String(valor ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function renderResumen(summary = {}) {
  resumen.innerHTML = '';

  [
    'confirmadas',
    'posibles',
    'total_vulnerabilidades',
    'superficie',
    'reconocimiento',
    'descartados'
  ].forEach(key => {
    const item = document.createElement('div');
    item.className = `summary-item summary-${key}`;
    item.innerHTML = `
      <span>${groupLabels[key]}</span>
      <strong>${summary[key] || 0}</strong>
    `;
    resumen.appendChild(item);
  });
}

function renderHerramientas(toolResults = {}) {
  herramientas.innerHTML = '';
  const counters = ultimoAnalisis?.tool_counters || {};

  Object.entries(toolResults).forEach(([tool, result]) => {
    const detalle = obtenerDetalleHerramienta(tool, result, counters[tool]);
    const item = document.createElement('div');
    item.className = 'tool-row';
    item.innerHTML = `
      <strong>${escaparHtml(tool)}</strong>
      <span class="tool-status">${escaparHtml(result.status)}</span>
      <span>${escaparHtml(detalle)}</span>
      ${result.error ? `<small>${escaparHtml(result.error)}</small>` : ''}
      ${result.warning ? `<small>${escaparHtml(result.warning)}</small>` : ''}
    `;
    herramientas.appendChild(item);
  });
}

function obtenerDetalleHerramienta(tool, result, counter = {}) {
  if (tool === 'subfinder') return `${counter.subdominios_encontrados || result.parsed_count || 0} subdominios`;
  if (tool === 'httpx') return `${counter.activos_vivos || result.parsed_count || 0} vivos`;
  if (tool === 'katana') {
    return `${counter.endpoints_encontrados || result.parsed_count || 0} normalizados / ${counter.raw_urls || 0} crudos / ${counter.superficie_util || 0} superficie`;
  }
  if (tool === 'gau') return `${counter.endpoints_encontrados || result.parsed_count || 0} historicas / ${counter.con_parametros || 0} con parametros`;
  if (tool === 'gf') return `${counter.xss || 0} XSS / ${counter.sqli || 0} SQLi / ${counter.ssrf || 0} SSRF / ${counter.redirect || 0} Redirect / ${counter.lfi || 0} LFI / ${counter.rce || 0} RCE`;
  if (tool === 'feroxbuster') return `${counter.rutas_descubiertas || 0} rutas / ${counter.rutas_sensibles || 0} sensibles`;
  if (tool === 'trufflehog') {
    return `${counter.secretos_confirmados || 0} secretos confirmados / ${counter.secretos_posibles || 0} posibles / ${counter.recursos_descargados || 0}/${counter.recursos_candidatos || 0} recursos / ${counter.recursos_fallidos || 0} fallidos`;
  }
  if (tool === 'nuclei') return `${counter.vulnerabilidades_reales || 0} vulnerabilidades`;
  if (tool === 'sqlmap') {
    if (counter.no_ejecutada) return 'no ejecutada';
    return `${counter.confirmadas || 0} confirmadas / ${counter.posibles || 0} posibles`;
  }
  return `${(result.findings || []).length} hallazgos`;
}

function badgeFinding(finding) {
  if (finding.type === 'surface') return { label: 'Superficie', className: 'badge-surface' };
  if (finding.type === 'discarded') return { label: 'Descartado', className: 'badge-discarded' };
  if (!finding.isVulnerability || finding.type === 'reconocimiento') return { label: 'Info', className: 'badge-info' };
  if (finding.confidence === 'high') return { label: 'Confirmada', className: 'badge-confirmed' };
  return { label: 'Posible', className: 'badge-possible' };
}

function crearCardFinding(finding, modo = 'vulnerability') {
  const severity = finding.severity || 'info';
  const card = document.createElement('article');
  const badge = badgeFinding(finding);
  card.className = `finding finding-${modo} severity-${severity}`;
  card.innerHTML = `
    <header>
      <div>
        <span class="badge">${escaparHtml(finding.tool)}</span>
        <span class="badge ${badge.className}">${escaparHtml(badge.label)}</span>
      </div>
      ${modo === 'vulnerability' ? `<span class="severity">${severityLabels[severity] || escaparHtml(severity)}</span>` : ''}
    </header>
    <h2>${escaparHtml(finding.title)}</h2>
    <p>${escaparHtml(finding.description)}</p>
    <dl>
      <dt>Activo</dt>
      <dd>${escaparHtml(finding.affected_url || finding.affected_asset || '-')}</dd>
      <dt>Evidencia</dt>
      <dd>${escaparHtml(finding.evidence)}</dd>
      <dt>Impacto</dt>
      <dd>${escaparHtml(finding.impact || '-')}</dd>
      <dt>Recomendacion</dt>
      <dd>${escaparHtml(finding.recommendation || '-')}</dd>
      ${finding.isFalsePositiveLikely ? `
        <dt>Posible falso positivo</dt>
        <dd>${escaparHtml(finding.falsePositiveReason || 'Baja confianza o evidencia limitada.')}</dd>
      ` : ''}
    </dl>
  `;
  return card;
}

function renderGrupo(titulo, descripcion, findings, opciones = {}) {
  const section = document.createElement('section');
  section.className = `result-group ${opciones.secundario ? 'result-group-secondary' : ''}`;
  section.innerHTML = `
    <header class="group-header">
      <h2>${escaparHtml(titulo)}</h2>
      <span>${findings.length}</span>
    </header>
    ${descripcion ? `<p class="group-desc">${escaparHtml(descripcion)}</p>` : ''}
  `;

  const lista = document.createElement('div');
  lista.className = 'group-list';

  if (!findings.length) {
    lista.innerHTML = '<p class="empty">Sin hallazgos en esta categoria.</p>';
  } else {
    findings.forEach(finding => lista.appendChild(crearCardFinding(finding, opciones.modo || 'vulnerability')));
  }

  section.appendChild(lista);
  resultados.appendChild(section);
}

function renderSeccionVulnerabilidades(agrupados) {
  const section = document.createElement('section');
  section.className = 'result-group vulnerabilities-main';
  section.innerHTML = `
    <header class="group-header group-header-main">
      <h2>Vulnerabilidades detectadas</h2>
      <span>${(agrupados.confirmadas || []).length + (agrupados.posibles || []).length}</span>
    </header>
    <p class="group-desc">Solo se muestran vulnerabilidades confirmadas o posibles con evidencia tecnica.</p>
  `;
  resultados.appendChild(section);

  renderGrupo('Confirmadas', 'Evidencia fuerte y alta confianza.', agrupados.confirmadas || []);
  renderGrupo('Posibles', 'Evidencia parcial que requiere validacion manual.', agrupados.posibles || []);
}

function renderSuperficieColapsable(superficie = []) {
  const details = document.createElement('details');
  details.className = 'surface-details';
  details.innerHTML = `
    <summary>
      <span>Ver superficie descubierta</span>
      <strong>${superficie.length}</strong>
    </summary>
    <p class="group-desc">No son vulnerabilidades confirmadas. Son rutas utiles para revision manual.</p>
  `;

  const lista = document.createElement('div');
  lista.className = 'group-list surface-list';

  if (!superficie.length) {
    lista.innerHTML = '<p class="empty">Sin superficie sensible destacable.</p>';
  } else {
    superficie.forEach(finding => lista.appendChild(crearCardFinding(finding, 'surface')));
  }

  details.appendChild(lista);
  resultados.appendChild(details);
}

function renderGfCandidates(candidates = {}) {
  const total = Object.values(candidates).reduce((sum, items) => sum + (Array.isArray(items) ? items.length : 0), 0);
  const details = document.createElement('details');
  details.className = 'surface-details';
  details.innerHTML = `
    <summary>
      <span>Ver candidatos priorizados por GF</span>
      <strong>${total}</strong>
    </summary>
    <p class="group-desc">GF no confirma vulnerabilidades: solo prioriza endpoints para Dalfox, sqlmap y validaciones dirigidas.</p>
  `;

  const lista = document.createElement('div');
  lista.className = 'gf-candidates';

  Object.entries(candidates).forEach(([tipo, urls]) => {
    const items = Array.isArray(urls) ? urls.slice(0, 20) : [];
    const bloque = document.createElement('section');
    bloque.className = 'candidate-block';
    bloque.innerHTML = `
      <h3>${escaparHtml(tipo.toUpperCase())} (${items.length})</h3>
      ${items.length ? `<ul>${items.map(url => `<li>${escaparHtml(url)}</li>`).join('')}</ul>` : '<p class="empty">Sin candidatos.</p>'}
    `;
    lista.appendChild(bloque);
  });

  details.appendChild(lista);
  resultados.appendChild(details);
}

function agruparLocal(findings = []) {
  return {
    confirmadas: findings.filter(f => f.isVulnerability && f.confidence === 'high' && !f.isFalsePositiveLikely),
    posibles: findings.filter(f => f.isVulnerability && f.confidence === 'medium' && !f.isFalsePositiveLikely),
    baja_confianza: findings.filter(f => f.isVulnerability && (f.confidence === 'low' || f.isFalsePositiveLikely)),
    superficie: findings.filter(f => f.type === 'surface'),
    reconocimiento: findings.filter(f => (!f.isVulnerability || f.type === 'reconocimiento') && f.type !== 'surface' && f.type !== 'discarded'),
    descartados: findings.filter(f => f.type === 'discarded')
  };
}

function renderFindings(findings = [], groups = null) {
  resultados.innerHTML = '';

  if (!findings.length && !ultimoAnalisis?.sqlmap_notice) {
    resultados.innerHTML = '<p class="empty">No se han identificado vulnerabilidades relevantes.</p>';
    return;
  }

  const agrupados = groups || agruparLocal(findings);

  if (ultimoAnalisis?.sqlmap_notice) {
    const aviso = document.createElement('p');
    aviso.className = 'notice';
    aviso.textContent = ultimoAnalisis.sqlmap_notice;
    resultados.appendChild(aviso);
  }

  if (ultimoAnalisis?.ai_notice) {
    const avisoIa = document.createElement('p');
    avisoIa.className = 'notice';
    avisoIa.textContent = ultimoAnalisis.ai_notice;
    resultados.appendChild(avisoIa);
  }

  renderSeccionVulnerabilidades(agrupados);
  renderSuperficieColapsable(agrupados.superficie || []);
  renderGfCandidates(ultimoAnalisis?.gf_candidates || {});
  renderGrupo('Reconocimiento informativo', 'Fingerprinting, WAF, DNS y tecnologias. No se tratan como vulnerabilidades.', agrupados.reconocimiento || [], { secundario: true, modo: 'info' });
  renderGrupo('Falsos positivos o descartados', 'Assets estaticos, hardening de baja confianza o hallazgos sin evidencia suficiente.', [
    ...(agrupados.baja_confianza || []),
    ...(agrupados.descartados || [])
  ], { secundario: true, modo: 'discarded' });
}

btnAnalizar.addEventListener('click', async () => {
  const prompt = promptInput.value.trim();

  if (!prompt) {
    setEstado('Escribe una URL o dominio.', 'error');
    return;
  }

  ultimoAnalisis = null;
  btnGenerarInforme.disabled = true;
  renderResumen();
  herramientas.innerHTML = '';
  resultados.innerHTML = '';
  setEstado('Ejecutando herramientas y extrayendo hallazgos por IA...', 'loading');

  try {
    const response = await fetch('/analizar', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: prompt })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Error desconocido');
    }

    ultimoAnalisis = data;
    renderResumen(data.summary_ui || data.summary);
    renderHerramientas(data.tool_results);
    renderFindings(data.findings, data.groups);
    btnGenerarInforme.disabled = false;
    setEstado(`Analisis completado para ${data.target}.`, 'success');
  } catch (error) {
    setEstado(`Error: ${error.message}`, 'error');
  }
});

btnGenerarInforme.addEventListener('click', async () => {
  if (!ultimoAnalisis) {
    setEstado('Primero ejecuta un analisis.', 'error');
    return;
  }

  btnGenerarInforme.disabled = true;
  setEstado('Generando informe PDF con los hallazgos mostrados...', 'loading');

  try {
    const response = await fetch('/generar-informe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: ultimoAnalisis.target,
        findings: ultimoAnalisis.findings || [],
        gf_candidates: ultimoAnalisis.gf_candidates || {},
        tool_results: ultimoAnalisis.tool_results || {}
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

    setEstado('Informe generado correctamente.', 'success');
  } catch (error) {
    setEstado(`Error: ${error.message}`, 'error');
  } finally {
    btnGenerarInforme.disabled = false;
  }
});
