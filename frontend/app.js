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

  ['critical', 'high', 'medium', 'low', 'info'].forEach(severity => {
    const item = document.createElement('div');
    item.className = `summary-item severity-${severity}`;
    item.innerHTML = `
      <span>${severityLabels[severity]}</span>
      <strong>${summary[severity] || 0}</strong>
    `;
    resumen.appendChild(item);
  });
}

function renderHerramientas(toolResults = {}) {
  herramientas.innerHTML = '';

  Object.entries(toolResults).forEach(([tool, result]) => {
    const item = document.createElement('div');
    item.className = 'tool-row';
    item.innerHTML = `
      <strong>${escaparHtml(tool)}</strong>
      <span class="tool-status">${escaparHtml(result.status)}</span>
      <span>${(result.findings || []).length} hallazgos</span>
      ${result.error ? `<small>${escaparHtml(result.error)}</small>` : ''}
    `;
    herramientas.appendChild(item);
  });
}

function renderFindings(findings = []) {
  resultados.innerHTML = '';

  if (!findings.length) {
    resultados.innerHTML = '<p class="empty">No se han identificado vulnerabilidades relevantes.</p>';
    return;
  }

  findings.forEach(finding => {
    const severity = finding.severity || 'info';
    const card = document.createElement('article');
    card.className = `finding severity-${severity}`;
    card.innerHTML = `
      <header>
        <div>
          <span class="badge">${escaparHtml(finding.tool)}</span>
          <span class="badge muted">${escaparHtml(finding.confidence)}</span>
        </div>
        <span class="severity">${severityLabels[severity] || escaparHtml(severity)}</span>
      </header>
      <h2>${escaparHtml(finding.title)}</h2>
      <p>${escaparHtml(finding.description)}</p>
      <dl>
        <dt>Activo</dt>
        <dd>${escaparHtml(finding.affected_url || finding.affected_asset || '-')}</dd>
        <dt>Evidencia</dt>
        <dd>${escaparHtml(finding.evidence)}</dd>
        <dt>Impacto</dt>
        <dd>${escaparHtml(finding.impact)}</dd>
        <dt>Recomendacion</dt>
        <dd>${escaparHtml(finding.recommendation)}</dd>
      </dl>
    `;
    resultados.appendChild(card);
  });
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
    renderResumen(data.summary);
    renderHerramientas(data.tool_results);
    renderFindings(data.findings);
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
        findings: ultimoAnalisis.findings || []
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
