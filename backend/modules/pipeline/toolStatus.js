function compactText(value) {
  return String(value || '').replace(/\s+/g, ' ').trim();
}

function canonicalTool(tool = '') {
  const normalized = String(tool || '').trim();
  const lower = normalized.toLowerCase();
  const aliases = {
    httpsredirect: 'httpsRedirect',
    https: 'httpsRedirect',
    robotssitemap: 'robotsSitemap',
    ferox: 'feroxbuster',
    'score final': 'score final',
    correlacion: 'correlacion'
  };
  return aliases[lower] || normalized || 'herramienta';
}

function normalizedStatusValue(status = '') {
  const lower = String(status || '').trim().toLowerCase();
  if (['ok', 'success', 'done', 'ready', 'completed', 'complete'].includes(lower)) return 'success';
  if (['partial', 'warning', 'warn', 'limited', 'timeout'].includes(lower)) return 'partial';
  if (['skip', 'skipped', 'omitido', 'omitted'].includes(lower)) return 'skipped';
  if (['cancelled', 'canceled', 'cancelado', 'cancelada'].includes(lower)) return 'cancelled';
  if (['fail', 'failed', 'failure', 'error'].includes(lower)) return 'error';
  return lower || 'skipped';
}

function joinedDetails(result = {}) {
  return compactText([
    result.status_message,
    result.message,
    result.reason,
    result.warning,
    result.error,
    result.skipped_reason,
    result.fallback_reason,
    result.technicalDetails,
    result.operationalWarning
  ].filter(Boolean).join(' | '));
}

function hasAny(text, tokens = []) {
  const lower = String(text || '').toLowerCase();
  return tokens.some(token => lower.includes(token));
}

function isRecoverableOperational(result = {}, text = '') {
  return result.blocking !== true && (
    result.metrics?.non_blocking === true ||
    result.metrics?.timed_out === true ||
    result.metrics?.fallback === true ||
    result.metrics?.fallback_used === true ||
    result.fallback_used === true ||
    hasAny(text, [
      'timeout',
      'timed out',
      'etimedout',
      'eacces',
      'fallback',
      'cobertura parcial',
      'cobertura limitada',
      'no comprobable',
      'no se pudieron',
      'no pudo comprobar',
      'no pudo extraer',
      'no devolvio',
      'sin resultados',
      'sin wordlist',
      'sin detener el pipeline'
    ])
  );
}

function isBinaryFailure(text = '') {
  return hasAny(text, [
    'enoent',
    'not found',
    'not installed',
    'no instalado',
    'binario no encontrado',
    'command not found'
  ]);
}

function hasFallback(result = {}, text = '') {
  return Boolean(
    result.fallback_used ||
    result.metrics?.fallback ||
    result.metrics?.fallback_used ||
    hasAny(text, ['fallback', 'url normalizada', 'baseurl'])
  );
}

function messageFor(tool, result = {}, flags = {}) {
  const toolName = canonicalTool(tool);
  const details = flags.details;
  const timeout = flags.timeout;
  const fallback = flags.fallback;
  const status = flags.status;

  if (toolName === 'httpx' && (fallback || hasAny(details, ['no obtuvo fingerprint', '0 activos vivos']))) {
    return 'httpx no obtuvo fingerprint HTTP; se continuo con URL normalizada.';
  }
  if (toolName === 'headers' && (timeout || status === 'partial')) {
    return 'No se pudieron comprobar cabeceras por timeout; cobertura limitada.';
  }
  if (toolName === 'cookies' && (timeout || status === 'partial')) {
    return 'No se pudieron comprobar cookies por timeout; cobertura limitada.';
  }
  if (toolName === 'httpsRedirect' && (timeout || status === 'partial')) {
    return 'No se pudo comprobar redireccion HTTP->HTTPS por timeout.';
  }
  if (toolName === 'tls' && (timeout || status === 'partial')) {
    return 'No se pudo extraer certificado TLS por timeout.';
  }
  if (toolName === 'gau' && status === 'partial') {
    return 'Los providers historicos no devolvieron URLs o excedieron timeout. Se usaron endpoints disponibles.';
  }
  if (toolName === 'nuclei' && (timeout || status === 'partial')) {
    return 'Nuclei tuvo cobertura limitada o excedio el timeout; el pipeline continuo.';
  }
  if (toolName === 'trufflehog' && status === 'partial') {
    return 'La busqueda de secretos tuvo cobertura parcial en recursos descargables.';
  }
  if (status === 'skipped') {
    return result.skipped_reason || result.reason || result.error || `No habia entrada valida para ${toolName}.`;
  }
  if (status === 'cancelled') {
    return result.warning || result.reason || `${toolName} fue cancelada manualmente.`;
  }
  if (status === 'error') {
    return result.error || result.reason || `Fallo operativo de ${toolName}.`;
  }
  if (status === 'partial' || fallback) {
    return result.warning || result.reason || `${toolName} se ejecuto con cobertura limitada.`;
  }
  return result.message || `${toolName} ejecutada correctamente.`;
}

function normalizeToolStatus(result = {}, tool = '') {
  const details = joinedDetails(result);
  let status = normalizedStatusValue(result.status);
  const timeout = hasAny(details, ['timeout', 'timed out', 'etimedout']);
  const fallback = hasFallback(result, details);
  const recoverable = isRecoverableOperational(result, details);
  const binaryFailure = isBinaryFailure(details);

  if (result.uiStatus || result.ui_status) {
    const uiInput = String(result.uiStatus || result.ui_status).toLowerCase();
    if (uiInput === 'limited') status = status === 'error' && !recoverable ? 'error' : 'partial';
    if (uiInput === 'ok') status = status === 'skipped' ? 'success' : status;
    if (uiInput === 'fail') status = 'error';
  }

  let uiStatus = 'ok';
  let severityForUi = 'normal';
  let coverageLimited = false;

  if (status === 'success') {
    coverageLimited = fallback;
    uiStatus = fallback ? 'limited' : 'ok';
    severityForUi = fallback ? 'info' : 'normal';
  } else if (status === 'partial') {
    coverageLimited = true;
    uiStatus = 'limited';
    severityForUi = 'info';
  } else if (status === 'skipped') {
    uiStatus = 'skipped';
    severityForUi = 'info';
  } else if (status === 'cancelled') {
    uiStatus = 'cancelled';
    severityForUi = 'warning';
  } else if (status === 'error') {
    if (recoverable && !binaryFailure) {
      coverageLimited = true;
      uiStatus = 'limited';
      severityForUi = 'info';
      status = 'partial';
    } else {
      uiStatus = 'fail';
      severityForUi = 'error';
    }
  }

  const message = messageFor(tool, result, { details, timeout, fallback, status });
  const operationalWarning = coverageLimited || uiStatus === 'fail'
    ? message
    : null;

  return {
    status,
    uiStatus,
    severityForUi,
    isBlocking: result.blocking === true,
    isSecurityFinding: false,
    coverageLimited,
    message,
    technicalDetails: details || null,
    operationalWarning,
    securityWarning: null
  };
}

function buildCoverageLimitations(toolResults = {}) {
  return Object.entries(toolResults || {})
    .map(([tool, result]) => ({
      tool: canonicalTool(tool),
      ...normalizeToolStatus(result, tool)
    }))
    .filter(item => item.coverageLimited)
    .map(item => ({
      tool: item.tool,
      status: item.status,
      uiStatus: item.uiStatus,
      message: item.message,
      technicalDetails: item.technicalDetails
    }));
}

module.exports = {
  buildCoverageLimitations,
  normalizeToolStatus
};
