const { requestUrl, deduplicarOrigenes } = require('./passiveHttp');

const SECURITY_HEADERS = [
  'content-security-policy',
  'x-frame-options',
  'strict-transport-security',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy'
];

const BANNER_HEADERS = [
  'server',
  'x-powered-by'
];

function headerValue(headers, name) {
  return headers[String(name).toLowerCase()] || null;
}

function analizarHeaders(url, response) {
  const headers = response.headers || {};
  const isHttps = String(url).startsWith('https://');
  const missing = SECURITY_HEADERS.filter(name => {
    if (name === 'strict-transport-security' && !isHttps) return false;
    return !headerValue(headers, name);
  });
  const present = SECURITY_HEADERS.filter(name => headerValue(headers, name));
  const banners = BANNER_HEADERS
    .map(name => ({ name, value: headerValue(headers, name) }))
    .filter(item => item.value);

  return {
    url,
    statusCode: response.statusCode,
    present,
    missing,
    banners,
    headers: Object.fromEntries([...SECURITY_HEADERS, ...BANNER_HEADERS].map(name => [name, headerValue(headers, name)])),
    isHttps
  };
}

async function ejecutarHeaders(activos = [], opciones = {}) {
  const timeoutMs = Number(opciones.timeoutMs || 8000);
  const maxTargets = Number(opciones.maxTargets || process.env.MAX_PASSIVE_TARGETS || 20);
  const targets = deduplicarOrigenes(activos).slice(0, maxTargets);
  const parsed = [];
  const errores = [];

  if (!targets.length) {
    return {
      status: 'skipped',
      raw: '',
      parsed: [],
      findings: [],
      error: 'headers no se ejecuto porque no hay activos HTTP vivos',
      metrics: { activos_analizados: 0, cabeceras_ausentes: 0, banners_expuestos: 0 }
    };
  }

  for (const url of targets) {
    try {
      const response = await requestUrl(url, { method: 'GET', timeoutMs, rejectUnauthorized: false, maxBytes: 64 * 1024 });
      parsed.push(analizarHeaders(url, response));
    } catch (error) {
      errores.push({ url, error: error.message });
    }
  }

  return {
    status: parsed.length ? (errores.length ? 'partial' : 'success') : 'error',
    raw: JSON.stringify({ parsed, errores }, null, 2),
    parsed,
    findings: [],
    error: parsed.length ? null : `headers no pudo analizar ningun activo: ${errores.map(e => `${e.url}: ${e.error}`).join(' | ')}`,
    warning: errores.length && parsed.length ? `headers fallo en ${errores.length} activo(s)` : null,
    metrics: {
      activos_analizados: parsed.length,
      cabeceras_ausentes: parsed.reduce((sum, item) => sum + item.missing.length, 0),
      banners_expuestos: parsed.reduce((sum, item) => sum + item.banners.length, 0),
      activos_fallidos: errores.length
    }
  };
}

module.exports = {
  ejecutarHeaders
};
