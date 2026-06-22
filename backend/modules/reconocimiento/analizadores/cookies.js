const { requestUrl, deduplicarOrigenes, normalizarSetCookie } = require('./passiveHttp');

const SESSION_COOKIE_NAMES = [
  'jsessionid',
  'phpsessid',
  'session',
  'sessionid',
  'connect.sid',
  'sid',
  'auth',
  'token'
];

function parseCookie(raw = '') {
  const parts = String(raw).split(';').map(part => part.trim()).filter(Boolean);
  const [nameValue, ...attrs] = parts;
  const [name, ...valueParts] = String(nameValue || '').split('=');
  const attrMap = new Map();

  attrs.forEach(attr => {
    const [key, ...rest] = attr.split('=');
    attrMap.set(String(key || '').toLowerCase(), rest.join('=') || true);
  });

  const lowerName = String(name || '').toLowerCase();

  return {
    name: name || '',
    valueLength: valueParts.join('=').length,
    isSessionCookie: SESSION_COOKIE_NAMES.some(token => lowerName === token || lowerName.includes(token)),
    secure: attrMap.has('secure'),
    httpOnly: attrMap.has('httponly'),
    sameSite: attrMap.get('samesite') || null,
    path: attrMap.get('path') || null,
    domain: attrMap.get('domain') || null,
    raw: String(raw).replace(/=([^;]{4})[^;]*/g, '=***')
  };
}

function analizarCookies(url, response) {
  const cookies = normalizarSetCookie(response.rawHeaders).map(parseCookie);

  return {
    url,
    statusCode: response.statusCode,
    isHttps: String(url).startsWith('https://'),
    cookies
  };
}

async function ejecutarCookies(activos = [], opciones = {}) {
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
      error: 'cookies no se ejecuto porque no hay activos HTTP vivos',
      metrics: { cookies_analizadas: 0, cookies_sesion: 0, cookies_inseguras: 0 }
    };
  }

  for (const url of targets) {
    try {
      const response = await requestUrl(url, { method: 'GET', timeoutMs, rejectUnauthorized: false, maxBytes: 64 * 1024 });
      parsed.push(analizarCookies(url, response));
    } catch (error) {
      errores.push({ url, error: error.message });
    }
  }

  const cookies = parsed.flatMap(item => item.cookies);
  const inseguras = parsed.flatMap(item => item.cookies.filter(cookie =>
    (item.isHttps && !cookie.secure) ||
    (cookie.isSessionCookie && (!cookie.httpOnly || !cookie.sameSite))
  ));

  return {
    status: parsed.length ? (errores.length ? 'partial' : 'success') : 'error',
    raw: JSON.stringify({ parsed, errores }, null, 2),
    parsed,
    findings: [],
    error: parsed.length ? null : `cookies no pudo analizar ningun activo: ${errores.map(e => `${e.url}: ${e.error}`).join(' | ')}`,
    warning: errores.length && parsed.length ? `cookies fallo en ${errores.length} activo(s)` : null,
    metrics: {
      activos_analizados: parsed.length,
      cookies_analizadas: cookies.length,
      cookies_sesion: cookies.filter(cookie => cookie.isSessionCookie).length,
      cookies_inseguras: inseguras.length,
      activos_fallidos: errores.length
    }
  };
}

module.exports = {
  ejecutarCookies
};
