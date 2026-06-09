const { requestUrl, deduplicarOrigenes } = require('./passiveHttp');

const SENSITIVE_PATHS = [
  '/admin',
  '/backup',
  '/private',
  '/debug',
  '/test',
  '/config',
  '/.git',
  '/.env',
  '/phpmyadmin'
];

function extraerRutasRobots(body = '') {
  return String(body)
    .split('\n')
    .map(line => line.trim())
    .filter(line => /^(disallow|allow|sitemap):/i.test(line))
    .map(line => {
      const [directive, ...rest] = line.split(':');
      return {
        directive: directive.toLowerCase(),
        value: rest.join(':').trim()
      };
    })
    .filter(item => item.value);
}

function rutasSensibles(entries = []) {
  return entries.filter(item => SENSITIVE_PATHS.some(path => item.value.toLowerCase().includes(path)));
}

async function comprobarRecurso(origin, path, timeoutMs) {
  const url = `${origin}${path}`;
  try {
    const response = await requestUrl(url, { method: 'GET', timeoutMs, rejectUnauthorized: false, maxBytes: 256 * 1024 });
    const exists = response.statusCode >= 200 && response.statusCode < 300;
    const entries = path === '/robots.txt' && exists ? extraerRutasRobots(response.body) : [];

    return {
      url,
      path,
      statusCode: response.statusCode,
      exists,
      entries,
      sensitiveEntries: rutasSensibles(entries)
    };
  } catch (error) {
    return {
      url,
      path,
      exists: false,
      error: error.message,
      entries: [],
      sensitiveEntries: []
    };
  }
}

async function ejecutarRobotsSitemap(activos = [], opciones = {}) {
  const timeoutMs = Number(opciones.timeoutMs || 8000);
  const maxTargets = Number(opciones.maxTargets || process.env.MAX_PASSIVE_TARGETS || 20);
  const origins = deduplicarOrigenes(activos).slice(0, maxTargets);
  const parsed = [];

  if (!origins.length) {
    return {
      status: 'skipped',
      raw: '',
      parsed: [],
      findings: [],
      error: 'robotsSitemap no se ejecuto porque no hay activos HTTP vivos',
      metrics: { recursos_encontrados: 0, rutas_sensibles: 0 }
    };
  }

  for (const origin of origins) {
    parsed.push(await comprobarRecurso(origin, '/robots.txt', timeoutMs));
    parsed.push(await comprobarRecurso(origin, '/sitemap.xml', timeoutMs));
  }

  return {
    status: 'success',
    raw: JSON.stringify(parsed, null, 2),
    parsed,
    findings: [],
    metrics: {
      recursos_encontrados: parsed.filter(item => item.exists).length,
      robots_encontrados: parsed.filter(item => item.path === '/robots.txt' && item.exists).length,
      sitemaps_encontrados: parsed.filter(item => item.path === '/sitemap.xml' && item.exists).length,
      rutas_sensibles: parsed.reduce((sum, item) => sum + item.sensitiveEntries.length, 0)
    }
  };
}

module.exports = {
  ejecutarRobotsSitemap
};
