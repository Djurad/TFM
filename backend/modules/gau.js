const { execFile } = require('child_process');
const { esAssetEstatico } = require('./clasificadorFindings');

const PARAMS_INTERESANTES = [
  'id',
  'q',
  's',
  'search',
  'query',
  'page',
  'file',
  'path',
  'url',
  'uri',
  'redirect',
  'redirect_uri',
  'next',
  'return',
  'callback',
  'token'
];

const RUTAS_INTERESANTES = [
  'api',
  'login',
  'signin',
  'admin',
  'upload',
  'search',
  'callback',
  'redirect',
  'debug',
  'actuator',
  'swagger',
  'openapi',
  'api-doc'
];

const EXTENSIONES_DINAMICAS = ['.php', '.jsp', '.jspx', '.asp', '.aspx', '.cfm'];
const TRACKERS = ['google-analytics.com', 'googletagmanager.com', 'doubleclick.net', 'facebook.com/tr', 'analytics'];

function ejecutar(binario, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    execFile(binario, args, { timeout: timeoutMs, maxBuffer: 1024 * 1024 * 20 }, (error, stdout, stderr) => {
      if (error) {
        const salida = [stderr, error.message].filter(Boolean).join('\n');
        reject(new Error(salida || 'gau fallo sin salida de error.'));
        return;
      }
      resolve(stdout || '');
    });
  });
}

function pareceNoInstalada(error) {
  const msg = String(error?.message || '').toLowerCase();
  return msg.includes('not found') ||
    msg.includes('not recognized') ||
    msg.includes('no se reconoce') ||
    msg.includes('enoent');
}

function parsearLineas(texto = '') {
  return String(texto)
    .split('\n')
    .map(linea => linea.trim())
    .filter(Boolean);
}

function deduplicar(urls) {
  return Array.from(new Set(urls));
}

function categorizar(url) {
  const lower = String(url || '').toLowerCase();
  if (lower.includes('swagger') || lower.includes('openapi') || lower.includes('/api-doc')) return 'api-docs';
  if (lower.includes('login') || lower.includes('signin')) return 'login';
  if (lower.includes('/admin') || /(^|[/?&=])admin([/?&=]|$)/i.test(lower)) return 'admin';
  if (lower.includes('upload')) return 'upload';
  if (lower.includes('graphql')) return 'graphql';
  if (lower.includes('debug') || lower.includes('actuator')) return 'debug';
  if (lower.includes('backup') || lower.includes('config')) return 'suspicious';
  if (lower.includes('?')) return 'dinamico';
  return 'historico';
}

function normalizarEndpoint(url, source = 'gau', extra = {}) {
  let parsed = null;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }

  parsed.hash = '';
  const params = Array.from(parsed.searchParams.keys());
  const categoria = categorizar(parsed.href);

  return {
    url: parsed.href,
    path: parsed.pathname,
    params,
    queryParams: params,
    parametros: params,
    hasParams: params.length > 0,
    tieneParametros: params.length > 0,
    source,
    sourceTool: source,
    category: categoria,
    categoria,
    contentType: null,
    status: null,
    score: extra.score || 0,
    scoreReasons: extra.scoreReasons || []
  };
}

function hostnameTarget(dominio = '') {
  const limpio = String(dominio || '').trim().replace(/^https?:\/\//i, '').split('/')[0];
  return limpio.split(':')[0].toLowerCase();
}

function perteneceAlTarget(parsed, dominio) {
  const host = parsed.hostname.toLowerCase();
  const target = hostnameTarget(dominio);
  if (!target) return true;
  return host === target || host.endsWith(`.${target}`);
}

function extensionPath(pathname = '') {
  const match = String(pathname).toLowerCase().match(/(\.[a-z0-9]+)$/);
  return match ? match[1] : '';
}

function clavePatron(parsed) {
  const params = Array.from(parsed.searchParams.keys())
    .map(param => param.toLowerCase())
    .sort()
    .join(',');
  return [
    parsed.origin.toLowerCase(),
    parsed.pathname.replace(/\/+$/, '').toLowerCase() || '/',
    params,
    extensionPath(parsed.pathname)
  ].join('|');
}

function puntuarUrl(parsed, dominio) {
  let score = 0;
  const reasons = [];
  const url = parsed.href.toLowerCase();
  const pathname = parsed.pathname.toLowerCase();
  const params = Array.from(parsed.searchParams.keys()).map(param => param.toLowerCase());

  if (params.length > 0) {
    score += 5;
    reasons.push('parametros');
  }

  if (params.some(param => PARAMS_INTERESANTES.includes(param))) {
    score += 4;
    reasons.push('parametro_interesante');
  }

  if (EXTENSIONES_DINAMICAS.some(ext => pathname.endsWith(ext))) {
    score += 3;
    reasons.push('extension_dinamica');
  }

  if (RUTAS_INTERESANTES.some(token => pathname.includes(token) || url.includes(`${token}=`))) {
    score += 3;
    reasons.push('ruta_interesante');
  }

  if (esAssetEstatico(parsed.href)) {
    score -= 5;
    reasons.push('asset_estatico');
  }

  if (!perteneceAlTarget(parsed, dominio)) {
    score -= 10;
    reasons.push('externa');
  }

  return { score, reasons };
}

function filtrarYPriorizarUrlsGau(rawUrls = [], dominio, opciones = {}) {
  const filtrarExternas = opciones.filterExternal !== false && process.env.GAU_FILTER_EXTERNAL !== 'false';
  const maxParamUrls = Number(opciones.maxParamUrls || process.env.MAX_GAU_PARAM_URLS || 100);
  const maxSurfaceUrls = Number(opciones.maxSurfaceUrls || process.env.MAX_GAU_SURFACE_URLS || 100);
  const maxTotal = Number(opciones.maxTotal || process.env.MAX_GAU_TOTAL_AFTER_FILTER || 300);
  const maxPorPatron = Number(opciones.maxPerPattern || process.env.MAX_GAU_PER_PATTERN || 3);
  const stats = {
    raw_urls: rawUrls.length,
    urls_validas: 0,
    urls_externas_descartadas: 0,
    assets_descartados: 0,
    trackers_descartados: 0,
    duplicados_descartados: 0,
    patrones_deduplicados: 0,
    con_parametros: 0,
    seleccionadas_final: 0,
    enviadas_gf: 0,
    enviadas_ia: 0
  };
  const vistosUrl = new Set();
  const porPatron = new Map();
  const candidatos = [];

  rawUrls.forEach(rawUrl => {
    let parsed;
    try {
      parsed = new URL(rawUrl);
    } catch {
      return;
    }

    if (!/^https?:$/i.test(parsed.protocol)) return;
    parsed.hash = '';
    stats.urls_validas += 1;

    const hrefLower = parsed.href.toLowerCase();
    if (TRACKERS.some(token => hrefLower.includes(token))) {
      stats.trackers_descartados += 1;
      return;
    }

    if (filtrarExternas && !perteneceAlTarget(parsed, dominio)) {
      stats.urls_externas_descartadas += 1;
      return;
    }

    if (esAssetEstatico(parsed.href)) {
      stats.assets_descartados += 1;
      return;
    }

    const normalizedHref = parsed.href.replace(/\/$/, '');
    if (vistosUrl.has(normalizedHref)) {
      stats.duplicados_descartados += 1;
      return;
    }
    vistosUrl.add(normalizedHref);

    const pattern = clavePatron(parsed);
    const count = porPatron.get(pattern) || 0;
    if (count >= maxPorPatron) {
      stats.patrones_deduplicados += 1;
      return;
    }
    porPatron.set(pattern, count + 1);

    const { score, reasons } = puntuarUrl(parsed, dominio);
    const endpoint = normalizarEndpoint(parsed.href, 'gau', { score, scoreReasons: reasons });
    if (!endpoint) return;
    candidatos.push(endpoint);
  });

  stats.con_parametros = candidatos.filter(endpoint => endpoint.hasParams).length;

  const ordenar = (a, b) =>
    (b.score || 0) - (a.score || 0) ||
    Number(Boolean(b.hasParams)) - Number(Boolean(a.hasParams)) ||
    String(a.url).localeCompare(String(b.url));

  const parametrizadas = candidatos.filter(endpoint => endpoint.hasParams).sort(ordenar).slice(0, maxParamUrls);
  const usadas = new Set(parametrizadas.map(endpoint => endpoint.url));
  const superficie = candidatos
    .filter(endpoint => !endpoint.hasParams && !usadas.has(endpoint.url))
    .filter(endpoint => (endpoint.score || 0) > 0 || endpoint.category !== 'historico')
    .sort(ordenar)
    .slice(0, maxSurfaceUrls);

  superficie.forEach(endpoint => usadas.add(endpoint.url));

  const relleno = candidatos
    .filter(endpoint => !usadas.has(endpoint.url))
    .sort(ordenar)
    .slice(0, Math.max(0, maxTotal - usadas.size));

  const seleccionadas = [...parametrizadas, ...superficie, ...relleno]
    .sort(ordenar)
    .slice(0, maxTotal);

  stats.seleccionadas_final = seleccionadas.length;
  stats.enviadas_gf = seleccionadas.length;

  return {
    selected: seleccionadas,
    filtered: candidatos.sort(ordenar),
    discardedStats: stats,
    limits: {
      max_param_urls: maxParamUrls,
      max_surface_urls: maxSurfaceUrls,
      max_total_after_filter: maxTotal,
      max_per_pattern: maxPorPatron,
      filter_external: filtrarExternas
    }
  };
}

async function ejecutarGau(dominio, opciones = {}) {
  const timeoutMs = Number(opciones.timeoutMs || (Number(process.env.TOOL_TIMEOUT_SECONDS || 120) * 1000));

  try {
    console.log(`[gau] dominio analizado: ${dominio}`);
    const raw = await ejecutar('gau', [dominio], timeoutMs);
    const rawUrls = deduplicar(parsearLineas(raw));
    const resultadoFiltro = filtrarYPriorizarUrlsGau(rawUrls, dominio, opciones);
    const endpoints = resultadoFiltro.selected;
    const top20 = endpoints.slice(0, 20).map(endpoint => ({
      url: endpoint.url,
      score: endpoint.score,
      reasons: endpoint.scoreReasons
    }));

    console.log(`[gau] raw URLs: ${rawUrls.length}`);
    console.log(`[gau] URLs validas: ${resultadoFiltro.discardedStats.urls_validas}`);
    console.log(`[gau] seleccionadas tras filtrado inteligente: ${endpoints.length}`);
    console.log(`[gau] URLs con parametros: ${resultadoFiltro.discardedStats.con_parametros}`);
    console.log('[gau] top seleccionadas:', top20);

    return {
      status: 'success',
      raw,
      parsed: endpoints,
      findings: [],
      metrics: {
        endpoints_encontrados: endpoints.length,
        raw_urls: rawUrls.length,
        urls_validas: resultadoFiltro.discardedStats.urls_validas,
        urls_externas_descartadas: resultadoFiltro.discardedStats.urls_externas_descartadas,
        assets_descartados: resultadoFiltro.discardedStats.assets_descartados,
        trackers_descartados: resultadoFiltro.discardedStats.trackers_descartados,
        duplicados_descartados: resultadoFiltro.discardedStats.duplicados_descartados,
        patrones_deduplicados: resultadoFiltro.discardedStats.patrones_deduplicados,
        con_parametros: resultadoFiltro.discardedStats.con_parametros,
        seleccionadas_final: endpoints.length,
        enviadas_gf: endpoints.length,
        enviados_ia: 0,
        enviadas_ia: 0,
        raw_length: raw.length,
        limits: resultadoFiltro.limits,
        top_selected: top20
      },
      debug: {
        filtered_count: resultadoFiltro.filtered.length,
        discardedStats: resultadoFiltro.discardedStats,
        selected: top20
      }
    };
  } catch (error) {
    const timeout = error.message.toLowerCase().includes('timed out') || error.message.toLowerCase().includes('timeout');
    const noInstalada = pareceNoInstalada(error);
    console.log(`[gau] error controlado: ${error.message}`);

    return {
      status: noInstalada ? 'skipped' : timeout ? 'timeout' : 'skipped',
      raw: '',
      parsed: [],
      findings: [],
      error: noInstalada ? 'gau no esta instalado' : timeout ? 'gau excedio el tiempo limite' : error.message,
      metrics: {
        endpoints_encontrados: 0,
        raw_urls: 0,
        urls_validas: 0,
        urls_externas_descartadas: 0,
        assets_descartados: 0,
        duplicados_descartados: 0,
        patrones_deduplicados: 0,
        con_parametros: 0,
        seleccionadas_final: 0,
        enviadas_gf: 0,
        enviados_ia: 0,
        enviadas_ia: 0,
        raw_length: 0
      }
    };
  }
}

module.exports = {
  ejecutarGau,
  normalizarEndpoint,
  filtrarYPriorizarUrlsGau,
  puntuarUrl,
  perteneceAlTarget,
  clavePatron
};
