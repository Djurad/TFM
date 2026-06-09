const fs = require('fs');
const { execFile } = require('child_process');
const { esAssetEstatico } = require('../procesamiento/clasificadorFindings');
const { normalizarEndpoint } = require('./gau');

const WORDLISTS_CANDIDATAS = [
  '/usr/share/seclists/Discovery/Web-Content/common.txt',
  '/usr/share/wordlists/dirb/common.txt',
  '/usr/share/dirb/wordlists/common.txt'
];

const EXTENSIONES_SENSIBLES = /\.(bak|old|backup|zip|tar|gz|tgz|sql|env|conf|ini)(\?|$)/i;

function ejecutar(binario, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    execFile(binario, args, { timeout: timeoutMs, maxBuffer: 1024 * 1024 * 20 }, (error, stdout, stderr) => {
      if (error) {
        if (stdout && stdout.trim()) return resolve(stdout);
        reject(new Error([stderr, error.message].filter(Boolean).join('\n') || 'feroxbuster fallo.'));
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

function pareceTimeout(error) {
  const msg = String(error?.message || '').toLowerCase();
  return msg.includes('timed out') || msg.includes('timeout');
}

function existeArchivo(path) {
  try {
    return Boolean(path) && fs.existsSync(path) && fs.statSync(path).isFile();
  } catch {
    return false;
  }
}

function resolverWordlist() {
  if (process.env.FEROX_WORDLIST) {
    return {
      path: process.env.FEROX_WORDLIST,
      exists: existeArchivo(process.env.FEROX_WORDLIST),
      source: 'env'
    };
  }

  const encontrada = WORDLISTS_CANDIDATAS.find(existeArchivo);
  return {
    path: encontrada || null,
    exists: Boolean(encontrada),
    source: encontrada ? 'auto' : 'none'
  };
}

function parsearJsonLines(raw = '') {
  const lineas = String(raw)
    .split('\n')
    .map(linea => linea.trim())
    .filter(Boolean);

  const items = [];
  let noJson = 0;

  lineas.forEach(linea => {
    try {
      items.push(JSON.parse(linea));
    } catch {
      noJson += 1;
    }
  });

  return { lineas, items, noJson };
}

function extraerUrl(item) {
  return item.url ||
    item.target ||
    item.location ||
    item.request?.url ||
    item.response?.url ||
    null;
}

function extraerStatus(item = {}) {
  const status = item.status ||
    item.status_code ||
    item.statusCode ||
    item.response?.status ||
    item.response?.status_code ||
    null;
  const numeric = Number(status);
  return Number.isFinite(numeric) ? numeric : null;
}

function statusConContenido(status) {
  return status >= 200 && status < 300;
}

function esRutaInteresante(url = '') {
  const lower = String(url).toLowerCase();
  return lower.includes('/.env') ||
    lower.includes('/.git') ||
    /\/admin(\/|$|\?)/i.test(lower) ||
    /(^|[/?&=])admin([/?&=]|$)/i.test(lower) ||
    [
      '/backup',
      '/backup.zip',
      '/db.sql',
      '/dump.sql',
      '/config',
      '/config.php',
      '/phpinfo.php',
      '/server-status',
      '/actuator',
      '/debug',
      '/uploads',
      'login',
      'upload',
      'phpmyadmin',
      'swagger',
      'openapi',
      'api-docs'
    ].some(token => lower.includes(token)) ||
    EXTENSIONES_SENSIBLES.test(lower);
}

function esPosibleVulnerabilidad(url = '', status = null) {
  if (!statusConContenido(Number(status))) return false;
  const lower = String(url).toLowerCase();
  return lower.includes('/.env') ||
    lower.includes('/.git') ||
    lower.includes('/backup') ||
    lower.includes('/backup.zip') ||
    lower.includes('/db.sql') ||
    lower.includes('/dump.sql') ||
    lower.includes('/config.php') ||
    lower.includes('/phpinfo.php') ||
    EXTENSIONES_SENSIBLES.test(lower);
}

function endpointDesdeFerox(item, stats) {
  const url = extraerUrl(item);
  if (!url) {
    stats.descartados_sin_url += 1;
    return null;
  }

  if (esAssetEstatico(url)) {
    stats.descartados_assets += 1;
    return null;
  }

  const status = extraerStatus(item);
  if (status && status >= 400 && status !== 403) {
    stats.descartados_status += 1;
    return null;
  }

  const endpoint = normalizarEndpoint(url, 'feroxbuster');
  if (!endpoint) {
    stats.descartados_sin_url += 1;
    return null;
  }

  endpoint.status = status;
  endpoint.contentLength = item.content_length || item.contentLength || item.response?.content_length || null;
  endpoint.category = esRutaInteresante(url) ? 'suspicious' : endpoint.category;
  endpoint.categoria = endpoint.category;
  endpoint.possibleExposure = esPosibleVulnerabilidad(url, status);
  return endpoint;
}

function procesarFeroxRaw(raw = '') {
  const parsed = parsearJsonLines(raw);
  const stats = {
    raw_lineas: parsed.lineas.length,
    lineas_no_json: parsed.noJson,
    parseados_json: parsed.items.length,
    descartados_assets: 0,
    descartados_status: 0,
    descartados_sin_url: 0
  };
  const endpoints = parsed.items
    .map(item => endpointDesdeFerox(item, stats))
    .filter(Boolean);

  return { endpoints, stats };
}

function crearArgs(activo, config) {
  const args = [
    '-u', activo,
    '--depth', String(config.depth),
    '--silent',
    '--json',
    '--time-limit', `${config.timeLimitSeconds}s`,
    '--threads', String(config.threads),
    '-k'
  ];

  if (config.wordlist?.exists) args.push('-w', config.wordlist.path);
  return args;
}

async function ejecutarFeroxbuster(activos = [], opciones = {}) {
  const maxUrls = Number(opciones.maxUrls || process.env.MAX_FEROX_URLS || 100);
  const maxTargets = Number(opciones.maxTargets || process.env.MAX_FEROX_TARGETS || 5);
  const timeoutMs = Number(opciones.timeoutMs || (Number(process.env.TOOL_TIMEOUT_SECONDS || 120) * 1000));
  const config = {
    binario: 'feroxbuster',
    depth: Number(process.env.FEROX_DEPTH || opciones.depth || 1),
    timeLimitSeconds: Number(process.env.FEROX_TIME_LIMIT_SECONDS || opciones.timeLimitSeconds || 60),
    threads: Number(process.env.FEROX_THREADS || opciones.threads || 10),
    wordlist: resolverWordlist()
  };
  const targets = activos.slice(0, maxTargets);
  const endpoints = [];
  const rawParts = [];
  const runs = [];
  const statsTotales = {
    raw_lineas: 0,
    lineas_no_json: 0,
    parseados_json: 0,
    descartados_assets: 0,
    descartados_status: 0,
    descartados_sin_url: 0
  };
  let herramientaNoInstalada = false;
  let ultimoError = null;
  let intentos = 0;

  console.log('[feroxbuster] binario:', config.binario);
  console.log('[feroxbuster] wordlist:', config.wordlist);
  console.log('[feroxbuster] activos enviados:', targets);

  for (const activo of targets) {
    if (endpoints.length >= maxUrls) break;
    intentos += 1;

    try {
      const args = crearArgs(activo, config);
      console.log('[feroxbuster] args:', args);
      const raw = await ejecutar(config.binario, args, timeoutMs);
      rawParts.push(raw);

      const procesado = procesarFeroxRaw(raw);
      Object.keys(statsTotales).forEach(key => {
        statsTotales[key] += procesado.stats[key] || 0;
      });

      runs.push({
        target: activo,
        args,
        raw_length: raw.length,
        raw_lineas: procesado.stats.raw_lineas,
        parseados: procesado.stats.parseados_json,
        descartados_assets: procesado.stats.descartados_assets,
        descartados_status: procesado.stats.descartados_status
      });

      procesado.endpoints.forEach(endpoint => {
        if (endpoints.length < maxUrls) endpoints.push(endpoint);
      });
    } catch (error) {
      ultimoError = error;
      if (pareceNoInstalada(error)) {
        herramientaNoInstalada = true;
        break;
      }
    }
  }

  if (herramientaNoInstalada) {
    return {
      status: 'skipped',
      raw: '',
      parsed: [],
      findings: [],
      error: 'feroxbuster no esta instalado',
      warning: 'No se pudo ejecutar feroxbuster; revisa PATH/permisos.',
      metrics: {
        endpoints_encontrados: 0,
        rutas_interesantes: 0,
        posibles_vulnerabilidades: 0,
        intentos,
        activos_enviados: targets.length,
        ...statsTotales,
        wordlist: config.wordlist
      }
    };
  }

  if (!endpoints.length && ultimoError && rawParts.length === 0) {
    const timeout = pareceTimeout(ultimoError);
    const mensaje = timeout
      ? 'feroxbuster excedio el tiempo limite'
      : ultimoError.message;

    console.log(`[feroxbuster] error controlado: ${mensaje}`);

    return {
      status: timeout ? 'timeout' : 'error',
      raw: '',
      parsed: [],
      findings: [],
      error: mensaje,
      metrics: {
        endpoints_encontrados: 0,
        rutas_interesantes: 0,
        posibles_vulnerabilidades: 0,
        intentos,
        activos_enviados: targets.length,
        ...statsTotales,
        wordlist: config.wordlist,
        runs
      }
    };
  }

  const dedup = Array.from(new Map(endpoints.map(endpoint => [endpoint.url, endpoint])).values());
  const limitados = dedup.slice(0, maxUrls);
  const posibles = limitados.filter(endpoint => esPosibleVulnerabilidad(endpoint.url, endpoint.status));
  const interesantes = limitados.filter(endpoint => esRutaInteresante(endpoint.url));
  const warningWordlist = config.wordlist.exists
    ? null
    : 'Feroxbuster se ejecuto sin wordlist externa detectable; los resultados pueden ser limitados.';
  const warningSinRutas = limitados.length === 0
    ? 'Feroxbuster no descubrio rutas adicionales con la configuracion y wordlist utilizadas.'
    : null;

  console.log(`[feroxbuster] raw lineas: ${statsTotales.raw_lineas}`);
  console.log(`[feroxbuster] parseados JSON: ${statsTotales.parseados_json}`);
  console.log(`[feroxbuster] descartados por asset estatico: ${statsTotales.descartados_assets}`);
  console.log(`[feroxbuster] descartados por status: ${statsTotales.descartados_status}`);
  console.log(`[feroxbuster] rutas encontradas: ${limitados.length}`);
  console.log(`[feroxbuster] rutas interesantes: ${interesantes.length}`);
  console.log(`[feroxbuster] posibles vulnerabilidades: ${posibles.length}`);

  return {
    status: 'success',
    raw: rawParts.join('\n'),
    parsed: limitados,
    findings: [],
    error: null,
    warning: [warningWordlist, warningSinRutas].filter(Boolean).join(' ') || null,
    metrics: {
      endpoints_encontrados: limitados.length,
      rutas_interesantes: interesantes.length,
      posibles_vulnerabilidades: posibles.length,
      intentos,
      activos_enviados: targets.length,
      duplicados_descartados: Math.max(0, endpoints.length - dedup.length),
      ...statsTotales,
      wordlist: config.wordlist,
      depth: config.depth,
      time_limit_seconds: config.timeLimitSeconds,
      threads: config.threads,
      runs
    }
  };
}

module.exports = {
  ejecutarFeroxbuster,
  esRutaInteresante,
  esPosibleVulnerabilidad,
  parsearJsonLines,
  procesarFeroxRaw,
  resolverWordlist
};
