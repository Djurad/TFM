const { exec } = require('child_process');
const { esAssetEstatico } = require('./clasificadorFindings');
const { normalizarEndpoint } = require('./gau');

function ejecutar(comando, timeoutMs) {
  return new Promise((resolve, reject) => {
    exec(comando, { timeout: timeoutMs, maxBuffer: 1024 * 1024 * 20 }, (error, stdout, stderr) => {
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

function parsearJsonLines(raw = '') {
  return String(raw)
    .split('\n')
    .map(linea => linea.trim())
    .filter(Boolean)
    .map(linea => {
      try {
        return JSON.parse(linea);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

function extraerUrl(item) {
  return item.url ||
    item.target ||
    item.location ||
    item.request?.url ||
    item.response?.url ||
    null;
}

function esRutaInteresante(url = '') {
  const lower = String(url).toLowerCase();
  return /\/admin(\/|$|\?)/i.test(lower) ||
    /(^|[/?&=])admin([/?&=]|$)/i.test(lower) ||
    ['login', 'upload', 'backup', 'config', 'debug', 'actuator', 'phpmyadmin', '.git', '.env']
      .some(token => lower.includes(token));
}

function esPosibleVulnerabilidad(url = '') {
  const lower = String(url).toLowerCase();
  return lower.includes('/.env') ||
    lower.includes('/.git') ||
    lower.includes('backup.zip') ||
    lower.includes('config.php') ||
    lower.includes('database.sql') ||
    lower.includes('dump.sql') ||
    /\.(zip|tar|tgz|tar\.gz|7z|rar|bak|backup|sql)(\?|$)/i.test(lower);
}

function endpointDesdeFerox(item) {
  const url = extraerUrl(item);
  if (!url || esAssetEstatico(url)) return null;

  const endpoint = normalizarEndpoint(url, 'feroxbuster');
  if (!endpoint) return null;

  endpoint.status = item.status || item.status_code || item.response?.status || null;
  endpoint.contentLength = item.content_length || item.contentLength || item.response?.content_length || null;
  endpoint.category = esRutaInteresante(url) ? 'suspicious' : endpoint.category;
  endpoint.categoria = endpoint.category;
  return endpoint;
}

async function ejecutarFeroxbuster(activos = [], opciones = {}) {
  const maxUrls = Number(opciones.maxUrls || process.env.MAX_FEROX_URLS || 100);
  const timeoutMs = Number(opciones.timeoutMs || (Number(process.env.TOOL_TIMEOUT_SECONDS || 120) * 1000));
  const endpoints = [];
  const rawParts = [];
  let herramientaNoInstalada = false;
  let ultimoError = null;
  let intentos = 0;

  for (const activo of activos.slice(0, 5)) {
    if (endpoints.length >= maxUrls) break;
    intentos += 1;

    try {
      const wordlist = process.env.FEROX_WORDLIST ? ` -w "${process.env.FEROX_WORDLIST}"` : '';
      const raw = await ejecutar(`feroxbuster -u "${activo}" --depth 1 --silent --json --time-limit 60s --threads 20 -k${wordlist}`, timeoutMs);
      rawParts.push(raw);
      parsearJsonLines(raw)
        .map(endpointDesdeFerox)
        .filter(Boolean)
        .forEach(endpoint => {
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
      metrics: { endpoints_encontrados: 0, rutas_interesantes: 0, posibles_vulnerabilidades: 0, intentos }
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
        intentos
      }
    };
  }

  const dedup = Array.from(new Map(endpoints.map(endpoint => [endpoint.url, endpoint])).values());
  const limitados = dedup.slice(0, maxUrls);
  const posibles = limitados.filter(endpoint => esPosibleVulnerabilidad(endpoint.url));
  const interesantes = limitados.filter(endpoint => esRutaInteresante(endpoint.url));

  console.log(`[feroxbuster] rutas encontradas: ${limitados.length}`);
  console.log(`[feroxbuster] rutas sensibles: ${interesantes.length}`);
  console.log(`[feroxbuster] posibles vulnerabilidades: ${posibles.length}`);

  return {
    status: 'success',
    raw: rawParts.join('\n'),
    parsed: limitados,
    findings: [],
    error: null,
    metrics: {
      endpoints_encontrados: limitados.length,
      rutas_interesantes: interesantes.length,
      posibles_vulnerabilidades: posibles.length,
      intentos
    }
  };
}

module.exports = {
  ejecutarFeroxbuster,
  esRutaInteresante,
  esPosibleVulnerabilidad
};
