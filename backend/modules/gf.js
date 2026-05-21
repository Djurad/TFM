const { exec } = require('child_process');

const PATRONES = {
  xss: 'xssCandidates',
  sqli: 'sqliCandidates',
  ssrf: 'ssrfCandidates',
  redirect: 'redirectCandidates',
  lfi: 'lfiCandidates',
  rce: 'rceCandidates'
};

const PRIORIDAD_PARAMS = [
  'id',
  'user',
  'account',
  'product',
  'item',
  'cat',
  'page',
  'search',
  'query',
  'q',
  'file',
  'url',
  'redirect',
  'return',
  'next',
  'lang',
  'step'
];

function ejecutar(comando, input, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = exec(comando, { timeout: timeoutMs, maxBuffer: 1024 * 1024 * 10 }, (error, stdout, stderr) => {
      if (error) {
        const salida = [stderr, error.message].filter(Boolean).join('\n');
        reject(new Error(salida || 'gf fallo.'));
        return;
      }
      resolve(stdout || '');
    });
    child.stdin.write(input);
    child.stdin.end();
  });
}

function pareceNoInstalada(error) {
  const msg = String(error?.message || '').toLowerCase();
  return msg.includes('not found') ||
    msg.includes('not recognized') ||
    msg.includes('no se reconoce') ||
    msg.includes('enoent');
}

function parametros(url) {
  try {
    return Array.from(new URL(url).searchParams.keys());
  } catch {
    return [];
  }
}

function claveUrl(url) {
  try {
    const parsed = new URL(url);
    const params = Array.from(parsed.searchParams.keys()).sort().join('&');
    return `${parsed.origin}${parsed.pathname}?${params}`;
  } catch {
    return url;
  }
}

function deduplicarPorPatron(urls = []) {
  const mapa = new Map();
  urls.forEach(url => {
    const key = claveUrl(url);
    if (!mapa.has(key)) mapa.set(key, url);
  });
  return Array.from(mapa.values());
}

function ordenarPorPrioridad(urls = []) {
  return urls.slice().sort((a, b) => {
    const score = url => parametros(url).some(param => PRIORIDAD_PARAMS.includes(param.toLowerCase())) ? 0 : 1;
    return score(a) - score(b);
  });
}

function parsearLineas(texto = '') {
  return String(texto)
    .split('\n')
    .map(linea => linea.trim())
    .filter(Boolean);
}

function metricasVacias(raw = '') {
  return {
    xss: 0,
    sqli: 0,
    ssrf: 0,
    redirect: 0,
    lfi: 0,
    rce: 0,
    producidos: 0,
    enviados_ia: 0,
    no_enviados_ia: 0,
    raw_length: raw.length
  };
}

function construirMetricas(buckets, raw = '') {
  const todos = Object.values(PATRONES)
    .flatMap(nombre => buckets[nombre] || []);
  const totalUnicos = new Set(todos).size;

  return {
    xss: buckets.xssCandidates.length,
    sqli: buckets.sqliCandidates.length,
    ssrf: buckets.ssrfCandidates.length,
    redirect: buckets.redirectCandidates.length,
    lfi: buckets.lfiCandidates.length,
    rce: buckets.rceCandidates.length,
    xssCandidates: buckets.xssCandidates.length,
    sqliCandidates: buckets.sqliCandidates.length,
    ssrfCandidates: buckets.ssrfCandidates.length,
    redirectCandidates: buckets.redirectCandidates.length,
    lfiCandidates: buckets.lfiCandidates.length,
    rceCandidates: buckets.rceCandidates.length,
    producidos: totalUnicos,
    enviados_ia: 0,
    no_enviados_ia: totalUnicos,
    raw_length: JSON.stringify(buckets).length || raw.length
  };
}

async function ejecutarGf(endpoints = [], opciones = {}) {
  const timeoutMs = Number(opciones.timeoutMs || (Number(process.env.TOOL_TIMEOUT_SECONDS || 120) * 1000));
  const urls = deduplicarPorPatron(
    endpoints
      .map(endpoint => typeof endpoint === 'string' ? endpoint : endpoint.url)
      .filter(Boolean)
      .filter(url => parametros(url).length > 0)
  );
  const input = urls.join('\n');
  const buckets = Object.fromEntries(Object.values(PATRONES).map(nombre => [nombre, []]));

  if (!urls.length) {
    return {
      status: 'skipped',
      raw: '',
      parsed: buckets,
      findings: [],
      error: 'gf no se ejecuto porque no hay endpoints parametrizados',
      metrics: metricasVacias()
    };
  }

  let raw = '';
  let herramientaNoInstalada = false;

  for (const [pattern, bucket] of Object.entries(PATRONES)) {
    try {
      const output = await ejecutar(`gf ${pattern}`, input, timeoutMs);
      raw += `\n# gf ${pattern}\n${output}`;
      buckets[bucket] = ordenarPorPrioridad(deduplicarPorPatron(parsearLineas(output)));
    } catch (error) {
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
      parsed: buckets,
      findings: [],
      error: 'gf no esta instalado',
      metrics: metricasVacias()
    };
  }

  console.log(`[gf] candidatos xss: ${buckets.xssCandidates.length}`);
  console.log(`[gf] candidatos sqli: ${buckets.sqliCandidates.length}`);
  console.log(`[gf] candidatos ssrf: ${buckets.ssrfCandidates.length}`);
  console.log(`[gf] candidatos redirect: ${buckets.redirectCandidates.length}`);
  console.log(`[gf] candidatos lfi: ${buckets.lfiCandidates.length}`);
  console.log(`[gf] candidatos rce: ${buckets.rceCandidates.length}`);

  return {
    status: 'success',
    raw,
    parsed: buckets,
    findings: [],
    metrics: construirMetricas(buckets, raw)
  };
}

module.exports = {
  ejecutarGf,
  deduplicarPorPatron,
  ordenarPorPrioridad,
  PRIORIDAD_PARAMS
};
