const { exec } = require('child_process');
const { esAssetEstatico } = require('./clasificadorFindings');

function ejecutar(comando, timeoutMs) {
  return new Promise((resolve, reject) => {
    exec(comando, { timeout: timeoutMs, maxBuffer: 1024 * 1024 * 20 }, (error, stdout, stderr) => {
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

function normalizarEndpoint(url, source = 'gau') {
  let parsed = null;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }

  const params = Array.from(parsed.searchParams.keys());

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
    category: categorizar(parsed.href),
    categoria: categorizar(parsed.href),
    contentType: null,
    status: null
  };
}

async function ejecutarGau(dominio, opciones = {}) {
  const maxUrls = Number(opciones.maxUrls || process.env.MAX_GAU_URLS || 500);
  const timeoutMs = Number(opciones.timeoutMs || (Number(process.env.TOOL_TIMEOUT_SECONDS || 120) * 1000));
  const comando = `gau ${dominio}`;

  try {
    console.log(`[gau] comando ejecutado: ${comando}`);
    const raw = await ejecutar(comando, timeoutMs);
    const urls = deduplicar(parsearLineas(raw))
      .filter(url => /^https?:\/\//i.test(url))
      .filter(url => !esAssetEstatico(url))
      .slice(0, maxUrls);
    const endpoints = urls.map(url => normalizarEndpoint(url)).filter(Boolean);

    console.log(`[gau] URLs encontradas: ${endpoints.length}`);
    console.log(`[gau] URLs con parametros: ${endpoints.filter(endpoint => endpoint.hasParams).length}`);
    console.log('[gau] enviadas IA: 0');

    return {
      status: 'success',
      raw,
      parsed: endpoints,
      findings: [],
      metrics: {
        endpoints_encontrados: endpoints.length,
        con_parametros: endpoints.filter(endpoint => endpoint.hasParams).length,
        enviados_ia: 0,
        raw_length: raw.length
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
        con_parametros: 0,
        enviados_ia: 0,
        raw_length: 0
      }
    };
  }
}

module.exports = {
  ejecutarGau,
  normalizarEndpoint
};
