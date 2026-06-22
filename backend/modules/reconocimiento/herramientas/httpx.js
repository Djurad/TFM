const { spawn } = require('child_process');

function ejecutarConInput(binario, args = [], input = '', opciones = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(binario, args, {
      shell: false,
      cwd: opciones.cwd || process.cwd()
    });

    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timeoutMsProceso = Number(opciones.timeout === undefined ? 180000 : opciones.timeout);
    const timeout = timeoutMsProceso > 0
      ? setTimeout(() => {
          timedOut = true;
          child.kill('SIGTERM');
        }, timeoutMsProceso)
      : null;

    child.stdout.on('data', data => {
      stdout += data.toString();
      if (stdout.length > (opciones.maxBuffer || 1024 * 1024 * 20)) child.kill('SIGTERM');
    });
    child.stderr.on('data', data => {
      stderr += data.toString();
    });
    child.on('error', error => {
      if (timeout) clearTimeout(timeout);
      reject(error);
    });
    child.on('close', code => {
      if (timeout) clearTimeout(timeout);
      if (timedOut) return reject(new Error(`${binario} excedio el tiempo limite.`));
      if (code !== 0 && !(opciones.permitirFalloSinSalida && !stdout.trim())) {
        if (stdout && stdout.trim()) return resolve(stdout);
        return reject(new Error([stderr.trim(), `${binario} finalizo con codigo ${code}`].filter(Boolean).join('\n')));
      }
      resolve(stdout);
    });

    child.stdin.write(input || '');
    child.stdin.end();
  });
}

function limpiarColoresANSI(texto = '') {
  return String(texto).replace(/\x1B\[[0-9;]*m/g, '');
}

function limpiarTarget(target) {
  return String(target || '')
    .replace(/^https?:\/\//, '')
    .split('/')[0]
    .replace(/\/$/, '')
    .trim();
}

function parsearLineas(texto = '') {
  return limpiarColoresANSI(texto)
    .split('\n')
    .map(linea => linea.trim())
    .filter(Boolean);
}

function deduplicarUrls(urls) {
  return Array.from(new Set((urls || []).filter(Boolean).map(url => String(url).trim()).filter(Boolean)));
}

function parsearHttpxJson(output) {
  return parsearLineas(output)
    .map(linea => {
      try {
        const item = JSON.parse(linea);

        return {
          url: item.url || item.input || null,
          finalUrl: item.final_url || item.url || item.location || null,
          input: item.input || null,
          statusCode: item.status_code || null,
          title: item.title || null,
          tecnologias: item.tech || [],
          webserver: item.webserver || null,
          contentLength: item.content_length || null,
          contentType: item.content_type || item.header?.['content-type'] || null,
          location: item.location || null
        };
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

function normalizarInputHttpxItem(valor = '', preferirUrl = false) {
  const raw = String(valor || '').trim();
  if (!raw) return null;

  if (/^https?:\/\//i.test(raw)) {
    try {
      const parsed = new URL(raw);
      parsed.hash = '';
      const base = `${parsed.protocol}//${parsed.host}`;
      const input = (parsed.pathname && parsed.pathname !== '/') || parsed.search
        ? `${parsed.origin}${parsed.pathname}${parsed.search}`.replace(/\/$/, '')
        : base;
      return {
        input,
        key: `${parsed.hostname.toLowerCase()}:${parsed.port || ''}`,
        preferirUrl
      };
    } catch {
      return null;
    }
  }

  const limpio = limpiarTarget(raw);
  if (!limpio) return null;

  try {
    const parsed = new URL(`http://${limpio}`);
    return {
      input: limpio,
      key: `${parsed.hostname.toLowerCase()}:${parsed.port || ''}`,
      preferirUrl
    };
  } catch {
    return {
      input: limpio,
      key: limpio.toLowerCase(),
      preferirUrl
    };
  }
}

function construirInputHttpx(entrada = {}, subdominios = []) {
  const originalConProtocolo = /^https?:\/\//i.test(String(entrada.original || ''));
  const candidatos = [
    entrada.original,
    entrada.inputUrl,
    entrada.baseUrl,
    ...(subdominios || [])
  ];
  const porHost = new Map();

  candidatos.forEach(valor => {
    const item = normalizarInputHttpxItem(valor, originalConProtocolo);
    if (!item) return;
    const existente = porHost.get(item.key);
    if (!existente || (item.preferirUrl && !existente.preferirUrl)) {
      porHost.set(item.key, item);
    }
  });

  return Array.from(porHost.values()).map(item => item.input);
}

function normalizarClaveHttpx(item = {}) {
  const candidate = item.finalUrl || item.final_url || item.url || item.input || '';
  try {
    const parsed = new URL(candidate);
    parsed.hash = '';
    return `${parsed.protocol}//${parsed.host}${parsed.pathname.replace(/\/$/, '') || '/'}${parsed.search}`.toLowerCase();
  } catch {
    return String(candidate || '').trim().replace(/\/$/, '').toLowerCase();
  }
}

function deduplicarHttpxResultados(resultados = []) {
  const mapa = new Map();
  const duplicados = [];

  resultados.filter(Boolean).forEach(item => {
    const key = normalizarClaveHttpx(item);
    if (!key) return;
    if (!mapa.has(key)) {
      mapa.set(key, {
        ...item,
        inputs: [item.input || item.url].filter(Boolean)
      });
      return;
    }

    const existente = mapa.get(key);
    existente.inputs = deduplicarUrls([...(existente.inputs || []), item.input || item.url]);
    existente.duplicateInputs = deduplicarUrls([...(existente.duplicateInputs || []), item.input || item.url]);
    duplicados.push(item);
  });

  return {
    unique: Array.from(mapa.values()),
    duplicates: duplicados,
    metrics: {
      respuestas_httpx: resultados.length,
      activos_vivos: mapa.size,
      duplicados_httpx: duplicados.length
    }
  };
}

async function ejecutarHttpx(entrada = {}, subdominios = [], opciones = {}) {
  const timeoutMs = Number(opciones.timeoutMs || 180000);
  const logVar = typeof opciones.logVar === 'function' ? opciones.logVar : () => {};
  const registrarPaso = typeof opciones.registrarPaso === 'function' ? opciones.registrarPaso : () => {};
  const progreso = typeof opciones.progreso === 'function' ? opciones.progreso : () => {};
  const target = opciones.target || '';
  const inputHttpxItems = construirInputHttpx(entrada, subdominios);
  const inputHttpx = inputHttpxItems.join('\n');
  const args = ['-silent', '-json', '-title', '-status-code', '-tech-detect', '-web-server', '-content-length', '-content-type', '-location', '-follow-redirects', '-no-color'];

  logVar('inputHttpxItems', inputHttpxItems);
  logVar('inputHttpx', inputHttpx);
  registrarPaso('httpx', 'entradas normalizadas', {
    entradas: inputHttpxItems.length,
    originales: deduplicarUrls([...subdominios, entrada.inputUrl, entrada.baseUrl]).length
  });

  let result;
  let httpxOutput = '';
  let httpxRespuestas = [];
  let httpxDedup = deduplicarHttpxResultados([]);
  let httpx = [];

  try {
    progreso('httpx', 'running', 'Ejecutando httpx');
    registrarPaso('httpx', 'ejecutando herramienta', { entrada: target, binario: 'httpx', args });
    logVar('httpx.binario', 'httpx');
    logVar('httpx.args', args);
    logVar('httpx.input', inputHttpx);
    httpxOutput = await ejecutarConInput('httpx', args, inputHttpx, { timeout: timeoutMs });
    httpxRespuestas = parsearHttpxJson(httpxOutput);
    httpxDedup = deduplicarHttpxResultados(httpxRespuestas);
    httpx = httpxDedup.unique;
    result = {
      status: 'success',
      raw: httpxOutput,
      parsed: httpxRespuestas,
      parsed_count: httpxRespuestas.length,
      findings: []
    };
    logVar('httpx.raw', httpxOutput);
    logVar('httpx.parsed', httpxRespuestas);
    progreso('httpx', 'done', 'httpx finalizado', { count: httpxRespuestas.length });
  } catch (error) {
    result = {
      status: 'error',
      raw: '',
      parsed: [],
      parsed_count: 0,
      findings: [],
      error: error.message
    };
    logVar('toolResults.httpx', result);
    progreso('httpx', 'error', error.message);
    console.error('Error en httpx:', error.message);
  }

  const httpxFallbackUrls = httpx.length === 0
    ? deduplicarUrls([entrada.baseUrl, entrada.inputUrl].filter(url => /^https?:\/\//i.test(String(url || ''))))
    : [];

  if (httpxFallbackUrls.length > 0) {
    httpx = httpxFallbackUrls.map(url => ({
      url,
      finalUrl: url,
      input: url,
      statusCode: null,
      title: null,
      tecnologias: [],
      webserver: null,
      contentLength: null,
      contentType: null,
      location: null,
      fallback: true
    }));

    result.status = 'partial';
    result.warning = 'httpx no devolvio activos; se usa la URL normalizada como fallback para continuar validaciones HTTP.';
    result.parsed = httpx;
    result.parsed_count = httpx.length;
    result.metrics = {
      ...(result.metrics || {}),
      respuestas_httpx: 0,
      activos_vivos: httpx.length,
      duplicados_httpx: 0,
      entradas_httpx: inputHttpxItems.length,
      fallback: true
    };
    logVar('httpxFallbackUrls', httpxFallbackUrls);
  } else {
    result.parsed = httpx;
    result.parsed_count = httpx.length;
    result.metrics = {
      ...(result.metrics || {}),
      entradas_httpx: inputHttpxItems.length,
      ...httpxDedup.metrics
    };
  }

  logVar('httpxOutput', httpxOutput);
  logVar('httpxRespuestas', httpxRespuestas);
  logVar('httpxDuplicados', httpxDedup.duplicates);
  logVar('httpx', httpx);
  logVar('toolResults.httpx', result);
  registrarPaso('httpx', 'deduplicacion completada', {
    entradas: inputHttpxItems.length,
    respuestas: httpxDedup.metrics.respuestas_httpx,
    activosUnicos: httpxDedup.metrics.activos_vivos,
    duplicados: httpxDedup.metrics.duplicados_httpx
  });

  return {
    result,
    httpx,
    httpxOutput,
    httpxRespuestas,
    httpxDedup,
    inputHttpx,
    inputHttpxItems
  };
}

module.exports = {
  construirInputHttpx,
  deduplicarHttpxResultados,
  ejecutarHttpx,
  parsearHttpxJson
};
