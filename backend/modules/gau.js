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
  'content',
  'template',
  'sec',
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

const EXTENSIONES_DINAMICAS = ['.php', '.jsp', '.jspx', '.asp', '.aspx', '.cfm', '.do', '.action'];
const TRACKERS = ['google-analytics.com', 'googletagmanager.com', 'doubleclick.net', 'facebook.com/tr', 'analytics'];

function ejecutar(binario, args, timeoutMs, input = null) {
  return new Promise(resolve => {
    const child = execFile(
      binario,
      args,
      { timeout: timeoutMs, maxBuffer: 1024 * 1024 * 20 },
      (error, stdout, stderr) => {
        const mensaje = String(error?.message || '');
        resolve({
          stdout: stdout || '',
          stderr: stderr || '',
          exitCode: error
            ? (Number.isInteger(error.code) ? error.code : null)
            : 0,
          timedOut: Boolean(error?.killed) ||
            mensaje.toLowerCase().includes('timed out') ||
            mensaje.toLowerCase().includes('timeout'),
          notInstalled: pareceNoInstalada(error),
          error: error ? mensaje || `${binario} fallo sin salida de error.` : null
        });
      }
    );

    if (input !== null && child.stdin) {
      child.stdin.on('error', () => {
        // El error de spawn se recoge en el callback de execFile.
      });
      child.stdin.end(input);
    }
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

function parsearLista(valor, fallback = []) {
  const items = String(valor || '')
    .split(',')
    .map(item => item.trim().toLowerCase())
    .filter(Boolean);
  return deduplicar(items.length > 0 ? items : fallback);
}

function envHabilitada(nombre, fallback = true) {
  const valor = process.env[nombre];
  if (valor === undefined || valor === '') return fallback;
  return String(valor).toLowerCase() === 'true';
}

function numeroPositivo(valor, fallback) {
  const numero = Number(valor);
  return Number.isFinite(numero) && numero > 0 ? numero : fallback;
}

function comandoLegible(binario, args = [], input = null) {
  const escapar = valor => {
    const texto = String(valor);
    return /^[a-z0-9._:/=-]+$/i.test(texto) ? texto : JSON.stringify(texto);
  };
  const comando = [binario, ...args].map(escapar).join(' ');
  return input === null ? comando : `echo ${escapar(String(input).trim())} | ${comando}`;
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
    source: extra.source || source,
    sourceTool: source,
    sourceProvider: extra.sourceProvider || null,
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

function decodificarSeguro(valor = '') {
  let resultado = String(valor || '');
  for (let intento = 0; intento < 2; intento += 1) {
    try {
      const decoded = decodeURIComponent(resultado);
      if (decoded === resultado) break;
      resultado = decoded;
    } catch {
      break;
    }
  }
  return resultado;
}

function motivoRuidoHistorico(parsed, rawUrl = '') {
  const raw = String(rawUrl || '');
  const decoded = decodificarSeguro(raw).toLowerCase();
  const pathname = decodificarSeguro(parsed.pathname);
  const valores = Array.from(parsed.searchParams.values()).map(decodificarSeguro);
  const contenido = [decoded, pathname, ...valores].join(' ').toLowerCase();

  if (
    contenido.includes('<script') ||
    contenido.includes('alert(') ||
    contenido.includes('javascript:') ||
    contenido.includes('onerror=') ||
    contenido.includes('onload=')
  ) {
    return 'payload_xss_historico';
  }

  if (contenido.includes('*~1*')) return 'ruta_fuzzing_8dot3';
  if (/(^|[\s/?=&])fuzz([\s/?=&]|$)/i.test(contenido)) return 'marcador_fuzzing';
  if (/[\u0000-\u001f<>`{}|\\]/.test(contenido)) return 'caracteres_atipicos';
  if (raw.length > 2048 || parsed.pathname.length > 768 || parsed.search.length > 1536) {
    return 'url_excesivamente_larga';
  }
  if (valores.some(valor => valor.length > 512 || /[a-z0-9+/=_-]{400,}/i.test(valor))) {
    return 'valor_codificado_excesivo';
  }

  const escapes = raw.match(/%[0-9a-f]{2}/gi) || [];
  if (raw.length > 200 && escapes.length * 3 > raw.length * 0.6) {
    return 'texto_codificado_atipico';
  }

  return null;
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
    ruido_historico_descartado: 0,
    ruido_historico_por_motivo: {},
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

    const motivoRuido = motivoRuidoHistorico(parsed, rawUrl);
    if (motivoRuido) {
      stats.ruido_historico_descartado += 1;
      stats.ruido_historico_por_motivo[motivoRuido] =
        (stats.ruido_historico_por_motivo[motivoRuido] || 0) + 1;
      return;
    }

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
    const endpoint = normalizarEndpoint(parsed.href, 'gau', {
      score,
      scoreReasons: reasons,
      source: opciones.source || 'gau'
    });
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
  const timeoutSeconds = numeroPositivo(
    opciones.timeoutSeconds || process.env.GAU_TIMEOUT_SECONDS,
    opciones.timeoutMs ? Math.max(1, Math.round(Number(opciones.timeoutMs) / 1000)) : 10
  );
  const timeoutMs = timeoutSeconds * 1000;
  const providersPrincipales = parsearLista(
    opciones.providers || process.env.GAU_PROVIDERS,
    ['otx']
  );
  const providerPrincipal = providersPrincipales[0] || 'otx';
  const providersFallback = parsearLista(
    opciones.fallbackProviders || process.env.GAU_FALLBACK_PROVIDERS,
    ['wayback', 'commoncrawl', 'urlscan']
  ).filter(provider => !providersPrincipales.includes(provider));
  const enableProviderFallback = opciones.enableProviderFallback === undefined
    ? envHabilitada('GAU_ENABLE_PROVIDER_FALLBACK', true)
    : Boolean(opciones.enableProviderFallback);
  const enableWaybackurlsFallback = opciones.enableWaybackurlsFallback === undefined
    ? envHabilitada('GAU_ENABLE_WAYBACKURLS_FALLBACK', true)
    : Boolean(opciones.enableWaybackurlsFallback);
  const ejecutarProceso = opciones.ejecutarProceso || ejecutar;
  const warnings = [];
  const providersProbados = [];
  const commandPorProvider = [];
  const stdoutLengthPorProvider = {};
  const stderrPorProvider = {};
  const exitCodePorProvider = {};
  const urlsPorProvider = {};
  let fallbackWaybackurlsUsado = false;
  let gauDisponible = true;
  let providerUsado = null;
  let source = 'none';
  let raw = '';
  let rawUrls = [];
  let gauRawUrls = 0;
  let fallbackRawUrls = 0;
  let huboIncidencia = false;

  const executionLog = {
    binario: 'gau',
    providersProbados,
    providerPrincipal,
    providerUsado: null,
    timeoutSeconds,
    commandPorProvider,
    stdoutLengthPorProvider,
    stderrPorProvider,
    exitCodePorProvider,
    urlsPorProvider,
    fallbackWaybackurlsUsado: false
  };

  const ejecutarIntento = async (clave, binario, args, input = null) => {
    commandPorProvider.push({
      provider: clave,
      command: comandoLegible(binario, args, input)
    });

    let resultado;
    try {
      resultado = await ejecutarProceso(binario, args, timeoutMs, input);
    } catch (error) {
      resultado = {
        stdout: '',
        stderr: '',
        exitCode: null,
        timedOut: false,
        notInstalled: pareceNoInstalada(error),
        error: error?.message || String(error)
      };
    }

    if (typeof resultado === 'string') {
      resultado = {
        stdout: resultado,
        stderr: '',
        exitCode: 0,
        timedOut: false,
        notInstalled: false,
        error: null
      };
    }

    const stdout = String(resultado?.stdout || '');
    const stderr = String(resultado?.stderr || '');
    const urls = parsearLineas(stdout).filter(linea => /^https?:\/\//i.test(linea));
    stdoutLengthPorProvider[clave] = stdout.length;
    stderrPorProvider[clave] = stderr || resultado?.error || '';
    exitCodePorProvider[clave] = resultado?.exitCode ?? null;
    urlsPorProvider[clave] = urls.length;

    return {
      ...resultado,
      stdout,
      stderr,
      urls
    };
  };

  const registrarIncidencia = (provider, resultado) => {
    if (resultado.timedOut) {
      huboIncidencia = true;
      warnings.push(`GAU provider ${provider} excedio el timeout de ${timeoutSeconds}s; se continuo con el siguiente fallback.`);
    } else if (resultado.error && !resultado.notInstalled) {
      huboIncidencia = true;
      warnings.push(`GAU provider ${provider} fallo sin detener el pipeline: ${resultado.error}`);
    }
  };

  console.log(`[gau] dominio analizado: ${dominio}`);

  if (!envHabilitada('ENABLE_GAU', true) && opciones.enabled !== true) {
    warnings.push('GAU esta deshabilitado mediante ENABLE_GAU=false.');
    const resultadoFiltro = filtrarYPriorizarUrlsGau([], dominio, opciones);
    return {
      status: 'skipped',
      raw: '',
      parsed: [],
      findings: [],
      warning: warnings.join(' '),
      metrics: {
        source: 'none',
        provider_principal: providerPrincipal,
        providers_probados: [],
        provider_usado: null,
        gau_raw_urls: 0,
        fallback_raw_urls: 0,
        endpoints_encontrados: 0,
        ...resultadoFiltro.discardedStats,
        raw_length: 0,
        timeout_seconds: timeoutSeconds,
        fallback_waybackurls_usado: false,
        enviadas_gf: 0,
        enviados_ia: 0,
        enviadas_ia: 0,
        limits: resultadoFiltro.limits
      },
      debug: { execution: executionLog }
    };
  }

  const intentarProviders = async providers => {
    for (const provider of providers) {
      providersProbados.push(provider);
      const args = [dominio, '--providers', provider, '--timeout', String(timeoutSeconds)];
      const resultado = await ejecutarIntento(provider, 'gau', args);

      if (resultado.notInstalled) {
        gauDisponible = false;
        huboIncidencia = true;
        warnings.push('gau no esta instalado; se intentara el fallback waybackurls si esta habilitado.');
        break;
      }

      registrarIncidencia(provider, resultado);
      if (resultado.urls.length === 0) continue;

      providerUsado = provider;
      source = `gau:${provider}`;
      raw = resultado.stdout;
      rawUrls = resultado.urls;
      gauRawUrls = resultado.urls.length;
      break;
    }
  };

  await intentarProviders(providersPrincipales);

  if (!providerUsado && gauDisponible && enableProviderFallback) {
    warnings.push(`El provider principal ${providerPrincipal} no devolvio URLs; se probaron providers fallback de forma independiente.`);
    await intentarProviders(providersFallback);
  }

  if (!providerUsado && enableWaybackurlsFallback) {
    fallbackWaybackurlsUsado = true;
    const resultado = await ejecutarIntento('waybackurls', 'waybackurls', [], `${dominio}\n`);

    if (resultado.notInstalled) {
      warnings.push('waybackurls no esta instalado; fallback omitido.');
    } else {
      if (resultado.timedOut) {
        huboIncidencia = true;
        warnings.push(`waybackurls excedio el timeout de ${timeoutSeconds}s; el pipeline continuo sin bloquearse.`);
      } else if (resultado.error) {
        huboIncidencia = true;
        warnings.push(`waybackurls fallo sin detener el pipeline: ${resultado.error}`);
      }

      if (resultado.urls.length > 0) {
        source = 'waybackurls';
        raw = resultado.stdout;
        rawUrls = resultado.urls;
        fallbackRawUrls = resultado.urls.length;
        warnings.push('GAU no devolvio URLs; se usaron resultados del fallback waybackurls.');
      }
    }
  }

  if (rawUrls.length === 0) {
    warnings.push('GAU no devolvio URLs con los providers configurados y no hubo resultados de fallback.');
  } else if (providerUsado && providerUsado !== providerPrincipal) {
    warnings.push(`El provider principal ${providerPrincipal} no devolvio resultados; se uso gau:${providerUsado}.`);
  }

  executionLog.providerUsado = providerUsado;
  executionLog.fallbackWaybackurlsUsado = fallbackWaybackurlsUsado;

  const resultadoFiltro = filtrarYPriorizarUrlsGau(rawUrls, dominio, {
    ...opciones,
    source
  });
  const endpoints = resultadoFiltro.selected;
  const top20 = endpoints.slice(0, 20).map(endpoint => ({
    url: endpoint.url,
    score: endpoint.score,
    reasons: endpoint.scoreReasons
  }));
  let status = 'partial';
  if (source === 'waybackurls') {
    status = 'partial';
  } else if (providerUsado) {
    status = providerUsado === providerPrincipal && !huboIncidencia ? 'success' : 'partial';
  } else if (!gauDisponible) {
    status = 'skipped';
  }

  console.log(`[gau] raw URLs: ${rawUrls.length}`);
  console.log(`[gau] URLs validas: ${resultadoFiltro.discardedStats.urls_validas}`);
  console.log(`[gau] seleccionadas tras filtrado inteligente: ${endpoints.length}`);
  console.log(`[gau] URLs con parametros: ${resultadoFiltro.discardedStats.con_parametros}`);
  console.log(`[gau] ejecucion: ${JSON.stringify(executionLog)}`);
  if (warnings.length > 0) console.log(`[gau] warnings: ${warnings.join(' ')}`);
  console.log('[gau] top seleccionadas:', top20);

  return {
    status,
    raw,
    parsed: endpoints,
    findings: [],
    warning: warnings.length > 0 ? warnings.join(' ') : null,
    error: !gauDisponible && source === 'none' ? 'gau no esta instalado' : null,
    metrics: {
      source,
      provider_principal: providerPrincipal,
      providers_probados: providersProbados,
      provider_usado: providerUsado,
      gau_raw_urls: gauRawUrls,
      fallback_raw_urls: fallbackRawUrls,
      endpoints_encontrados: endpoints.length,
      raw_urls: rawUrls.length,
      urls_validas: resultadoFiltro.discardedStats.urls_validas,
      urls_externas_descartadas: resultadoFiltro.discardedStats.urls_externas_descartadas,
      assets_descartados: resultadoFiltro.discardedStats.assets_descartados,
      trackers_descartados: resultadoFiltro.discardedStats.trackers_descartados,
      ruido_historico_descartado: resultadoFiltro.discardedStats.ruido_historico_descartado,
      ruido_historico_por_motivo: resultadoFiltro.discardedStats.ruido_historico_por_motivo,
      duplicados_descartados: resultadoFiltro.discardedStats.duplicados_descartados,
      patrones_deduplicados: resultadoFiltro.discardedStats.patrones_deduplicados,
      con_parametros: resultadoFiltro.discardedStats.con_parametros,
      seleccionadas_final: endpoints.length,
      enviadas_gf: endpoints.length,
      enviados_ia: 0,
      enviadas_ia: 0,
      raw_length: raw.length,
      timeout_seconds: timeoutSeconds,
      fallback_waybackurls_usado: fallbackWaybackurlsUsado,
      command_por_provider: commandPorProvider,
      stdout_length_por_provider: stdoutLengthPorProvider,
      stderr_por_provider: stderrPorProvider,
      exit_code_por_provider: exitCodePorProvider,
      urls_por_provider: urlsPorProvider,
      limits: resultadoFiltro.limits,
      top_selected: top20
    },
    debug: {
      execution: executionLog,
      filtered_count: resultadoFiltro.filtered.length,
      discardedStats: resultadoFiltro.discardedStats,
      selected: top20
    }
  };
}

module.exports = {
  ejecutarGau,
  normalizarEndpoint,
  filtrarYPriorizarUrlsGau,
  puntuarUrl,
  perteneceAlTarget,
  clavePatron
};
