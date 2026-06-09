const { esAssetEstatico } = require('./procesamiento/clasificadorFindings');
const { ejecutarGau } = require('./herramientas/gau');
const { ejecutarFeroxbuster } = require('./herramientas/feroxbuster');
const { ejecutarGf, deduplicarPorPatron, ordenarPorPrioridad, PRIORIDAD_PARAMS } = require('./herramientas/gf');
const { ejecutarTrufflehog } = require('./herramientas/trufflehog');
const { ejecutarNuclei, construirArgsNuclei, contarDescartadosNuclei, parsearNucleiJsonl } = require('./herramientas/nuclei');
const { ejecutarDalfox, parsearDalfox } = require('./herramientas/dalfox');
const { ejecutarSqlmap, normalizarUrlParaSqlmap } = require('./herramientas/sqlmap');
const { ejecutarSubfinder } = require('./herramientas/subfinder');
const { ejecutarKatana } = require('./herramientas/katana');
const { ejecutarHttpx, construirInputHttpx, deduplicarHttpxResultados } = require('./herramientas/httpx');
const { ejecutarHeaders } = require('./analizadores/headers');
const { ejecutarCookies } = require('./analizadores/cookies');
const { ejecutarHttpsRedirect } = require('./analizadores/httpsRedirect');
const { ejecutarRobotsSitemap } = require('./analizadores/robotsSitemap');
const { ejecutarTls } = require('./analizadores/tls');
const { ejecutarPorts } = require('./analizadores/ports');
const { extraerFindingsDeterministas } = require('./procesamiento/extractores');

function limpiarColoresANSI(texto = '') {
  return texto.replace(/\x1B\[[0-9;]*m/g, '');
}

function limpiarTarget(target) {
  return target
    .replace(/^https?:\/\//, '')
    .split('/')[0]
    .replace(/\/$/, '')
    .trim();
}

function normalizarEntrada(targetOriginal) {
  const entrada = String(targetOriginal || '').trim();
  const conProtocolo = /^https?:\/\//i.test(entrada) ? entrada : `https://${entrada}`;

  try {
    const parsed = new URL(conProtocolo);
    const domain = limpiarTarget(parsed.hostname);
    const baseUrl = `${parsed.protocol}//${parsed.host}`;
    const inputUrl = parsed.pathname !== '/' || parsed.search
      ? `${parsed.origin}${parsed.pathname}${parsed.search}`.replace(/\/$/, '')
      : baseUrl;

    return {
      domain,
      baseUrl,
      inputUrl,
      original: entrada
    };
  } catch {
    return {
      domain: limpiarTarget(entrada),
      baseUrl: `https://${limpiarTarget(entrada)}`,
      inputUrl: `https://${limpiarTarget(entrada)}`,
      original: entrada
    };
  }
}

function validarTarget(target) {
  return esDominio(target) || esIpV4(target) || target === 'localhost';
}

function esDominio(target) {
  return /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(target);
}

function esIpV4(target) {
  const partes = String(target || '').split('.');
  return partes.length === 4 && partes.every(parte => {
    if (!/^\d+$/.test(parte)) return false;
    const numero = Number(parte);
    return numero >= 0 && numero <= 255;
  });
}

function esTargetLocal(target) {
  return target === 'localhost' ||
    target === '127.0.0.1' ||
    target === '0.0.0.0' ||
    target.startsWith('192.168.') ||
    target.startsWith('10.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(target);
}

function parsearLineas(texto = '') {
  return limpiarColoresANSI(texto)
    .split('\n')
    .map(linea => linea.trim())
    .filter(Boolean);
}

function obtenerParametros(url) {
  try {
    return Array.from(new URL(url).searchParams.keys());
  } catch {
    return [];
  }
}

function tieneParametros(url) {
  return obtenerParametros(url).length > 0;
}

function esCandidatoSqlmap(url) {
  const parametros = obtenerParametros(url).map(p => p.toLowerCase());

  return parametros.some(p => PRIORIDAD_PARAMS.includes(p));
}

function categorizarEndpoint(url) {
  const lower = String(url || '').toLowerCase();

  if (esAssetEstatico(url)) return 'estatico';
  if (lower.includes('swagger') || lower.includes('/api-doc') || lower.includes('openapi')) return 'api-docs';
  if (lower.includes('admin')) return 'admin';
  if (lower.includes('login') || lower.includes('signin')) return 'login';
  if (lower.includes('search') || lower.includes('?q=')) return 'busqueda';
  if (lower.includes('feedback') || lower.includes('survey') || lower.includes('contact') || lower.includes('subscribe')) return 'formulario';
  if (lower.endsWith('.js')) return 'javascript';
  if (lower.endsWith('.css') || lower.match(/\.(png|jpe?g|gif|svg|ico|woff2?)($|\?)/)) return 'estatico';
  if (lower.includes('?')) return 'dinamico';

  return 'general';
}

function crearEndpoint(url, sourceTool = 'katana', httpInfo = null) {
  let parsed = null;

  try {
    parsed = new URL(url);
  } catch {
    // Se mantiene la URL cruda si Katana devuelve un formato no estandar.
  }

  const queryParams = parsed ? Array.from(parsed.searchParams.keys()) : [];

  return {
    url,
    path: parsed ? parsed.pathname : '',
    queryParams,
    parametros: queryParams,
    sourceTool,
    status: httpInfo?.statusCode || null,
    contentType: httpInfo?.contentType || null,
    category: categorizarEndpoint(url),
    categoria: categorizarEndpoint(url),
    hasParams: queryParams.length > 0,
    tieneParametros: queryParams.length > 0
  };
}

function deduplicarUrls(urls) {
  return Array.from(new Set((urls || []).filter(Boolean).map(url => String(url).trim()).filter(Boolean)));
}

function normalizarClaveUrl(url) {
  try {
    const parsed = new URL(url);
    parsed.hash = '';
    const params = Array.from(parsed.searchParams.entries())
      .sort(([a], [b]) => a.localeCompare(b));
    parsed.search = '';
    params.forEach(([key, value]) => parsed.searchParams.append(key, value));
    return parsed.href.replace(/\/$/, '');
  } catch {
    return String(url || '').trim().replace(/\/$/, '');
  }
}

function deduplicarUrlsNormalizadas(urls = []) {
  const mapa = new Map();

  urls.filter(Boolean).forEach(url => {
    const key = normalizarClaveUrl(url);
    if (!mapa.has(key)) mapa.set(key, String(url).trim());
  });

  return Array.from(mapa.values());
}

function deduplicarEndpoints(endpoints = []) {
  const mapa = new Map();
  endpoints.filter(Boolean).forEach(endpoint => {
    if (!endpoint.url) return;
    const key = normalizarClaveUrl(endpoint.url);
    if (!mapa.has(key)) mapa.set(key, endpoint);
  });
  return Array.from(mapa.values());
}

function limitarUrls(urls = [], max) {
  return deduplicarPorPatron(ordenarPorPrioridad(urls.filter(Boolean))).slice(0, max);
}

function esUrlPrioritariaDalfox(url = '') {
  try {
    const parsed = new URL(url);
    const params = Array.from(parsed.searchParams.keys()).map(param => param.toLowerCase());
    const path = parsed.pathname.toLowerCase();
    return params.includes('hostname') ||
      params.includes('host') ||
      path.includes('serverstatuscheckservice') ||
      path.includes('status_check');
  } catch {
    return /hostname|serverstatuscheckservice|status_check/i.test(String(url || ''));
  }
}

function asegurarUrlsPrioritariasDalfox(seleccionadas = [], candidatas = [], max = 50) {
  const seleccion = deduplicarUrls(seleccionadas);
  const prioritarias = deduplicarUrls(candidatas).filter(esUrlPrioritariaDalfox);

  prioritarias.forEach(url => {
    if (seleccion.includes(url)) return;
    if (seleccion.length < max) {
      seleccion.push(url);
      return;
    }
    seleccion[seleccion.length - 1] = url;
  });

  return deduplicarUrls(seleccion);
}

function buscarHttpInfo(url, httpx = []) {
  try {
    const parsed = new URL(url);
    return httpx.find(item => {
      try {
        const itemUrl = new URL(item.finalUrl || item.url);
        return itemUrl.origin === parsed.origin && itemUrl.pathname === parsed.pathname;
      } catch {
        return false;
      }
    }) || null;
  } catch {
    return null;
  }
}

function registrarPaso(nombre, mensaje, extra = {}) {
  console.log(`[recon] ${nombre}: ${mensaje}`, Object.keys(extra).length ? extra : '');
}

async function ejecutarReconocimiento(targetOriginal, opciones = {}) {
  const scanLogger = opciones.scanLogger || null;
  const onProgress = typeof opciones.onProgress === 'function' ? opciones.onProgress : null;
  const progreso = (tool, status, message, extra = {}) => {
    if (onProgress) onProgress({ tool, status, message, ...extra });
  };
  const logVar = (name, value) => {
    if (scanLogger?.variable) scanLogger.variable(name, value);
  };
  const entrada = normalizarEntrada(targetOriginal);
  let target = entrada.domain;

  if (!validarTarget(target)) {
    throw new Error('Target no valido. Usa un dominio, por ejemplo: testphp.vulnweb.com');
  }

  logVar('targetOriginal', targetOriginal);
  logVar('entrada', entrada);
  logVar('target', target);

  const toolResults = {};
  const sqlmapCrawlIfNoParams = process.env.SQLMAP_CRAWL_IF_NO_PARAMS === 'true';
  const timeoutMs = Number(process.env.TOOL_TIMEOUT_SECONDS || 120) * 1000;
  const gauTimeoutSeconds = Number(process.env.GAU_TIMEOUT_SECONDS || 10);
  const maxFeroxUrls = Number(process.env.MAX_FEROX_URLS || 100);
  const maxDalfoxUrls = Number(process.env.MAX_DALFOX_URLS || 50);
  const maxSqlmapUrls = Number(process.env.MAX_SQLMAP_URLS || 10);
  const maxJsSecretScan = Number(process.env.MAX_JS_SECRET_SCAN || 20);
  const passiveTimeoutMs = Number(process.env.PASSIVE_TIMEOUT_SECONDS || 8) * 1000;

  registrarPaso('normalizacion', 'entrada normalizada', {
    original: entrada.original,
    dominioLimpio: target,
    urlInicial: entrada.inputUrl
  });
  progreso('normalizacion', 'running', 'Normalizando objetivo');

  const targetLocal = esTargetLocal(target) || esIpV4(target);

  toolResults.subfinder = await ejecutarSubfinder(target, {
    targetLocal,
    timeoutMs,
    logVar,
    registrarPaso,
    progreso
  });
  const subfinderOutput = toolResults.subfinder.raw || '';

  let subdominios = parsearLineas(subfinderOutput);
  logVar('subfinderOutput', subfinderOutput);

  subdominios = deduplicarUrls([...subdominios, target]);
  logVar('subdominios', subdominios);

  const httpxResult = await ejecutarHttpx(entrada, subdominios, {
    timeoutMs,
    target,
    logVar,
    registrarPaso,
    progreso
  });
  toolResults.httpx = httpxResult.result;
  const httpx = httpxResult.httpx;
  const activos = deduplicarUrls(httpx.map(item => item.finalUrl || item.url).filter(Boolean));
  logVar('activos', activos);
  const inputKatana = activos.join('\n');
  logVar('inputKatana', inputKatana);

  progreso('headers', 'running', 'Analizando cabeceras HTTP');
  toolResults.headers = await ejecutarHeaders(activos, { timeoutMs: passiveTimeoutMs });
  logVar('toolResults.headers', toolResults.headers);
  progreso('headers', toolResults.headers.status || 'done', 'Cabeceras HTTP finalizadas');
  progreso('cookies', 'running', 'Analizando cookies');
  toolResults.cookies = await ejecutarCookies(activos, { timeoutMs: passiveTimeoutMs });
  logVar('toolResults.cookies', toolResults.cookies);
  progreso('cookies', toolResults.cookies.status || 'done', 'Cookies finalizadas');
  progreso('httpsRedirect', 'running', 'Comprobando redireccion HTTPS');
  toolResults.httpsRedirect = await ejecutarHttpsRedirect(target, { timeoutMs: passiveTimeoutMs });
  logVar('toolResults.httpsRedirect', toolResults.httpsRedirect);
  progreso('httpsRedirect', toolResults.httpsRedirect.status || 'done', 'Redireccion HTTPS finalizada');
  progreso('tls', 'running', 'Revisando TLS y certificados');
  toolResults.tls = await ejecutarTls(activos, { timeoutMs: passiveTimeoutMs });
  logVar('toolResults.tls', toolResults.tls);
  progreso('tls', toolResults.tls.status || 'done', 'TLS finalizado');
  progreso('robotsSitemap', 'running', 'Leyendo robots.txt y sitemap.xml');
  toolResults.robotsSitemap = await ejecutarRobotsSitemap(activos, { timeoutMs: passiveTimeoutMs });
  logVar('toolResults.robotsSitemap', toolResults.robotsSitemap);
  progreso('robotsSitemap', toolResults.robotsSitemap.status || 'done', 'Robots y sitemap finalizados');
  progreso('ports', 'running', 'Comprobando puertos expuestos');
  toolResults.ports = await ejecutarPorts(target, { timeoutMs: passiveTimeoutMs });
  logVar('toolResults.ports', toolResults.ports);
  progreso('ports', toolResults.ports.status || 'done', 'Puertos finalizados');

  progreso('feroxbuster', 'running', 'Descubriendo rutas');
  const feroxResult = activos.length > 0
    ? await ejecutarFeroxbuster(activos, { maxUrls: maxFeroxUrls, timeoutMs })
    : {
        status: 'skipped',
        raw: '',
        parsed: [],
        findings: [],
        error: 'No hay activos HTTP para analizar con feroxbuster.',
        metrics: { endpoints_encontrados: 0, rutas_interesantes: 0, posibles_vulnerabilidades: 0 }
      };
  logVar('feroxResult', feroxResult);
  toolResults.feroxbuster = feroxResult;
  logVar('toolResults.feroxbuster', toolResults.feroxbuster);
  progreso('feroxbuster', feroxResult.status || 'done', 'Feroxbuster finalizado');

  logVar('inputKatana', inputKatana);

  toolResults.katana = await ejecutarKatana(activos, {
    timeoutMs,
    target,
    logVar,
    registrarPaso,
    progreso
  });
  const katanaOutput = toolResults.katana.raw || '';

  const endpointUrlsCrudosSinDedup = [
    ...parsearLineas(katanaOutput),
    ...activos,
    entrada.inputUrl
  ];
  const endpointUrlsCrudos = deduplicarUrlsNormalizadas(endpointUrlsCrudosSinDedup);
  const endpointUrls = endpointUrlsCrudos.filter(url => !esAssetEstatico(url));
  const assetsIgnorados = endpointUrlsCrudos.length - endpointUrls.length;
  const duplicadosKatana = Math.max(0, endpointUrlsCrudosSinDedup.filter(Boolean).length - endpointUrlsCrudos.length);
  logVar('katanaOutput', katanaOutput);
  logVar('endpointUrlsCrudosSinDedup', endpointUrlsCrudosSinDedup);
  logVar('endpointUrlsCrudos', endpointUrlsCrudos);
  logVar('endpointUrls', endpointUrls);
  logVar('assetsIgnorados', assetsIgnorados);
  logVar('duplicadosKatana', duplicadosKatana);

  progreso('gau', 'running', 'Recuperando URLs historicas');
  const gauResult = targetLocal
    ? {
        status: 'skipped',
        raw: '',
        parsed: [],
        findings: [],
        error: 'gau no aplica a targets locales o direcciones IP',
        metrics: {
          source: 'none',
          provider_principal: String(process.env.GAU_PROVIDERS || 'otx').split(',')[0].trim() || 'otx',
          providers_probados: [],
          provider_usado: null,
          gau_raw_urls: 0,
          fallback_raw_urls: 0,
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
          raw_length: 0,
          timeout_seconds: gauTimeoutSeconds,
          fallback_waybackurls_usado: false
        }
      }
    : await ejecutarGau(target, { timeoutSeconds: gauTimeoutSeconds });
  logVar('gauResult', gauResult);
  toolResults.gau = gauResult;
  logVar('toolResults.gau', toolResults.gau);
  progreso('gau', gauResult.status || 'done', 'GAU finalizado');

  const endpointsKatana = endpointUrls.map(url => crearEndpoint(url, 'katana', buscarHttpInfo(url, httpx)));
  const endpointsGau = Array.isArray(gauResult.parsed) ? gauResult.parsed : [];
  const endpointsFerox = Array.isArray(feroxResult.parsed) ? feroxResult.parsed : [];
  const endpoints = deduplicarEndpoints([
    ...endpointsKatana,
    ...endpointsGau,
    ...endpointsFerox
  ]);
  logVar('endpointsKatana', endpointsKatana);
  logVar('endpointsGau', endpointsGau);
  logVar('endpointsFerox', endpointsFerox);
  logVar('endpoints', endpoints);
  registrarPaso('katana', 'endpoints normalizados', {
    resultados: endpointsKatana.length,
    totalFusionado: endpoints.length,
    conParametros: endpoints.filter(endpoint => endpoint.hasParams).length,
    ignorados: assetsIgnorados,
    motivo: assetsIgnorados ? 'assets estaticos descartados' : 'sin descartes por assets estaticos'
  });

  if (toolResults.katana) {
    const superficieUtil = endpointsKatana.filter(endpoint => {
      const lower = String(endpoint.url || '').toLowerCase();
      return lower.includes('swagger') ||
        lower.includes('openapi') ||
        lower.includes('/api-doc') ||
        lower.includes('login') ||
        lower.includes('signin') ||
        lower.includes('/admin') ||
        lower.includes('upload') ||
        lower.includes('graphql') ||
        lower.includes('debug') ||
        lower.includes('actuator');
    }).length;

    toolResults.katana.parsed = endpointsKatana;
    toolResults.katana.metrics = {
      raw_urls: endpointUrlsCrudosSinDedup.filter(Boolean).length,
      endpoints_normalizados: endpointsKatana.length,
      superficie_util: superficieUtil,
      descartados_ruido: 0,
      descartados_assets: assetsIgnorados,
      duplicados_descartados: duplicadosKatana,
      enviados_ia: 0
    };
    logVar('toolResults.katana', toolResults.katana);
  }

  progreso('gf', 'running', 'Priorizando candidatos con GF');
  const gfResult = await ejecutarGf(endpoints, { timeoutMs });
  logVar('gfResult', gfResult);
  toolResults.gf = gfResult;
  logVar('toolResults.gf', toolResults.gf);
  progreso('gf', gfResult.status || 'done', 'GF finalizado');

  const endpointsConParametros = endpoints.filter(endpoint => endpoint.hasParams);
  const urlsParametrizadas = endpointsConParametros.map(endpoint => endpoint.url);
  const gfBuckets = gfResult.parsed || {};
  const gfUtil = ['success', 'partial'].includes(gfResult.status);
  const xssDesdeGf = gfUtil ? (gfBuckets.xssCandidates || []) : [];
  const sqliDesdeGf = gfUtil ? (gfBuckets.sqliCandidates || []) : [];
  logVar('endpointsConParametros', endpointsConParametros);
  logVar('urlsParametrizadas', urlsParametrizadas);
  logVar('gfBuckets', gfBuckets);
  logVar('xssDesdeGf', xssDesdeGf);
  logVar('sqliDesdeGf', sqliDesdeGf);

  const inputNuclei = activos.join('\n');
  const nucleiConfig = construirArgsNuclei();
  logVar('inputNuclei', inputNuclei);
  logVar('nucleiConfig', nucleiConfig);
  registrarPaso('nuclei', 'configuracion efectiva', {
    targets: activos.length,
    templatesPath: nucleiConfig.templatesPath,
    severidades: nucleiConfig.severidades,
    tags: nucleiConfig.tags,
    excludeTags: nucleiConfig.excludeTags,
    includeInfo: nucleiConfig.includeInfo
  });

  toolResults.nuclei = await ejecutarNuclei(activos, { timeoutMs });
  logVar('toolResults.nuclei', toolResults.nuclei);
  progreso('nuclei', toolResults.nuclei.status || 'done', 'Nuclei finalizado', {
    count: toolResults.nuclei.parsed_count || 0
  });

  const vulnerabilidades = Array.isArray(toolResults.nuclei?.parsed)
    ? toolResults.nuclei.parsed
    : [];
  logVar('nucleiOutput', toolResults.nuclei.raw || '');
  logVar('vulnerabilidades', vulnerabilidades);
  registrarPaso('nuclei', 'ruido informativo/fingerprinting descartado por configuracion o clasificador', {
    descartados: contarDescartadosNuclei(vulnerabilidades),
    includeInfo: nucleiConfig.includeInfo
  });

  const urlsDalfoxBase = limitarUrls(
    xssDesdeGf.length ? xssDesdeGf : urlsParametrizadas,
    xssDesdeGf.length ? maxDalfoxUrls : Math.min(maxDalfoxUrls, 30)
  );
  const urlsDalfox = asegurarUrlsPrioritariasDalfox(
    urlsDalfoxBase,
    xssDesdeGf.length ? xssDesdeGf : urlsParametrizadas,
    xssDesdeGf.length ? maxDalfoxUrls : Math.min(maxDalfoxUrls, 30)
  );
  logVar('urlsDalfoxBase', urlsDalfoxBase);
  logVar('urlsDalfox', urlsDalfox);

  console.log(`[dalfox] URLs recibidas desde gf xss: ${xssDesdeGf.length}`);

  toolResults.dalfox = await ejecutarDalfox(urlsDalfox, {
    timeoutMs,
    target,
    logVar,
    registrarPaso,
    progreso
  });
  progreso('dalfox', toolResults.dalfox?.status || 'done', 'Dalfox finalizado');

  const dalfox = toolResults.dalfox.parsed || [];
  logVar('dalfox', dalfox);

  console.log(`[sqlmap] URLs recibidas desde gf sqli: ${sqliDesdeGf.length}`);

  let candidatosSqlmap = limitarUrls(
    (sqliDesdeGf.length ? sqliDesdeGf : urlsParametrizadas.filter(esCandidatoSqlmap)),
    maxSqlmapUrls
  ).map(normalizarUrlParaSqlmap);

  if (candidatosSqlmap.length === 0) {
    candidatosSqlmap = limitarUrls(urlsParametrizadas, maxSqlmapUrls).map(normalizarUrlParaSqlmap);
  }

  candidatosSqlmap = deduplicarPorPatron(candidatosSqlmap);
  logVar('candidatosSqlmap', candidatosSqlmap);

  toolResults.sqlmap = await ejecutarSqlmap(candidatosSqlmap, {
    activos,
    timeoutMs,
    sqlmapCrawlIfNoParams,
    logVar,
    registrarPaso,
    progreso
  });
  progreso('sqlmap', toolResults.sqlmap.status || 'done', 'Sqlmap finalizado');
  const sqlmap = toolResults.sqlmap.parsed || [];

  progreso('trufflehog', 'running', 'Buscando secretos expuestos');
  const trufflehogResult = await ejecutarTrufflehog(
    [
      ...endpointUrlsCrudos,
      ...endpoints.map(endpoint => endpoint.url)
    ],
    { maxJs: maxJsSecretScan, timeoutMs }
  );
  logVar('trufflehogResult', trufflehogResult);
  toolResults.trufflehog = trufflehogResult;
  logVar('toolResults.trufflehog', toolResults.trufflehog);
  progreso('trufflehog', trufflehogResult.status || 'done', 'Trufflehog finalizado');

  return {
    target,
    fecha: new Date().toISOString(),
    subdominios,
    activos,
    endpoints,
    vulnerabilidades,
    tool_results: toolResults,
    herramientas: {
      httpx,
      dalfox,
      sqlmap,
      headers: toolResults.headers?.parsed || [],
      cookies: toolResults.cookies?.parsed || [],
      httpsRedirect: toolResults.httpsRedirect?.parsed || [],
      tls: toolResults.tls?.parsed || [],
      robotsSitemap: toolResults.robotsSitemap?.parsed || [],
      ports: toolResults.ports?.parsed || [],
      gf: gfResult.parsed || {},
      gau: endpointsGau,
      feroxbuster: endpointsFerox,
      trufflehog: trufflehogResult.parsed || []
    }
  };
}

module.exports = {
  ejecutarReconocimiento,
  normalizarUrlParaSqlmap,
  parsearDalfox,
  construirInputHttpx,
  deduplicarHttpxResultados,
  construirArgsNuclei,
  parsearNucleiJsonl
};
