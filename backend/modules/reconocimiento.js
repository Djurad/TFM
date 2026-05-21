const { exec } = require('child_process');
const { esAssetEstatico } = require('./clasificadorFindings');
const { ejecutarGau } = require('./gau');
const { ejecutarFeroxbuster } = require('./feroxbuster');
const { ejecutarGf, deduplicarPorPatron, ordenarPorPrioridad, PRIORIDAD_PARAMS } = require('./gf');
const { ejecutarTrufflehog } = require('./trufflehog');

function ejecutarComando(comando, opciones = {}) {
  return new Promise((resolve, reject) => {
    exec(
      comando,
      {
        timeout: 180000,
        maxBuffer: 1024 * 1024 * 20
      },
      (error, stdout, stderr) => {
        if (error) {
          if (stdout && stdout.trim()) return resolve(stdout);
          if (opciones.permitirFalloSinSalida) return resolve('');

          const detalles = [
            stderr && stderr.trim(),
            error.message && error.message.trim()
          ].filter(Boolean);

          return reject(new Error(detalles.join('\n') || 'Comando fallido sin salida de error.'));
        }

        resolve(stdout);
      }
    );
  });
}

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

function parsearDalfox(output) {
  return parsearLineas(output)
    .map(linea => {
      try {
        return JSON.parse(linea);
      } catch {
        return {
          raw: linea
        };
      }
    });
}

function parsearSqlmap(url, output) {
  const limpio = limpiarColoresANSI(output);

  const confirmed =
    limpio.includes('is vulnerable') ||
    limpio.includes('sqlmap identified the following injection point') ||
    limpio.includes('Parameter:');

  const possible =
    !confirmed &&
    (
      limpio.includes('might be injectable') ||
      limpio.includes('heuristic test shows') ||
      limpio.includes('appears to be injectable')
    );

  const parametro = (limpio.match(/Parameter:\s*([^\s(]+)/i) || [])[1] || null;
  const dbms = (limpio.match(/back-end DBMS:\s*([^\n]+)/i) || [])[1]?.trim() || null;
  const payload = (limpio.match(/Payload:\s*([^\n]+)/i) || [])[1]?.trim() || null;
  const resumen = limpio
    .split('\n')
    .filter(linea =>
      linea.includes('Parameter:') ||
      linea.includes('Type:') ||
      linea.includes('Title:') ||
      linea.includes('Payload:') ||
      linea.includes('back-end DBMS:')
    )
    .map(linea => linea.trim());

  return {
    url,
    status: confirmed ? 'confirmed_sqli' : possible ? 'possible_sqli' : 'not_vulnerable',
    vulnerable: confirmed,
    parametro,
    payload,
    dbms,
    evidencia: confirmed || possible
      ? [
          parametro ? `Parametro vulnerable: ${parametro}` : null,
          payload ? `Payload: ${payload}` : null,
          dbms ? `DBMS: ${dbms}` : null
        ].filter(Boolean).join('\n')
      : 'Sqlmap no confirmo inyeccion SQL.',
    resumen
  };
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

function valorSospechosoSqlmap(valor = '') {
  const decoded = decodeURIComponent(String(valor || '')).toLowerCase();
  return decoded.includes('<') ||
    decoded.includes('>') ||
    decoded.includes('script') ||
    decoded.includes('alert') ||
    decoded.includes('svg') ||
    decoded.includes('iframe') ||
    decoded.includes('onerror') ||
    decoded.includes('onload');
}

function normalizarUrlParaSqlmap(url) {
  try {
    const parsed = new URL(url);
    const entradas = Array.from(parsed.searchParams.entries());

    parsed.search = '';
    entradas.forEach(([key, value]) => {
      if (value === '') {
        parsed.searchParams.append(key, '1');
      } else if (valorSospechosoSqlmap(value)) {
        parsed.searchParams.append(key, 'test');
      } else {
        parsed.searchParams.append(key, value);
      }
    });

    return parsed.href;
  } catch {
    return url;
  }
}

function registrarPaso(nombre, mensaje, extra = {}) {
  console.log(`[recon] ${nombre}: ${mensaje}`, Object.keys(extra).length ? extra : '');
}

function contarDescartadosNuclei(lineas = []) {
  return lineas.filter(linea => {
    const lower = String(linea).toLowerCase();
    return lower.includes('[info]') ||
      lower.includes('waf-detect') ||
      lower.includes('wildcard-dns-detect') ||
      lower.includes('tech-detect') ||
      lower.includes('favicon') ||
      lower.includes('cdn');
  }).length;
}

async function ejecutarReconocimiento(targetOriginal) {
  const entrada = normalizarEntrada(targetOriginal);
  let target = entrada.domain;

  if (target === 'juice-shop.github.io') {
    registrarPaso('normalizacion', 'juice-shop.github.io apunta a documentacion estatica; se usa la app vulnerable publica.', {
      original: target,
      normalizado: 'demo.owasp-juice.shop'
    });
    target = 'demo.owasp-juice.shop';
    entrada.baseUrl = 'https://demo.owasp-juice.shop';
    entrada.inputUrl = 'https://demo.owasp-juice.shop';
  }

  if (!validarTarget(target)) {
    throw new Error('Target no valido. Usa un dominio, por ejemplo: testphp.vulnweb.com');
  }

  const toolResults = {};
  const includeNucleiInfo = process.env.NUCLEI_INCLUDE_INFO === 'true';
  const sqlmapCrawlIfNoParams = process.env.SQLMAP_CRAWL_IF_NO_PARAMS === 'true';
  const timeoutMs = Number(process.env.TOOL_TIMEOUT_SECONDS || 120) * 1000;
  const maxGauUrls = Number(process.env.MAX_GAU_URLS || 500);
  const maxFeroxUrls = Number(process.env.MAX_FEROX_URLS || 100);
  const maxDalfoxUrls = Number(process.env.MAX_DALFOX_URLS || 50);
  const maxSqlmapUrls = Number(process.env.MAX_SQLMAP_URLS || 10);
  const maxJsSecretScan = Number(process.env.MAX_JS_SECRET_SCAN || 20);

  async function ejecutarHerramienta(nombre, comando, parser = parsearLineas) {
    try {
      registrarPaso(nombre, 'ejecutando herramienta', { entrada: target, comando });
      const raw = await ejecutarComando(comando, {
        permitirFalloSinSalida: nombre === 'nuclei'
      });
      const parsed = parser(raw);
      const parsedCount = Array.isArray(parsed) ? parsed.length : 0;
      registrarPaso(nombre, 'resultados producidos', { resultados: parsedCount });

      toolResults[nombre] = {
        status: 'success',
        raw,
        parsed,
        findings: []
      };

      return raw;
    } catch (error) {
      toolResults[nombre] = {
        status: 'error',
        raw: '',
        parsed: [],
        findings: [],
        error: error.message
      };

      console.error(`Error en ${nombre}:`, error.message);
      return '';
    }
  }

  registrarPaso('normalizacion', 'entrada normalizada', {
    original: entrada.original,
    dominioLimpio: target,
    urlInicial: entrada.inputUrl
  });

  const targetLocal = esTargetLocal(target) || esIpV4(target);

  const subfinderOutput = targetLocal
    ? ''
    : await ejecutarHerramienta(
        'subfinder',
        `subfinder -d ${target} -silent`
      );

  if (targetLocal) {
    toolResults.subfinder = {
      status: 'skipped',
      raw: '',
      parsed: [],
      findings: [],
      error: 'subfinder no aplica a targets locales o direcciones IP'
    };
  }

  let subdominios = parsearLineas(subfinderOutput);

  subdominios = deduplicarUrls([...subdominios, target]);

  const inputHttpx = deduplicarUrls([...subdominios, entrada.inputUrl, entrada.baseUrl]).join('\n');

  const httpxOutput = await ejecutarHerramienta(
    'httpx',
    `printf "%s\n" "${inputHttpx}" | httpx -silent -json -title -status-code -tech-detect -web-server -content-length -content-type -location -follow-redirects -no-color`,
    parsearHttpxJson
  );

  const httpx = parsearHttpxJson(httpxOutput);
  const activos = deduplicarUrls(httpx.map(item => item.finalUrl || item.url).filter(Boolean));
  const inputKatana = activos.join('\n');

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
  toolResults.feroxbuster = feroxResult;

  const katanaOutput = activos.length > 0
    ? await ejecutarHerramienta(
        'katana',
        `printf "%s\n" "${inputKatana}" | katana -silent -depth 3 -jc -kf all`
      )
    : '';

  if (activos.length === 0) {
    toolResults.katana = {
      status: 'skipped',
      raw: '',
      parsed: [],
      findings: [],
      error: 'No hay activos HTTP para rastrear.'
    };
  }

  const endpointUrlsCrudosSinDedup = [
    ...parsearLineas(katanaOutput),
    ...activos,
    entrada.inputUrl
  ];
  const endpointUrlsCrudos = deduplicarUrlsNormalizadas(endpointUrlsCrudosSinDedup);
  const endpointUrls = endpointUrlsCrudos.filter(url => !esAssetEstatico(url));
  const assetsIgnorados = endpointUrlsCrudos.length - endpointUrls.length;
  const duplicadosKatana = Math.max(0, endpointUrlsCrudosSinDedup.filter(Boolean).length - endpointUrlsCrudos.length);

  const gauResult = targetLocal
    ? {
        status: 'skipped',
        raw: '',
        parsed: [],
        findings: [],
        error: 'gau no aplica a targets locales o direcciones IP',
        metrics: {
          endpoints_encontrados: 0,
          con_parametros: 0,
          enviados_ia: 0,
          raw_length: 0
        }
      }
    : await ejecutarGau(target, { maxUrls: maxGauUrls, timeoutMs });
  toolResults.gau = gauResult;

  const endpointsKatana = endpointUrls.map(url => crearEndpoint(url, 'katana', buscarHttpInfo(url, httpx)));
  const endpointsGau = Array.isArray(gauResult.parsed) ? gauResult.parsed : [];
  const endpointsFerox = Array.isArray(feroxResult.parsed) ? feroxResult.parsed : [];
  const endpoints = deduplicarEndpoints([
    ...endpointsKatana,
    ...endpointsGau,
    ...endpointsFerox
  ]);
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
  }

  const inputNuclei = activos.join('\n');
  const severidadesNuclei = includeNucleiInfo ? 'info,low,medium,high,critical' : 'low,medium,high,critical';
  const excludeTags = 'dns,tech,waf,cdn,favicon';

  const nucleiOutput = activos.length > 0
    ? await ejecutarHerramienta(
        'nuclei',
        `printf "%s\n" "${inputNuclei}" | nuclei -severity ${severidadesNuclei} -exclude-tags ${excludeTags} -silent -timeout 10 -no-color`
      )
    : '';

  if (activos.length === 0) {
    toolResults.nuclei = {
      status: 'skipped',
      raw: '',
      parsed: [],
      findings: [],
      error: 'No hay activos HTTP para analizar con nuclei.'
    };
  }

  const vulnerabilidades = parsearLineas(nucleiOutput);
  registrarPaso('nuclei', 'ruido informativo/fingerprinting descartado por configuracion o clasificador', {
    descartados: contarDescartadosNuclei(vulnerabilidades),
    includeInfo: includeNucleiInfo
  });

  const gfResult = await ejecutarGf(endpoints, { timeoutMs });
  toolResults.gf = gfResult;

  const endpointsConParametros = endpoints.filter(endpoint => endpoint.hasParams);
  const urlsParametrizadas = endpointsConParametros.map(endpoint => endpoint.url);
  const gfBuckets = gfResult.parsed || {};
  const xssDesdeGf = gfResult.status === 'success' ? (gfBuckets.xssCandidates || []) : [];
  const sqliDesdeGf = gfResult.status === 'success' ? (gfBuckets.sqliCandidates || []) : [];
  const urlsDalfox = limitarUrls(
    xssDesdeGf.length ? xssDesdeGf : urlsParametrizadas,
    xssDesdeGf.length ? maxDalfoxUrls : Math.min(maxDalfoxUrls, 30)
  );
  const inputDalfox = urlsDalfox.join('\n');

  console.log(`[dalfox] URLs recibidas desde gf xss: ${xssDesdeGf.length}`);

  const dalfoxOutput = urlsDalfox.length > 0
    ? await ejecutarHerramienta(
        'dalfox',
        `printf "%s\n" "${inputDalfox}" | dalfox pipe --silence --format json`,
        parsearDalfox
      )
    : '';

  if (urlsDalfox.length === 0) {
    toolResults.dalfox = {
      status: 'skipped',
      raw: '',
      parsed: [],
      findings: [],
      error: 'No hay endpoints con parametros para probar XSS.'
    };
  }

  const dalfox = parsearDalfox(dalfoxOutput);

  console.log(`[sqlmap] URLs recibidas desde gf sqli: ${sqliDesdeGf.length}`);

  let candidatosSqlmap = limitarUrls(
    (sqliDesdeGf.length ? sqliDesdeGf : urlsParametrizadas.filter(esCandidatoSqlmap)),
    maxSqlmapUrls
  ).map(normalizarUrlParaSqlmap);

  if (candidatosSqlmap.length === 0) {
    candidatosSqlmap = limitarUrls(urlsParametrizadas, maxSqlmapUrls).map(normalizarUrlParaSqlmap);
  }

  candidatosSqlmap = deduplicarPorPatron(candidatosSqlmap);

  const sqlmap = [];

  for (const url of candidatosSqlmap) {
    try {
      registrarPaso('sqlmap', 'ejecutando sobre URL parametrizada', { entrada: url });
      const sqlmapOutput = await ejecutarComando(
        `python3 tools/sqlmap/sqlmap.py -u "${url}" --batch --random-agent --level=1 --risk=1 --smart --disable-coloring`
      );

      sqlmap.push(parsearSqlmap(url, sqlmapOutput));
    } catch (error) {
      console.error(`Error en sqlmap para ${url}:`, error.message);

      sqlmap.push({
        url,
        vulnerable: false,
        error: error.message,
        evidencia: null,
        resumen: []
      });
    }
  }

  if (candidatosSqlmap.length === 0 && sqlmapCrawlIfNoParams && activos.length > 0) {
    for (const url of activos.slice(0, 3)) {
      try {
        registrarPaso('sqlmap', 'sin parametros descubiertos; ejecutando crawl ligero', { entrada: url });
        const sqlmapOutput = await ejecutarComando(
          `python3 tools/sqlmap/sqlmap.py -u "${url}" --crawl=2 --batch --random-agent --level=1 --risk=1 --smart --disable-coloring`
        );
        sqlmap.push(parsearSqlmap(url, sqlmapOutput));
      } catch (error) {
        sqlmap.push({
          url,
          status: 'error',
          vulnerable: false,
          error: error.message,
          evidencia: null,
          resumen: []
        });
      }
    }
  }

  if (candidatosSqlmap.length === 0 && !sqlmapCrawlIfNoParams) {
    registrarPaso('sqlmap', 'no ejecutado', {
      motivo: 'sqlmap no se ejecuto porque no se encontraron parametros'
    });
  }

  toolResults.sqlmap = {
    status: candidatosSqlmap.length === 0 && !sqlmapCrawlIfNoParams
      ? 'skipped'
      : sqlmap.some(item => item.error) ? 'partial' : 'success',
    raw: JSON.stringify(sqlmap, null, 2),
    parsed: sqlmap,
    findings: [],
    error: candidatosSqlmap.length === 0 && !sqlmapCrawlIfNoParams
      ? 'sqlmap no se ejecuto porque no se encontraron parametros'
      : null
  };

  const trufflehogResult = await ejecutarTrufflehog(
    [
      ...endpointUrlsCrudos,
      ...endpoints.map(endpoint => endpoint.url)
    ],
    { maxJs: maxJsSecretScan, timeoutMs }
  );
  toolResults.trufflehog = trufflehogResult;

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
      gf: gfResult.parsed || {},
      gau: endpointsGau,
      feroxbuster: endpointsFerox,
      trufflehog: trufflehogResult.parsed || []
    }
  };
}

module.exports = {
  ejecutarReconocimiento,
  normalizarUrlParaSqlmap
};
