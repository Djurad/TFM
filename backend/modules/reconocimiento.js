const { exec, execFile, spawn } = require('child_process');
const { esAssetEstatico } = require('./clasificadorFindings');
const { ejecutarGau } = require('./gau');
const { ejecutarFeroxbuster } = require('./feroxbuster');
const { ejecutarGf, deduplicarPorPatron, ordenarPorPrioridad, PRIORIDAD_PARAMS } = require('./gf');
const { ejecutarTrufflehog } = require('./trufflehog');
const { ejecutarHeaders } = require('./headers');
const { ejecutarCookies } = require('./cookies');
const { ejecutarHttpsRedirect } = require('./httpsRedirect');
const { ejecutarRobotsSitemap } = require('./robotsSitemap');
const { ejecutarTls } = require('./tls');
const { ejecutarPorts } = require('./ports');
const { extraerFindingsDeterministas } = require('./extractores');

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

function ejecutarBinario(binario, args = [], opciones = {}) {
  return new Promise((resolve, reject) => {
    execFile(
      binario,
      args,
      {
        timeout: opciones.timeout || 180000,
        maxBuffer: opciones.maxBuffer || 1024 * 1024 * 20,
        cwd: opciones.cwd || process.cwd()
      },
      (error, stdout, stderr) => {
        if (error) {
          if (stdout && stdout.trim()) return resolve(stdout);
          if (opciones.permitirFalloSinSalida) return resolve('');

          const detalles = [
            stderr && stderr.trim(),
            error.message && error.message.trim()
          ].filter(Boolean);

          return reject(new Error(detalles.join('\n') || `${binario} fallo sin salida de error.`));
        }

        resolve(stdout || '');
      }
    );
  });
}

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

function esObjetoVacioDalfox(item) {
  return item &&
    typeof item === 'object' &&
    !Array.isArray(item) &&
    Object.keys(item).length === 0;
}

function normalizarItemsDalfox(parsed) {
  const items = Array.isArray(parsed) ? parsed : [parsed];
  return items
    .flatMap(item => Array.isArray(item) ? item : [item])
    .filter(item => item && typeof item === 'object' && !esObjetoVacioDalfox(item));
}

function parsearDalfox(output) {
  const limpio = limpiarColoresANSI(String(output || '')).trim();
  if (!limpio) return [];

  try {
    return normalizarItemsDalfox(JSON.parse(limpio));
  } catch {
    // Puede venir como JSON lines o con alguna linea no JSON.
  }

  return limpio
    .split('\n')
    .map(linea => linea.trim())
    .filter(Boolean)
    .flatMap(linea => {
      try {
        return normalizarItemsDalfox(JSON.parse(linea));
      } catch {
        return [];
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

  logVar('targetOriginal', targetOriginal);
  logVar('entrada', entrada);
  logVar('target', target);

  const toolResults = {};
  const includeNucleiInfo = process.env.NUCLEI_INCLUDE_INFO === 'true';
  const sqlmapCrawlIfNoParams = process.env.SQLMAP_CRAWL_IF_NO_PARAMS === 'true';
  const timeoutMs = Number(process.env.TOOL_TIMEOUT_SECONDS || 120) * 1000;
  const maxGauUrls = Number(process.env.MAX_GAU_URLS || 500);
  const maxFeroxUrls = Number(process.env.MAX_FEROX_URLS || 100);
  const maxDalfoxUrls = Number(process.env.MAX_DALFOX_URLS || 50);
  const maxSqlmapUrls = Number(process.env.MAX_SQLMAP_URLS || 10);
  const maxJsSecretScan = Number(process.env.MAX_JS_SECRET_SCAN || 20);
  const passiveTimeoutMs = Number(process.env.PASSIVE_TIMEOUT_SECONDS || 8) * 1000;

  async function ejecutarHerramienta(nombre, comando, parser = parsearLineas) {
    try {
      progreso(nombre, 'running', `Ejecutando ${nombre}`);
      registrarPaso(nombre, 'ejecutando herramienta', { entrada: target, comando });
      logVar(`${nombre}.comando`, comando);
      const raw = await ejecutarComando(comando, {
        permitirFalloSinSalida: nombre === 'nuclei'
      });
      logVar(`${nombre}.raw`, raw);
      const parsed = parser(raw);
      logVar(`${nombre}.parsed`, parsed);
      const parsedCount = Array.isArray(parsed) ? parsed.length : 0;
      registrarPaso(nombre, 'resultados producidos', { resultados: parsedCount });

      toolResults[nombre] = {
        status: 'success',
        raw,
        parsed,
        parsed_count: parsedCount,
        findings: []
      };
      logVar(`toolResults.${nombre}`, toolResults[nombre]);
      progreso(nombre, 'done', `${nombre} finalizado`, { count: parsedCount });

      return raw;
    } catch (error) {
      toolResults[nombre] = {
        status: 'error',
        raw: '',
        parsed: [],
        parsed_count: 0,
        findings: [],
        error: error.message
      };
      logVar(`toolResults.${nombre}`, toolResults[nombre]);
      progreso(nombre, 'error', error.message);

      console.error(`Error en ${nombre}:`, error.message);
      return '';
    }
  }

  async function ejecutarHerramientaInput(nombre, binario, args, input, parser = parsearLineas, opciones = {}) {
    try {
      progreso(nombre, 'running', `Ejecutando ${nombre}`);
      registrarPaso(nombre, 'ejecutando herramienta', { entrada: target, binario, args });
      logVar(`${nombre}.binario`, binario);
      logVar(`${nombre}.args`, args);
      logVar(`${nombre}.input`, input);
      const raw = await ejecutarConInput(binario, args, input, {
        timeout: nombre === 'nuclei' ? 0 : timeoutMs,
        permitirFalloSinSalida: nombre === 'nuclei' || opciones.permitirFalloSinSalida
      });
      logVar(`${nombre}.raw`, raw);
      const parsed = parser(raw);
      logVar(`${nombre}.parsed`, parsed);
      const parsedCount = Array.isArray(parsed) ? parsed.length : 0;
      registrarPaso(nombre, 'resultados producidos', { resultados: parsedCount });

      toolResults[nombre] = {
        status: 'success',
        raw,
        parsed,
        findings: []
      };
      logVar(`toolResults.${nombre}`, toolResults[nombre]);
      progreso(nombre, 'done', `${nombre} finalizado`, { count: parsedCount });

      return raw;
    } catch (error) {
      toolResults[nombre] = {
        status: 'error',
        raw: '',
        parsed: [],
        findings: [],
        error: error.message
      };
      logVar(`toolResults.${nombre}`, toolResults[nombre]);
      progreso(nombre, 'error', error.message);

      console.error(`Error en ${nombre}:`, error.message);
      return '';
    }
  }

  async function ejecutarDalfoxPorUrl(urls = []) {
    const urlsValidas = deduplicarUrls(urls);
    const rawPorUrl = {};
    const parsedPorUrl = {};
    const inputPorUrl = {};
    const parsedTotal = [];
    let errores = 0;

    if (urlsValidas.length === 0) {
      const skipped = {
        status: 'skipped',
        raw: '',
        parsed: [],
        findings: [],
        error: 'No hay endpoints con parametros para probar XSS.',
        metrics: {
          urls_analizadas: 0,
          hallazgos: 0,
          confirmadas: 0,
          errores: 0
        }
      };
      logVar('toolResults.dalfox', skipped);
      return skipped;
    }

    progreso('dalfox', 'running', `Ejecutando Dalfox sobre ${urlsValidas.length} URLs`);

    for (const url of urlsValidas) {
      const input = `${url}\n`;
      inputPorUrl[url] = input;
      logVar(`dalfox.inputPorUrl.${url}`, input);

      try {
        registrarPaso('dalfox', 'ejecutando URL individual', { entrada: url });
        const raw = await ejecutarConInput(
          'dalfox',
          ['pipe', '--silence', '--format', 'json'],
          input,
          {
            timeout: timeoutMs,
            permitirFalloSinSalida: true
          }
        );
        const parsed = parsearDalfox(raw);

        rawPorUrl[url] = raw;
        parsedPorUrl[url] = parsed;
        logVar(`dalfox.rawPorUrl.${url}`, raw);
        logVar(`dalfox.parsedPorUrl.${url}`, parsed);

        if (parsed.length > 0) parsedTotal.push(...parsed);
      } catch (error) {
        errores += 1;
        rawPorUrl[url] = '';
        parsedPorUrl[url] = [];
        logVar(`dalfox.errorPorUrl.${url}`, error.message);
        console.error(`Error en dalfox para ${url}:`, error.message);
      }
    }

    const result = {
      status: errores === 0 ? 'success' : parsedTotal.length > 0 ? 'partial' : 'error',
      raw: JSON.stringify(rawPorUrl, null, 2),
      parsed: parsedTotal,
      findings: [],
      error: errores > 0 ? `${errores} ejecuciones de Dalfox fallaron.` : null,
      metrics: {
        urls_analizadas: urlsValidas.length,
        hallazgos: parsedTotal.length,
        confirmadas: parsedTotal.filter(item => String(item.type || '').toUpperCase() === 'V').length,
        errores
      }
    };

    result.findings = extraerFindingsDeterministas('dalfox', result, target);
    logVar('dalfox.inputPorUrl', inputPorUrl);
    logVar('dalfox.rawPorUrl', rawPorUrl);
    logVar('dalfox.parsedPorUrl', parsedPorUrl);
    logVar('dalfox.findingsFinales', result.findings);
    logVar('toolResults.dalfox', result);

    return result;
  }

  registrarPaso('normalizacion', 'entrada normalizada', {
    original: entrada.original,
    dominioLimpio: target,
    urlInicial: entrada.inputUrl
  });
  progreso('normalizacion', 'running', 'Normalizando objetivo');

  const targetLocal = esTargetLocal(target) || esIpV4(target);

  const subfinderOutput = targetLocal
    ? ''
    : await (async () => {
        try {
          progreso('subfinder', 'running', 'Buscando subdominios');
          registrarPaso('subfinder', 'ejecutando herramienta', { entrada: target, binario: 'subfinder' });
          logVar('subfinder.args', ['-d', target, '-silent']);
          const raw = await ejecutarBinario('subfinder', ['-d', target, '-silent'], { timeout: timeoutMs });
          logVar('subfinder.raw', raw);
          toolResults.subfinder = {
            status: 'success',
            raw,
            parsed: parsearLineas(raw),
            findings: []
          };
          logVar('toolResults.subfinder', toolResults.subfinder);
          progreso('subfinder', 'done', 'Subfinder finalizado', { count: toolResults.subfinder.parsed.length });
          return raw;
        } catch (error) {
          toolResults.subfinder = {
            status: 'error',
            raw: '',
            parsed: [],
            findings: [],
            error: error.message
          };
          logVar('toolResults.subfinder', toolResults.subfinder);
          progreso('subfinder', 'error', error.message);
          console.error('Error en subfinder:', error.message);
          return '';
        }
      })();

  if (targetLocal) {
    toolResults.subfinder = {
      status: 'skipped',
      raw: '',
      parsed: [],
      findings: [],
      error: 'subfinder no aplica a targets locales o direcciones IP'
    };
    logVar('toolResults.subfinder', toolResults.subfinder);
    progreso('subfinder', 'skipped', 'Subfinder no aplica a targets locales o IP');
  }

  let subdominios = parsearLineas(subfinderOutput);
  logVar('subfinderOutput', subfinderOutput);

  subdominios = deduplicarUrls([...subdominios, target]);
  logVar('subdominios', subdominios);

  const inputHttpx = deduplicarUrls([...subdominios, entrada.inputUrl, entrada.baseUrl]).join('\n');
  logVar('inputHttpx', inputHttpx);

  const httpxOutput = await ejecutarHerramientaInput(
    'httpx',
    'httpx',
    ['-silent', '-json', '-title', '-status-code', '-tech-detect', '-web-server', '-content-length', '-content-type', '-location', '-follow-redirects', '-no-color'],
    inputHttpx,
    parsearHttpxJson
  );

  let httpx = parsearHttpxJson(httpxOutput);
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

    if (toolResults.httpx) {
      toolResults.httpx.status = 'partial';
      toolResults.httpx.warning = 'httpx no devolvio activos; se usa la URL normalizada como fallback para continuar validaciones HTTP.';
      toolResults.httpx.parsed = httpx;
      toolResults.httpx.parsed_count = httpx.length;
      toolResults.httpx.metrics = {
        ...(toolResults.httpx.metrics || {}),
        activos_vivos: httpx.length,
        fallback: true
      };
    }
    logVar('httpxFallbackUrls', httpxFallbackUrls);
    logVar('toolResults.httpx', toolResults.httpx);
  }
  logVar('httpxOutput', httpxOutput);
  logVar('httpx', httpx);
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

  const katanaOutput = activos.length > 0
    ? await ejecutarHerramientaInput(
        'katana',
        'katana',
        ['-silent', '-depth', '3', '-jc', '-kf', 'all'],
        inputKatana
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
    logVar('toolResults.katana', toolResults.katana);
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
          endpoints_encontrados: 0,
          con_parametros: 0,
          enviados_ia: 0,
          raw_length: 0
        }
      }
    : await ejecutarGau(target, { maxUrls: maxGauUrls, timeoutMs });
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
  const severidadesNuclei = includeNucleiInfo ? 'info,low,medium,high,critical' : 'low,medium,high,critical';
  const excludeTags = 'dns,tech,waf,cdn,favicon';
  logVar('inputNuclei', inputNuclei);
  logVar('severidadesNuclei', severidadesNuclei);
  logVar('excludeTags', excludeTags);

  const nucleiOutput = activos.length > 0
    ? await ejecutarHerramientaInput(
        'nuclei',
        'nuclei',
        ['-severity', severidadesNuclei, '-exclude-tags', excludeTags, '-silent', '-no-color'],
        inputNuclei,
        parsearLineas,
        { permitirFalloSinSalida: true }
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
    logVar('toolResults.nuclei', toolResults.nuclei);
  }

  const vulnerabilidades = parsearLineas(nucleiOutput);
  logVar('nucleiOutput', nucleiOutput);
  logVar('vulnerabilidades', vulnerabilidades);
  registrarPaso('nuclei', 'ruido informativo/fingerprinting descartado por configuracion o clasificador', {
    descartados: contarDescartadosNuclei(vulnerabilidades),
    includeInfo: includeNucleiInfo
  });

  const urlsDalfox = limitarUrls(
    xssDesdeGf.length ? xssDesdeGf : urlsParametrizadas,
    xssDesdeGf.length ? maxDalfoxUrls : Math.min(maxDalfoxUrls, 30)
  );
  logVar('urlsDalfox', urlsDalfox);

  console.log(`[dalfox] URLs recibidas desde gf xss: ${xssDesdeGf.length}`);

  toolResults.dalfox = await ejecutarDalfoxPorUrl(urlsDalfox);
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

  const sqlmap = [];

  for (const url of candidatosSqlmap) {
    try {
      progreso('sqlmap', 'running', `Probando SQLi en ${url}`);
      registrarPaso('sqlmap', 'ejecutando sobre URL parametrizada', { entrada: url });
      const sqlmapOutput = await ejecutarBinario(
        'python3',
        ['tools/sqlmap/sqlmap.py', '-u', url, '--batch', '--random-agent', '--level=1', '--risk=1', '--smart', '--disable-coloring'],
        { timeout: timeoutMs }
      );

      const parsedSqlmap = parsearSqlmap(url, sqlmapOutput);
      logVar(`sqlmapOutput.${url}`, sqlmapOutput);
      logVar(`parsedSqlmap.${url}`, parsedSqlmap);
      sqlmap.push(parsedSqlmap);
    } catch (error) {
      console.error(`Error en sqlmap para ${url}:`, error.message);

      sqlmap.push({
        url,
        vulnerable: false,
        error: error.message,
        evidencia: null,
        resumen: []
      });
      logVar(`sqlmapError.${url}`, error.message);
    }
  }

  if (candidatosSqlmap.length === 0 && sqlmapCrawlIfNoParams && activos.length > 0) {
    for (const url of activos.slice(0, 3)) {
      try {
        registrarPaso('sqlmap', 'sin parametros descubiertos; ejecutando crawl ligero', { entrada: url });
        const sqlmapOutput = await ejecutarBinario(
          'python3',
          ['tools/sqlmap/sqlmap.py', '-u', url, '--crawl=2', '--batch', '--random-agent', '--level=1', '--risk=1', '--smart', '--disable-coloring'],
          { timeout: timeoutMs }
        );
        const parsedSqlmap = parsearSqlmap(url, sqlmapOutput);
        logVar(`sqlmapOutput.${url}`, sqlmapOutput);
        logVar(`parsedSqlmap.${url}`, parsedSqlmap);
        sqlmap.push(parsedSqlmap);
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
  logVar('sqlmap', sqlmap);
  logVar('toolResults.sqlmap', toolResults.sqlmap);
  progreso('sqlmap', toolResults.sqlmap.status || 'done', 'Sqlmap finalizado');

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
  parsearDalfox
};
