const { spawn } = require('child_process');
const { extraerFindingsDeterministas } = require('../../procesamiento/extractores');

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

function deduplicarUrls(urls) {
  return Array.from(new Set(urls));
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

function esDalfoxConfirmado(item = {}) {
  const tipo = String(item.type || item.severity || '').trim().toUpperCase();
  const evidencia = [
    item.message_str,
    item.message,
    item.evidence,
    item.payload,
    item.poc,
    item.data
  ].filter(Boolean).join(' ');

  return tipo === 'V' ||
    item.vulnerable === true ||
    /triggered\s+xss\s+payload|found\s+dom\s+object|verified\s+xss|\bVULN\b/i.test(evidencia);
}

function construirIntentoDalfox(url, intento = 0) {
  if (intento % 2 === 0) {
    return {
      modo: 'url',
      args: ['url', url, '--silence', '--format', 'json'],
      input: ''
    };
  }

  return {
    modo: 'pipe',
    args: ['pipe', '--silence', '--format', 'json'],
    input: `${url}\n`
  };
}

async function ejecutarDalfox(urls = [], opciones = {}) {
  const urlsValidas = deduplicarUrls(urls);
  const timeoutMs = Number(opciones.timeoutMs || 180000);
  const target = opciones.target || '';
  const logVar = typeof opciones.logVar === 'function' ? opciones.logVar : () => {};
  const registrarPaso = typeof opciones.registrarPaso === 'function' ? opciones.registrarPaso : () => {};
  const progreso = typeof opciones.progreso === 'function' ? opciones.progreso : () => {};
  const rawPorUrl = {};
  const parsedPorUrl = {};
  const inputPorUrl = {};
  const rawIntentosPorUrl = {};
  const parsedIntentosPorUrl = {};
  const argsPorUrl = {};
  const timeoutPorUrl = {};
  const parsedTotal = [];
  let errores = 0;
  let reintentos = 0;
  const maxReintentos = Number(process.env.DALFOX_RETRIES || 1);

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
        errores: 0,
        reintentos: 0
      }
    };
    logVar('toolResults.dalfox', skipped);
    return skipped;
  }

  progreso('dalfox', 'running', `Ejecutando Dalfox sobre ${urlsValidas.length} URLs`);

  for (const url of urlsValidas) {
    inputPorUrl[url] = [];
    argsPorUrl[url] = [];
    timeoutPorUrl[url] = timeoutMs;
    logVar(`dalfox.binarioPorUrl.${url}`, 'dalfox');
    logVar(`dalfox.timeoutPorUrl.${url}`, timeoutMs);

    for (let intento = 0; intento <= maxReintentos; intento += 1) {
      try {
        if (intento > 0) reintentos += 1;
        const estrategia = construirIntentoDalfox(url, intento);
        inputPorUrl[url].push(estrategia.input);
        argsPorUrl[url].push(estrategia.args);
        logVar(`dalfox.modoPorUrl.${url}.intento${intento + 1}`, estrategia.modo);
        logVar(`dalfox.inputPorUrl.${url}.intento${intento + 1}`, estrategia.input || '(URL enviada como argumento)');
        logVar(`dalfox.argsPorUrl.${url}.intento${intento + 1}`, estrategia.args);
        registrarPaso('dalfox', 'ejecutando URL individual', {
          entrada: url,
          intento: intento + 1,
          maxIntentos: maxReintentos + 1,
          modo: estrategia.modo,
          args: estrategia.args,
          timeoutMs
        });
        const raw = await ejecutarConInput(
          'dalfox',
          estrategia.args,
          estrategia.input,
          {
            timeout: timeoutMs,
            permitirFalloSinSalida: true
          }
        );
        const parsed = parsearDalfox(raw);

        rawIntentosPorUrl[url] = rawIntentosPorUrl[url] || [];
        parsedIntentosPorUrl[url] = parsedIntentosPorUrl[url] || [];
        rawIntentosPorUrl[url].push(raw);
        parsedIntentosPorUrl[url].push(parsed);
        rawPorUrl[url] = raw;
        parsedPorUrl[url] = parsed;
        logVar(`dalfox.rawPorUrl.${url}.intento${intento + 1}`, raw);
        logVar(`dalfox.parsedPorUrl.${url}.intento${intento + 1}`, parsed);

        if (parsed.length > 0) {
          parsedTotal.push(...parsed);
          break;
        }

        if (intento >= maxReintentos) break;
        registrarPaso('dalfox', 'sin hallazgos en intento; reintentando URL individual', {
          entrada: url,
          siguienteModo: construirIntentoDalfox(url, intento + 1).modo,
          rawLength: raw.length,
          parsed: parsed.length
        });
      } catch (error) {
        errores += 1;
        rawPorUrl[url] = rawPorUrl[url] || '';
        parsedPorUrl[url] = parsedPorUrl[url] || [];
        logVar(`dalfox.errorPorUrl.${url}.intento${intento + 1}`, error.message);
        console.error(`Error en dalfox para ${url}:`, error.message);
        if (intento < maxReintentos) {
          registrarPaso('dalfox', 'modo de ejecucion fallido; probando fallback', {
            entrada: url,
            error: error.message,
            siguienteModo: construirIntentoDalfox(url, intento + 1).modo
          });
          continue;
        }
        break;
      }
    }

    logVar(`dalfox.rawPorUrl.${url}`, rawPorUrl[url] || '');
    logVar(`dalfox.parsedPorUrl.${url}`, parsedPorUrl[url] || []);
  }

  const confirmados = parsedTotal.filter(esDalfoxConfirmado);
  const posibles = parsedTotal.filter(item => !esDalfoxConfirmado(item));
  console.log(`[DALFOX-PARSE] rawFindings=${parsedTotal.length} confirmedXss=${confirmados.length} possibleXss=${posibles.length}`);
  registrarPaso('dalfox', 'parse finalizado', {
    rawFindings: parsedTotal.length,
    confirmedXss: confirmados.length,
    possibleXss: posibles.length
  });

  const result = {
    status: errores === 0 ? 'success' : parsedTotal.length > 0 ? 'partial' : 'error',
    raw: JSON.stringify(rawPorUrl, null, 2),
    parsed: parsedTotal,
    findings: [],
    error: errores > 0 ? `${errores} ejecuciones de Dalfox fallaron.` : null,
    metrics: {
      urls_analizadas: urlsValidas.length,
      hallazgos: parsedTotal.length,
      confirmadas: confirmados.length,
      posibles: posibles.length,
      errores,
      reintentos,
      max_reintentos_por_url: maxReintentos,
      comando: 'dalfox url <URL> --silence --format json; fallback dalfox pipe',
      timeout_ms: timeoutMs
    }
  };

  result.findings = extraerFindingsDeterministas('dalfox', result, target);
  logVar('dalfox.inputPorUrl', inputPorUrl);
  logVar('dalfox.argsPorUrl', argsPorUrl);
  logVar('dalfox.timeoutPorUrl', timeoutPorUrl);
  logVar('dalfox.rawPorUrl', rawPorUrl);
  logVar('dalfox.rawIntentosPorUrl', rawIntentosPorUrl);
  logVar('dalfox.parsedPorUrl', parsedPorUrl);
  logVar('dalfox.parsedIntentosPorUrl', parsedIntentosPorUrl);
  logVar('dalfox.findingsFinales', result.findings);
  logVar('toolResults.dalfox', result);

  return result;
}

module.exports = {
  construirIntentoDalfox,
  ejecutarDalfox,
  esDalfoxConfirmado,
  parsearDalfox
};
