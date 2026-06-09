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
  const dalfoxArgs = ['pipe', '--silence', '--format', 'json'];

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
    const input = `${url}\n`;
    inputPorUrl[url] = input;
    argsPorUrl[url] = dalfoxArgs;
    timeoutPorUrl[url] = timeoutMs;
    logVar(`dalfox.inputPorUrl.${url}`, input);
    logVar(`dalfox.binarioPorUrl.${url}`, 'dalfox');
    logVar(`dalfox.argsPorUrl.${url}`, dalfoxArgs);
    logVar(`dalfox.timeoutPorUrl.${url}`, timeoutMs);

    for (let intento = 0; intento <= maxReintentos; intento += 1) {
      try {
        if (intento > 0) reintentos += 1;
        registrarPaso('dalfox', 'ejecutando URL individual', {
          entrada: url,
          intento: intento + 1,
          maxIntentos: maxReintentos + 1,
          args: dalfoxArgs,
          timeoutMs
        });
        const raw = await ejecutarConInput(
          'dalfox',
          dalfoxArgs,
          input,
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
          rawLength: raw.length,
          parsed: parsed.length
        });
      } catch (error) {
        errores += 1;
        rawPorUrl[url] = rawPorUrl[url] || '';
        parsedPorUrl[url] = parsedPorUrl[url] || [];
        logVar(`dalfox.errorPorUrl.${url}.intento${intento + 1}`, error.message);
        console.error(`Error en dalfox para ${url}:`, error.message);
        break;
      }
    }

    logVar(`dalfox.rawPorUrl.${url}`, rawPorUrl[url] || '');
    logVar(`dalfox.parsedPorUrl.${url}`, parsedPorUrl[url] || []);
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
      errores,
      reintentos,
      max_reintentos_por_url: maxReintentos,
      comando: 'dalfox pipe --silence --format json',
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
  ejecutarDalfox,
  parsearDalfox
};
