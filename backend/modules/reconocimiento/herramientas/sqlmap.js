const { execFile } = require('child_process');

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

function limpiarColoresANSI(texto = '') {
  return String(texto).replace(/\x1B\[[0-9;]*m/g, '');
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

async function ejecutarSqlmap(candidatosSqlmap = [], opciones = {}) {
  const activos = Array.isArray(opciones.activos) ? opciones.activos : [];
  const timeoutMs = Number(opciones.timeoutMs || 180000);
  const sqlmapCrawlIfNoParams = Boolean(opciones.sqlmapCrawlIfNoParams);
  const logVar = typeof opciones.logVar === 'function' ? opciones.logVar : () => {};
  const registrarPaso = typeof opciones.registrarPaso === 'function' ? opciones.registrarPaso : () => {};
  const progreso = typeof opciones.progreso === 'function' ? opciones.progreso : () => {};
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

  const result = {
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
  logVar('toolResults.sqlmap', result);

  return result;
}

module.exports = {
  ejecutarSqlmap,
  normalizarUrlParaSqlmap,
  parsearSqlmap
};
