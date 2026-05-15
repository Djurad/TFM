const { exec } = require('child_process');

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
    .replace(/\/$/, '')
    .trim();
}

function validarTarget(target) {
  const regex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return regex.test(target);
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

  const parametrosSQLi = [
    'id',
    'user',
    'username',
    'account',
    'search',
    'query',
    'q',
    'name',
    'category',
    'cat',
    'product',
    'item',
    'page',
    'step',
    'job'
  ];

  return parametros.some(p => parametrosSQLi.includes(p));
}

function parsearHttpxJson(output) {
  return parsearLineas(output)
    .map(linea => {
      try {
        const item = JSON.parse(linea);

        return {
          url: item.url || item.input || null,
          input: item.input || null,
          statusCode: item.status_code || null,
          title: item.title || null,
          tecnologias: item.tech || [],
          webserver: item.webserver || null,
          contentLength: item.content_length || null,
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

  const vulnerable =
    limpio.includes('is vulnerable') ||
    limpio.includes('sqlmap identified the following injection point') ||
    limpio.includes('Parameter:');

  return {
    url,
    vulnerable,
    evidencia: vulnerable ? 'SQL Injection detectada por sqlmap' : null,
    resumen: vulnerable
      ? limpio
          .split('\n')
          .filter(linea =>
            linea.includes('Parameter:') ||
            linea.includes('Type:') ||
            linea.includes('Title:') ||
            linea.includes('Payload:')
          )
          .map(linea => linea.trim())
      : []
  };
}

async function ejecutarReconocimiento(targetOriginal) {
  const target = limpiarTarget(targetOriginal);

  if (!validarTarget(target)) {
    throw new Error('Target no valido. Usa un dominio, por ejemplo: testphp.vulnweb.com');
  }

  const toolResults = {};

  async function ejecutarHerramienta(nombre, comando, parser = parsearLineas) {
    try {
      const raw = await ejecutarComando(comando, {
        permitirFalloSinSalida: nombre === 'nuclei'
      });
      const parsed = parser(raw);

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

  const subfinderOutput = await ejecutarHerramienta(
    'subfinder',
    `subfinder -d ${target} -silent`
  );

  let subdominios = parsearLineas(subfinderOutput);

  if (subdominios.length === 0) {
    subdominios = [target];
  }

  const inputHttpx = subdominios.join('\n');

  const httpxOutput = await ejecutarHerramienta(
    'httpx',
    `printf "%s\n" "${inputHttpx}" | httpx -silent -json -title -status-code -tech-detect -web-server -content-length -location -follow-redirects -no-color`,
    parsearHttpxJson
  );

  const httpx = parsearHttpxJson(httpxOutput);
  const activos = httpx.map(item => item.url).filter(Boolean);
  const inputKatana = activos.join('\n');

  const katanaOutput = activos.length > 0
    ? await ejecutarHerramienta(
        'katana',
        `printf "%s\n" "${inputKatana}" | katana -silent -depth 3`
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

  const endpoints = parsearLineas(katanaOutput);
  const inputNuclei = activos.join('\n');

  const nucleiOutput = activos.length > 0
    ? await ejecutarHerramienta(
        'nuclei',
        `printf "%s\n" "${inputNuclei}" | nuclei -severity info,low,medium,high,critical -silent -timeout 10 -no-color`
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
  const endpointsConParametros = endpoints.filter(tieneParametros);
  const inputDalfox = endpointsConParametros.join('\n');

  const dalfoxOutput = endpointsConParametros.length > 0
    ? await ejecutarHerramienta(
        'dalfox',
        `printf "%s\n" "${inputDalfox}" | dalfox pipe --silence --format json`,
        parsearDalfox
      )
    : '';

  if (endpointsConParametros.length === 0) {
    toolResults.dalfox = {
      status: 'skipped',
      raw: '',
      parsed: [],
      findings: [],
      error: 'No hay endpoints con parametros para probar XSS.'
    };
  }

  const dalfox = parsearDalfox(dalfoxOutput);

  const candidatosSqlmap = endpoints
    .filter(tieneParametros)
    .filter(esCandidatoSqlmap)
    .slice(0, 10);

  const sqlmap = [];

  for (const url of candidatosSqlmap) {
    try {
      const sqlmapOutput = await ejecutarComando(
        `python3 tools/sqlmap/sqlmap.py -u "${url}" --batch --level=1 --risk=1 --smart --disable-coloring`
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

  toolResults.sqlmap = {
    status: sqlmap.some(item => item.error) ? 'partial' : 'success',
    raw: JSON.stringify(sqlmap, null, 2),
    parsed: sqlmap,
    findings: []
  };

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
      sqlmap
    }
  };
}

module.exports = {
  ejecutarReconocimiento
};
