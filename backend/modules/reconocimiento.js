const { exec } = require('child_process');

function ejecutarComando(comando) {
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
          return reject(new Error(stderr || error.message));
        }

        resolve(stdout);
      }
    );
  });
}

function limpiarColoresANSI(texto) {
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

function parsearLineas(texto) {
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
    throw new Error('Target no válido. Usa un dominio, por ejemplo: testphp.vulnweb.com');
  }

  const subfinderOutput = await ejecutarComando(
    `subfinder -d ${target} -silent`
  );

  let subdominios = parsearLineas(subfinderOutput);

  if (subdominios.length === 0) {
    subdominios = [target];
  }

  const inputHttpx = subdominios.join('\n');

  const httpxOutput = await ejecutarComando(
    `printf "%s\n" "${inputHttpx}" | httpx -silent -json -title -status-code -tech-detect -web-server -content-length -location -follow-redirects -no-color`
  );

  const httpx = parsearHttpxJson(httpxOutput);

  const activos = httpx
    .map(item => item.url)
    .filter(Boolean);

  const inputKatana = activos.join('\n');

  const katanaOutput = activos.length > 0
    ? await ejecutarComando(
        `printf "%s\n" "${inputKatana}" | katana -silent -depth 3`
      )
    : '';

  const endpoints = parsearLineas(katanaOutput);

  const inputNuclei = activos.join('\n');

  let nucleiOutput = '';

  if (activos.length > 0) {
    try {
      nucleiOutput = await ejecutarComando(
        `printf "%s\n" "${inputNuclei}" | nuclei -severity info,low,medium,high,critical -silent -timeout 10`
      );
    } catch (error) {
      console.error('Error en Nuclei:', error.message);
      nucleiOutput = '';
    }
  }

  const vulnerabilidades = parsearLineas(nucleiOutput);

  const endpointsConParametros = endpoints.filter(tieneParametros);
  const inputDalfox = endpointsConParametros.join('\n');

  let dalfoxOutput = '';

  if (endpointsConParametros.length > 0) {
    try {
      dalfoxOutput = await ejecutarComando(
        `printf "%s\n" "${inputDalfox}" | dalfox pipe --silence --format json`
      );
    } catch (error) {
      console.error('Error en Dalfox:', error.message);
      dalfoxOutput = '';
    }
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

  return {
    target,
    fecha: new Date().toISOString(),
    subdominios,
    activos,
    endpoints,
    vulnerabilidades,
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