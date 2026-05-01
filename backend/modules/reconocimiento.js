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
          if (stdout && stdout.trim()) {
            return resolve(stdout);
          }

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
    `printf "%s\n" "${inputHttpx}" | httpx -silent -title -status-code -tech-detect -no-color`
  );

  const activosRaw = parsearLineas(httpxOutput);

  const activos = activosRaw.map(linea => linea.split(' ')[0]);

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

  return {
    target,
    fecha: new Date().toISOString(),
    subdominios,
    activos,
    endpoints,
    vulnerabilidades
  };
}

module.exports = {
  ejecutarReconocimiento
};