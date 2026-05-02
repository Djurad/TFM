const { exec } = require('child_process');

// Ejecuta comandos de terminal y devuelve su salida como una promesa.
function ejecutarComando(comando) {
  return new Promise((resolve, reject) => {
    exec(
      comando,
      {
        // Tiempo máximo de ejecución: 3 minutos.
        timeout: 180000,
        // Tamaño máximo de salida permitido: 20 MB.
        maxBuffer: 1024 * 1024 * 20
      },
      (error, stdout, stderr) => {
        if (error) {
          // Algunas herramientas devuelven código de error aunque generen resultados útiles.
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

// Elimina códigos ANSI de color/formato que pueden aparecer en la salida de consola.
function limpiarColoresANSI(texto) {
  return texto.replace(/\x1B\[[0-9;]*m/g, '');
}

// Normaliza el objetivo recibido eliminando protocolo, barra final y espacios.
function limpiarTarget(target) {
  return target
    .replace(/^https?:\/\//, '')
    .replace(/\/$/, '')
    .trim();
}

// Valida que el objetivo tenga formato de dominio.
function validarTarget(target) {
  const regex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return regex.test(target);
}

// Convierte la salida de una herramienta en un array de líneas limpias.
function parsearLineas(texto) {
  return limpiarColoresANSI(texto)
    .split('\n')
    .map(linea => linea.trim())
    .filter(Boolean);
}

// Ejecuta el flujo completo de reconocimiento sobre un dominio.
async function ejecutarReconocimiento(targetOriginal) {
  const target = limpiarTarget(targetOriginal);

  // Se detiene el proceso si el dominio introducido no es válido.
  if (!validarTarget(target)) {
    throw new Error('Target no válido. Usa un dominio, por ejemplo: testphp.vulnweb.com');
  }

  // Busca subdominios del dominio objetivo usando subfinder.
  const subfinderOutput = await ejecutarComando(
    `subfinder -d ${target} -silent`
  );

  let subdominios = parsearLineas(subfinderOutput);

  // Si no se encuentran subdominios, se usa el propio dominio como objetivo.
  if (subdominios.length === 0) {
    subdominios = [target];
  }

  const inputHttpx = subdominios.join('\n');

  // Comprueba qué subdominios están activos y obtiene información básica de cada uno.
  const httpxOutput = await ejecutarComando(
    `printf "%s\n" "${inputHttpx}" | httpx -silent -title -status-code -tech-detect -no-color`
  );

  const activosRaw = parsearLineas(httpxOutput);

  // Extrae únicamente la URL o host activo de cada línea devuelta por httpx.
  const activos = activosRaw.map(linea => linea.split(' ')[0]);

  const inputKatana = activos.join('\n');

  // Rastrea endpoints de los hosts activos usando katana.
  const katanaOutput = activos.length > 0
    ? await ejecutarComando(
        `printf "%s\n" "${inputKatana}" | katana -silent -depth 3`
      )
    : '';

  const endpoints = parsearLineas(katanaOutput);

  const inputNuclei = activos.join('\n');

let nucleiOutput = '';

// Ejecuta nuclei sobre los hosts activos para detectar posibles hallazgos o vulnerabilidades.
if (activos.length > 0) {
  try {
    nucleiOutput = await ejecutarComando(
      `printf "%s\n" "${inputNuclei}" | nuclei -severity info,low,medium,high,critical -silent -timeout 10`
    );
  } catch (error) {
    // Si nuclei falla, se registra el error y el reconocimiento continúa.
    console.error('Error en Nuclei:', error.message);
    nucleiOutput = '';
  }
}

const vulnerabilidades = parsearLineas(nucleiOutput);

  // Devuelve todos los resultados agrupados junto con la fecha del análisis.
  return {
    target,
    fecha: new Date().toISOString(),
    subdominios,
    activos,
    endpoints,
    vulnerabilidades
  };
}

// Exporta la función principal para poder usarla desde otros módulos del backend.
module.exports = {
  ejecutarReconocimiento
};
