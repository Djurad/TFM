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

function parsearLineas(texto = '') {
  return String(texto)
    .split('\n')
    .map(linea => linea.trim())
    .filter(Boolean);
}

async function ejecutarSubfinder(target, opciones = {}) {
  const timeoutMs = Number(opciones.timeoutMs || 180000);
  const targetLocal = Boolean(opciones.targetLocal);
  const logVar = typeof opciones.logVar === 'function' ? opciones.logVar : () => {};
  const registrarPaso = typeof opciones.registrarPaso === 'function' ? opciones.registrarPaso : () => {};
  const progreso = typeof opciones.progreso === 'function' ? opciones.progreso : () => {};

  if (targetLocal) {
    const result = {
      status: 'skipped',
      raw: '',
      parsed: [],
      findings: [],
      error: 'subfinder no aplica a targets locales o direcciones IP'
    };
    logVar('toolResults.subfinder', result);
    progreso('subfinder', 'skipped', 'Subfinder no aplica a targets locales o IP');
    return result;
  }

  try {
    progreso('subfinder', 'running', 'Buscando subdominios');
    registrarPaso('subfinder', 'ejecutando herramienta', { entrada: target, binario: 'subfinder' });
    logVar('subfinder.args', ['-d', target, '-silent']);
    const raw = await ejecutarBinario('subfinder', ['-d', target, '-silent'], { timeout: timeoutMs });
    const result = {
      status: 'success',
      raw,
      parsed: parsearLineas(raw),
      findings: []
    };
    logVar('subfinder.raw', raw);
    logVar('toolResults.subfinder', result);
    progreso('subfinder', 'done', 'Subfinder finalizado', { count: result.parsed.length });
    return result;
  } catch (error) {
    const result = {
      status: 'error',
      raw: '',
      parsed: [],
      findings: [],
      error: error.message
    };
    logVar('toolResults.subfinder', result);
    progreso('subfinder', 'error', error.message);
    console.error('Error en subfinder:', error.message);
    return result;
  }
}

module.exports = {
  ejecutarSubfinder
};
