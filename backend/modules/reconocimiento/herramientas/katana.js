const { spawn } = require('child_process');

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

function parsearLineas(texto = '') {
  return limpiarColoresANSI(texto)
    .split('\n')
    .map(linea => linea.trim())
    .filter(Boolean);
}

async function ejecutarKatana(activos = [], opciones = {}) {
  const targets = Array.isArray(activos) ? activos.filter(Boolean) : [];
  const timeoutMs = Number(opciones.timeoutMs || 180000);
  const input = targets.join('\n');
  const args = ['-silent', '-depth', '3', '-jc', '-kf', 'all'];
  const logVar = typeof opciones.logVar === 'function' ? opciones.logVar : () => {};
  const registrarPaso = typeof opciones.registrarPaso === 'function' ? opciones.registrarPaso : () => {};
  const progreso = typeof opciones.progreso === 'function' ? opciones.progreso : () => {};

  if (targets.length === 0) {
    const result = {
      status: 'skipped',
      raw: '',
      parsed: [],
      parsed_count: 0,
      findings: [],
      error: 'No hay activos HTTP para rastrear.'
    };
    logVar('toolResults.katana', result);
    return result;
  }

  try {
    progreso('katana', 'running', 'Ejecutando katana');
    registrarPaso('katana', 'ejecutando herramienta', { entrada: opciones.target || '', binario: 'katana', args });
    logVar('katana.binario', 'katana');
    logVar('katana.args', args);
    logVar('katana.input', input);
    const raw = await ejecutarConInput('katana', args, input, { timeout: timeoutMs });
    const parsed = parsearLineas(raw);
    const result = {
      status: 'success',
      raw,
      parsed,
      parsed_count: parsed.length,
      findings: []
    };
    logVar('katana.raw', raw);
    logVar('katana.parsed', parsed);
    logVar('toolResults.katana', result);
    progreso('katana', 'done', 'katana finalizado', { count: parsed.length });
    return result;
  } catch (error) {
    const result = {
      status: 'error',
      raw: '',
      parsed: [],
      parsed_count: 0,
      findings: [],
      error: error.message
    };
    logVar('toolResults.katana', result);
    progreso('katana', 'error', error.message);
    console.error('Error en katana:', error.message);
    return result;
  }
}

module.exports = {
  ejecutarKatana
};
