const fs = require('fs');
const path = require('path');

const MAX_BLOCK_CHARS = Number(process.env.LOG_MAX_BLOCK_CHARS || 50000);

function asegurarDirectorioLogs() {
  const dir = path.join(__dirname, '..', 'logs');
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function siguienteArchivoLog() {
  const dir = asegurarDirectorioLogs();
  let index = 1;

  while (fs.existsSync(path.join(dir, `log${index}.txt`))) {
    index += 1;
  }

  return path.join(dir, `log${index}.txt`);
}

function limitarTexto(valor, max = MAX_BLOCK_CHARS) {
  const texto = typeof valor === 'string' ? valor : JSON.stringify(valor ?? null, null, 2);
  if (texto.length <= max) return texto;
  return `${texto.slice(0, max)}\n...[TRUNCADO: ${texto.length - max} caracteres restantes]`;
}

function contarParsed(parsed) {
  if (Array.isArray(parsed)) return parsed.length;
  if (parsed && typeof parsed === 'object') {
    return Object.fromEntries(
      Object.entries(parsed).map(([key, value]) => [
        key,
        Array.isArray(value) ? value.length : value && typeof value === 'object' ? Object.keys(value).length : value
      ])
    );
  }
  return parsed === undefined || parsed === null ? 0 : 1;
}

function toolDesdeVariable(name = '') {
  const directToolResult = name.match(/^toolResults\.([^.]+)$/);
  if (directToolResult) return directToolResult[1];

  const directToolField = name.match(/^([a-zA-Z][a-zA-Z0-9]*?)\.(binario|args|comando|input|raw|parsed)$/);
  if (directToolField) return directToolField[1];

  const resultName = name.match(/^([a-zA-Z][a-zA-Z0-9]*?)Result$/);
  if (resultName) return resultName[1];

  const outputName = name.match(/^([a-zA-Z][a-zA-Z0-9]*?)Output$/);
  if (outputName) return outputName[1];

  return null;
}

function tituloVariable(name = '') {
  const field = name.split('.').pop();

  if (name.startsWith('toolResults.')) return `${name} - resultado final guardado por el backend`;
  if (field === 'binario') return `${name} - binario ejecutado`;
  if (field === 'args') return `${name} - argumentos enviados`;
  if (field === 'comando') return `${name} - comando ejecutado`;
  if (field === 'input') return `${name} - datos enviados a la herramienta`;
  if (field === 'raw' || name.endsWith('Output')) return `${name} - salida bruta`;
  if (field === 'parsed') return `${name} - salida parseada por el backend`;
  if (name.endsWith('Result')) return `${name} - objeto devuelto por el modulo`;
  return name;
}

function crearScanLogger(target) {
  const file = siguienteArchivoLog();
  const startedAt = new Date().toISOString();
  let currentTool = null;

  function append(text = '') {
    fs.appendFileSync(file, `${text}\n`, 'utf8');
  }

  function section(title, data = null) {
    append('');
    append(`========== ${title} ==========`);
    if (data !== null && data !== undefined) append(limitarTexto(data));
  }

  function progress(tool, status, message, extra = {}) {
    if (status === 'running') return;

    const limpio = Object.fromEntries(
      Object.entries(extra).filter(([, value]) => value !== null && value !== undefined)
    );

    if (!Object.keys(limpio).length && !message) return;

    append('');
    append(`========== EVENTO ${tool} ${status} ==========`);
    append(limitarTexto({
      tool,
      status,
      message,
      ...limpio
    }, 8000));
  }

  function json(title, data = {}) {
    section(title, data);
  }

  function variable(name, value) {
    const tool = toolDesdeVariable(name);

    if (tool && tool !== currentTool) {
      currentTool = tool;
      append('');
      append('');
      append('############################################################');
      append(`# HERRAMIENTA / MODULO: ${tool}`);
      append('############################################################');
      append('Orden de lectura: programa/argumentos -> datos enviados -> salida bruta -> salida parseada -> toolResults final.');
    } else if (!tool && currentTool) {
      currentTool = null;
      append('');
      append('');
      append('############################################################');
      append('# VARIABLES GLOBALES / TRANSFORMACIONES DEL PIPELINE');
      append('############################################################');
    }

    section(tituloVariable(name), value);
  }

  function toolResult(tool, result = {}) {
    section(`HERRAMIENTA: ${tool}`, {
      status: result.status || 'unknown',
      error: result.error || null,
      warning: result.warning || null,
      parsed_count: contarParsed(result.parsed),
      raw_length: typeof result.raw === 'string' ? result.raw.length : 0,
      metrics: result.metrics || {}
    });

    append('');
    append(`--- ${tool} PARSED ---`);
    append(limitarTexto(result.parsed));

    append('');
    append(`--- ${tool} RAW ---`);
    append(limitarTexto(result.raw || ''));
  }

  append(`SCAN LOG`);
  append(`created_at: ${startedAt}`);
  append(`target_input: ${target}`);
  append(`file: ${file}`);
  append('');
  append('COMO LEER ESTE LOG');
  append('- Los nombres de bloque son variables reales del codigo.');
  append('- *.binario indica el programa ejecutado.');
  append('- *.args indica los argumentos enviados al programa.');
  append('- *.input indica los datos enviados a la herramienta.');
  append('- *.raw o *Output es salida bruta.');
  append('- *.parsed es la salida parseada por el backend.');
  append('- toolResults.* es el objeto final que el backend conserva para esa herramienta.');

  return {
    file,
    progress,
    section,
    json,
    variable,
    toolResult,
    error(error) {
      section('ERROR FINAL', {
        message: error?.message || String(error),
        stack: error?.stack || null
      });
    },
    done() {
      section('FIN', {
        started_at: startedAt,
        finished_at: new Date().toISOString()
      });
    }
  };
}

module.exports = {
  crearScanLogger
};
