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

function contarDescartadosNuclei(lineas = []) {
  return lineas.filter(linea => {
    const lower = String(linea).toLowerCase();
    try {
      const item = JSON.parse(linea);
      const severity = String(item.info?.severity || item.severity || '').toLowerCase();
      const tags = Array.isArray(item.info?.tags)
        ? item.info.tags.join(',')
        : String(item.info?.tags || '');
      const template = String(item['template-id'] || item.templateID || item.template_id || '');
      const texto = `${severity} ${tags} ${template}`.toLowerCase();
      return severity === 'info' ||
        texto.includes('waf') ||
        texto.includes('wildcard-dns') ||
        texto.includes('tech') ||
        texto.includes('favicon') ||
        texto.includes('cdn');
    } catch {
      // Se mantiene el conteo para salida de texto.
    }

    return lower.includes('[info]') ||
      lower.includes('waf-detect') ||
      lower.includes('wildcard-dns-detect') ||
      lower.includes('tech-detect') ||
      lower.includes('favicon') ||
      lower.includes('cdn');
  }).length;
}

function parsearNucleiJsonl(output = '') {
  return parsearLineas(output).map(linea => {
    try {
      const item = JSON.parse(linea);
      return JSON.stringify(item);
    } catch {
      return linea;
    }
  });
}

function construirArgsNuclei() {
  const includeInfo = process.env.NUCLEI_INCLUDE_INFO === 'true';
  const severidades = process.env.NUCLEI_SEVERITIES ||
    (includeInfo ? 'info,low,medium,high,critical' : 'critical,high,medium,low');
  const args = ['-jsonl', '-silent', '-no-color', '-severity', severidades];
  const templatesPath = process.env.NUCLEI_TEMPLATES_PATH;
  const tags = process.env.NUCLEI_TAGS;
  const rateLimit = process.env.NUCLEI_RATE_LIMIT;
  const timeoutSeconds = process.env.NUCLEI_TIMEOUT_SECONDS;

  if (templatesPath) args.push('-t', templatesPath);
  if (tags) args.push('-tags', tags);
  if (!includeInfo) args.push('-exclude-tags', 'dns,tech,waf,cdn,favicon');
  if (rateLimit) args.push('-rl', rateLimit);
  if (timeoutSeconds) args.push('-timeout', timeoutSeconds);

  return {
    args,
    severidades,
    includeInfo,
    templatesPath: templatesPath || 'templates oficiales instaladas localmente',
    tags: tags || '',
    excludeTags: includeInfo ? '' : 'dns,tech,waf,cdn,favicon',
    rateLimit: rateLimit || '',
    timeoutSeconds: timeoutSeconds || ''
  };
}

async function ejecutarNuclei(activos = [], opciones = {}) {
  const targets = Array.isArray(activos) ? activos.filter(Boolean) : [];
  const timeoutMs = Number(opciones.timeoutMs || 180000);
  const input = targets.join('\n');
  const config = construirArgsNuclei();

  if (targets.length === 0) {
    return {
      status: 'skipped',
      raw: '',
      parsed: [],
      parsed_count: 0,
      findings: [],
      error: 'No hay activos HTTP para analizar con nuclei.',
      config,
      metrics: {
        targets: 0,
        raw_lineas: 0,
        parsed_findings: 0,
        templates_path: config.templatesPath,
        severities: config.severidades,
        tags: config.tags,
        exclude_tags: config.excludeTags,
        include_info: config.includeInfo,
        rate_limit: config.rateLimit,
        timeout_seconds: config.timeoutSeconds
      }
    };
  }

  try {
    const raw = await ejecutarConInput('nuclei', config.args, input, {
      timeout: 0,
      permitirFalloSinSalida: true,
      maxBuffer: opciones.maxBuffer || 1024 * 1024 * 20
    });
    const parsed = parsearNucleiJsonl(raw);

    return {
      status: 'success',
      raw,
      parsed,
      parsed_count: parsed.length,
      findings: [],
      config,
      metrics: {
        targets: targets.length,
        raw_lineas: parsearLineas(raw).length,
        parsed_findings: parsed.length,
        templates_path: config.templatesPath,
        severities: config.severidades,
        tags: config.tags,
        exclude_tags: config.excludeTags,
        include_info: config.includeInfo,
        rate_limit: config.rateLimit,
        timeout_seconds: config.timeoutSeconds,
        timeout_ms: timeoutMs
      }
    };
  } catch (error) {
    return {
      status: 'error',
      raw: '',
      parsed: [],
      parsed_count: 0,
      findings: [],
      error: error.message,
      config,
      metrics: {
        targets: targets.length,
        raw_lineas: 0,
        parsed_findings: 0,
        templates_path: config.templatesPath,
        severities: config.severidades,
        tags: config.tags,
        exclude_tags: config.excludeTags,
        include_info: config.includeInfo,
        rate_limit: config.rateLimit,
        timeout_seconds: config.timeoutSeconds,
        timeout_ms: timeoutMs
      }
    };
  }
}

module.exports = {
  ejecutarNuclei,
  construirArgsNuclei,
  contarDescartadosNuclei,
  parsearNucleiJsonl
};
