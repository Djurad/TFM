const { execFile } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const zlib = require('zlib');

function ejecutar(args, timeoutMs) {
  return new Promise((resolve, reject) => {
    execFile('trufflehog', args, {
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024 * 20,
      env: {
        ...process.env,
        TRUFFLEHOG_NO_UPDATE: 'true'
      }
    }, (error, stdout, stderr) => {
      if (error) {
        if (stdout && stdout.trim()) return resolve(stdout);
        reject(new Error([stderr, error.message].filter(Boolean).join('\n') || 'trufflehog fallo.'));
        return;
      }
      resolve(stdout || '');
    });
  });
}

function esErrorNoUpdateNoSoportado(error) {
  const msg = String(error?.message || '').toLowerCase();
  return msg.includes('unknown flag') ||
    msg.includes('flag provided but not defined') ||
    msg.includes('no-update');
}

function esErrorUpdater(error) {
  const msg = String(error?.message || '').toLowerCase();
  return msg.includes('trufflehog updater') ||
    msg.includes('cannot move binary') ||
    msg.includes('auto-update') ||
    msg.includes('updater');
}

function pareceNoInstalada(error) {
  const msg = String(error?.message || '').toLowerCase();
  return msg.includes('not found') ||
    msg.includes('not recognized') ||
    msg.includes('no se reconoce') ||
    msg.includes('enoent');
}

function descomprimirSiAplica(buffer, encoding = '') {
  const lower = String(encoding || '').toLowerCase();

  if (lower.includes('br')) return zlib.brotliDecompressSync(buffer);
  if (lower.includes('gzip')) return zlib.gunzipSync(buffer);
  if (lower.includes('deflate')) return zlib.inflateSync(buffer);

  return buffer;
}

function descargar(url, timeoutMs, redirecciones = 0) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const client = parsed.protocol === 'https:' ? https : http;
    const req = client.get(url, {
      timeout: timeoutMs,
      headers: {
        'user-agent': 'Mozilla/5.0 (compatible; TFM-Security-Scanner/1.0)',
        'accept': 'application/javascript,text/javascript,text/plain,*/*',
        'accept-encoding': 'gzip, deflate, br'
      }
    }, res => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume();
        if (redirecciones >= 5) {
          reject(new Error('demasiadas redirecciones'));
          return;
        }

        const siguiente = new URL(res.headers.location, url).href;
        descargar(siguiente, timeoutMs, redirecciones + 1).then(resolve).catch(reject);
        return;
      }

      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }
      const chunks = [];
      let size = 0;
      res.on('data', chunk => {
        size += chunk.length;
        if (size <= 1024 * 1024) chunks.push(chunk);
        if (size > 1024 * 1024) req.destroy(new Error('archivo demasiado grande'));
      });
      res.on('end', () => {
        try {
          resolve(descomprimirSiAplica(Buffer.concat(chunks), res.headers['content-encoding']));
        } catch (error) {
          reject(new Error(`no se pudo descomprimir recurso: ${error.message}`));
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout descargando recurso')));
    req.on('error', reject);
  });
}

function esJsEscaneable(url = '') {
  const lower = String(url).toLowerCase().split('?')[0];
  return /\.(js|mjs|cjs|jsx|ts|tsx|map|json)$/i.test(lower) &&
    !lower.includes('/node_modules/') &&
    !lower.includes('/swagger-ui');
}

function esRecursoSensibleEscaneable(url = '') {
  const lower = String(url).toLowerCase().split('?')[0];
  return lower.includes('/.git') ||
    lower.endsWith('/.env') ||
    /\.(env|config|conf|ini|yml|yaml|txt|xml|sql|bak)$/i.test(lower);
}

function urlsParaSecretos(endpoints = []) {
  return Array.from(new Set(endpoints
    .map(endpoint => typeof endpoint === 'string' ? endpoint : endpoint.url)
    .filter(Boolean)
    .filter(url => esJsEscaneable(url) || esRecursoSensibleEscaneable(url))));
}

function nombreRecurso(url, index) {
  try {
    const pathname = new URL(url).pathname;
    const ext = path.extname(pathname).slice(0, 12) || '.js';
    return `recurso-${index}${ext}`;
  } catch {
    return `recurso-${index}.js`;
  }
}

function resumirErroresDescarga(errores = []) {
  return errores
    .slice(0, 3)
    .map(item => `${item.url}: ${item.error}`)
    .join(' | ');
}

function parsearResultados(raw = '', urlMap = new Map()) {
  return String(raw)
    .split('\n')
    .map(linea => linea.trim())
    .filter(Boolean)
    .map(linea => {
      try {
        return JSON.parse(linea);
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .map((item, index) => {
      const verified = Boolean(item.Verified ?? item.verified);
      const detectorName = item.DetectorName || item.detectorName || item.detector_name || 'secret';
      const fileSource = item.SourceMetadata?.Data?.Filesystem?.file || item.SourceName || item.source || null;
      const source = urlMap.get(path.basename(fileSource || '')) || fileSource;

      return {
        id: `trufflehog-secret-${index + 1}`,
        tool: 'trufflehog',
        type: 'secret',
        title: verified ? 'Secreto verificado detectado' : 'Posible secreto detectado',
        description: `TruffleHog detecto ${detectorName}.`,
        severity: verified ? 'high' : 'medium',
        confidence: verified ? 'high' : 'medium',
        isVulnerability: true,
        detectorName,
        verified,
        source,
        file: fileSource,
        affected_url: source,
        evidence: `${detectorName}${verified ? ' verificado' : ' no verificado'} en ${source || 'recurso descargado'}. El valor del secreto fue omitido.`,
        raw_reference: JSON.stringify({
          detectorName,
          verified,
          source,
          file: fileSource
        }),
        recommendation: 'Revocar el secreto si es real, rotarlo y eliminarlo del codigo o recurso publico.'
      };
    });
}

async function ejecutarTrufflehog(endpoints = [], opciones = {}) {
  const maxJs = Number(opciones.maxJs || process.env.MAX_JS_SECRET_SCAN || 20);
  const timeoutMs = Number(opciones.timeoutMs || (Number(process.env.TOOL_TIMEOUT_SECONDS || 120) * 1000));
  const urls = urlsParaSecretos(endpoints).slice(0, maxJs);

  if (!urls.length) {
    return {
      status: 'skipped',
      raw: '',
      parsed: [],
      findings: [],
      error: 'trufflehog no se ejecuto porque no hay JS o recursos relevantes para escanear',
      metrics: { secretos_verificados: 0, secretos_posibles: 0, recursos_candidatos: 0, recursos_descargados: 0 }
    };
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tfm-trufflehog-'));

  try {
    const urlMap = new Map();
    const erroresDescarga = [];

    for (let i = 0; i < urls.length; i++) {
      try {
        const data = await descargar(urls[i], timeoutMs);
        const filename = nombreRecurso(urls[i], i);
        urlMap.set(filename, urls[i]);
        fs.writeFileSync(path.join(tmpDir, filename), data);
      } catch (error) {
        erroresDescarga.push({
          url: urls[i],
          error: error.message
        });
      }
    }

    if (urlMap.size === 0) {
      const detalle = resumirErroresDescarga(erroresDescarga);

      return {
        status: 'skipped',
        raw: '',
        parsed: [],
        findings: [],
        error: `trufflehog no se ejecuto porque no se pudo descargar ningun JS o recurso relevante${detalle ? ` (${detalle})` : ''}`,
        metrics: {
          secretos_verificados: 0,
          secretos_posibles: 0,
          recursos_candidatos: urls.length,
          recursos_descargados: 0,
          recursos_fallidos: erroresDescarga.length
        }
      };
    }

    let raw = '';

    try {
      raw = await ejecutar(['filesystem', tmpDir, '--json', '--no-update'], timeoutMs);
    } catch (error) {
      if (!esErrorNoUpdateNoSoportado(error)) throw error;
      raw = await ejecutar(['filesystem', tmpDir, '--json'], timeoutMs);
    }

    const parsed = parsearResultados(raw, urlMap);

    console.log(`[trufflehog] secretos verificados: ${parsed.filter(item => item.verified).length}`);
    console.log(`[trufflehog] secretos posibles: ${parsed.filter(item => !item.verified).length}`);

    return {
      status: 'success',
      raw,
      parsed,
      findings: parsed,
      warning: erroresDescarga.length
        ? `TruffleHog escaneo ${urlMap.size} de ${urls.length} recursos; ${erroresDescarga.length} no se pudieron descargar. ${resumirErroresDescarga(erroresDescarga)}`
        : null,
      metrics: {
        secretos_verificados: parsed.filter(item => item.verified).length,
        secretos_posibles: parsed.filter(item => !item.verified).length,
        recursos_candidatos: urls.length,
        recursos_descargados: urlMap.size,
        recursos_fallidos: erroresDescarga.length
      }
    };
  } catch (error) {
    if (esErrorUpdater(error)) {
      console.log(`[trufflehog] warning controlado: ${error.message}`);
      return {
        status: 'success',
        raw: '',
        parsed: [],
        findings: [],
        error: null,
        warning: 'TruffleHog no pudo ejecutar el updater; se continua sin secretos detectados.',
        metrics: { secretos_verificados: 0, secretos_posibles: 0 }
      };
    }

    return {
      status: pareceNoInstalada(error) ? 'skipped' : 'error',
      raw: '',
      parsed: [],
      findings: [],
      error: pareceNoInstalada(error) ? 'trufflehog no esta instalado' : error.message,
      metrics: { secretos_verificados: 0, secretos_posibles: 0 }
    };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

module.exports = {
  ejecutarTrufflehog
};
