const http = require('http');
const https = require('https');

function requestUrl(url, opciones = {}) {
  const timeoutMs = Number(opciones.timeoutMs || 8000);
  const method = opciones.method || 'GET';
  const maxBytes = Number(opciones.maxBytes || 256 * 1024);

  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      reject(new Error(`URL invalida: ${url}`));
      return;
    }

    const client = parsed.protocol === 'https:' ? https : http;
    const req = client.request(parsed, {
      method,
      timeout: timeoutMs,
      rejectUnauthorized: opciones.rejectUnauthorized !== false,
      headers: {
        'user-agent': 'TFM-Passive-Scanner/1.0',
        accept: '*/*'
      }
    }, res => {
      const chunks = [];
      let size = 0;

      res.on('data', chunk => {
        size += chunk.length;
        if (size <= maxBytes) chunks.push(chunk);
        if (size > maxBytes) req.destroy(new Error('respuesta demasiado grande'));
      });

      res.on('end', () => {
        resolve({
          url,
          statusCode: res.statusCode,
          headers: res.headers || {},
          rawHeaders: res.rawHeaders || [],
          body: Buffer.concat(chunks).toString('utf8')
        });
      });
    });

    req.on('timeout', () => req.destroy(new Error('timeout HTTP')));
    req.on('error', reject);
    req.end();
  });
}

function origen(url) {
  try {
    const parsed = new URL(url);
    return parsed.origin;
  } catch {
    return null;
  }
}

function deduplicarOrigenes(urls = []) {
  return Array.from(new Set(urls.map(origen).filter(Boolean)));
}

function normalizarSetCookie(rawHeaders = []) {
  const cookies = [];
  for (let i = 0; i < rawHeaders.length; i += 2) {
    if (String(rawHeaders[i] || '').toLowerCase() === 'set-cookie') {
      cookies.push(rawHeaders[i + 1]);
    }
  }
  return cookies;
}

module.exports = {
  requestUrl,
  origen,
  deduplicarOrigenes,
  normalizarSetCookie
};
