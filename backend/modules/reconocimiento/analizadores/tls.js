const tls = require('tls');

function hostnameDesdeUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' ? parsed.hostname : null;
  } catch {
    return null;
  }
}

function diasHasta(fecha) {
  return Math.ceil((fecha.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
}

function conectarTls(hostname, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: hostname,
      timeout: timeoutMs,
      rejectUnauthorized: false
    }, () => {
      const cert = socket.getPeerCertificate(true);
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();
      const authorized = socket.authorized;
      const authorizationError = socket.authorizationError || null;
      socket.end();
      resolve({ cert, protocol, cipher, authorized, authorizationError });
    });

    socket.on('timeout', () => socket.destroy(new Error('timeout TLS')));
    socket.on('error', reject);
  });
}

async function ejecutarTls(activos = [], opciones = {}) {
  const timeoutMs = Number(opciones.timeoutMs || 8000);
  const maxTargets = Number(opciones.maxTargets || process.env.MAX_PASSIVE_TARGETS || 20);
  const hosts = Array.from(new Set(activos.map(hostnameDesdeUrl).filter(Boolean))).slice(0, maxTargets);
  const parsed = [];
  const errores = [];

  if (!hosts.length) {
    return {
      status: 'skipped',
      raw: '',
      parsed: [],
      findings: [],
      error: 'tls no se ejecuto porque no hay activos HTTPS',
      metrics: { certificados_analizados: 0, expirados: 0, proximos_expirar: 0, errores_tls: 0 }
    };
  }

  for (const hostname of hosts) {
    try {
      const result = await conectarTls(hostname, timeoutMs);
      const validTo = result.cert?.valid_to ? new Date(result.cert.valid_to) : null;
      const daysRemaining = validTo ? diasHasta(validTo) : null;

      parsed.push({
        host: hostname,
        subject: result.cert?.subject || null,
        issuer: result.cert?.issuer || null,
        subjectaltname: result.cert?.subjectaltname || null,
        validFrom: result.cert?.valid_from || null,
        validTo: result.cert?.valid_to || null,
        daysRemaining,
        expired: typeof daysRemaining === 'number' ? daysRemaining < 0 : false,
        nearExpiry: typeof daysRemaining === 'number' ? daysRemaining >= 0 && daysRemaining < 30 : false,
        protocol: result.protocol,
        cipher: result.cipher?.name || null,
        authorized: result.authorized,
        authorizationError: result.authorizationError
      });
    } catch (error) {
      errores.push({ host: hostname, error: error.message });
      parsed.push({
        host: hostname,
        error: error.message,
        tlsError: true
      });
    }
  }

  return {
    status: parsed.length ? (errores.length ? 'partial' : 'success') : 'error',
    raw: JSON.stringify(parsed, null, 2),
    parsed,
    findings: [],
    error: parsed.length ? null : 'tls no pudo analizar certificados',
    warning: errores.length ? `tls tuvo errores en ${errores.length} host(s)` : null,
    metrics: {
      certificados_analizados: parsed.filter(item => !item.tlsError).length,
      expirados: parsed.filter(item => item.expired).length,
      proximos_expirar: parsed.filter(item => item.nearExpiry).length,
      errores_tls: parsed.filter(item => item.tlsError || item.authorizationError).length
    }
  };
}

module.exports = {
  ejecutarTls
};
