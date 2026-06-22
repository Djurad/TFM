const { execFile } = require('child_process');
const net = require('net');

const DEFAULT_PORTS = [80, 443, 8080, 8443, 8000, 3000, 5000, 5432, 3306, 6379, 9200, 27017, 22, 21, 25];
const DB_PORTS = new Set([5432, 3306, 6379, 9200, 27017]);

function ejecutarNmap(host, ports, timeoutMs) {
  return new Promise((resolve, reject) => {
    execFile('nmap', ['-Pn', '--open', '-p', ports.join(','), host], {
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024
    }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error([stderr, error.message].filter(Boolean).join('\n')));
        return;
      }
      resolve(stdout || '');
    });
  });
}

function parsearNmap(raw = '', host) {
  return String(raw)
    .split('\n')
    .map(line => line.trim())
    .map(line => line.match(/^(\d+)\/tcp\s+open\s+(\S+)/i))
    .filter(Boolean)
    .map(match => ({
      host,
      port: Number(match[1]),
      state: 'open',
      service: match[2],
      source: 'nmap'
    }));
}

function pareceNmapNoInstalado(error) {
  const msg = String(error?.message || '').toLowerCase();
  return msg.includes('not found') ||
    msg.includes('not recognized') ||
    msg.includes('no se reconoce') ||
    msg.includes('enoent');
}

function comprobarPuerto(host, port, timeoutMs) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    let done = false;

    function finalizar(open) {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(open);
    }

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finalizar(true));
    socket.once('timeout', () => finalizar(false));
    socket.once('error', () => finalizar(false));
    socket.connect(port, host);
  });
}

async function fallbackTcp(host, ports, timeoutMs) {
  const abiertos = [];

  for (const port of ports) {
    const open = await comprobarPuerto(host, port, timeoutMs);
    if (open) {
      abiertos.push({
        host,
        port,
        state: 'open',
        service: null,
        source: 'tcp-fallback'
      });
    }
  }

  return abiertos;
}

function clasificarPuerto(port) {
  if ([80, 443].includes(port)) return 'web';
  if ([8080, 8443, 8000, 3000, 5000].includes(port)) return 'web-alt';
  if (DB_PORTS.has(port)) return 'data-store';
  if ([22, 21, 25].includes(port)) return 'service';
  return 'other';
}

async function ejecutarPorts(host, opciones = {}) {
  const ports = String(process.env.PASSIVE_PORTS || '')
    .split(',')
    .map(item => Number(item.trim()))
    .filter(Boolean);
  const targetPorts = ports.length ? ports.slice(0, 40) : DEFAULT_PORTS;
  const timeoutMs = Number(opciones.timeoutMs || 12000);
  const perPortTimeoutMs = Number(process.env.PORT_SCAN_TIMEOUT_MS || 800);

  if (!host) {
    return {
      status: 'skipped',
      raw: '',
      parsed: [],
      findings: [],
      error: 'ports no se ejecuto porque no hay host valido',
      metrics: { puertos_abiertos: 0, puertos_datos: 0 }
    };
  }

  try {
    const raw = await ejecutarNmap(host, targetPorts, timeoutMs);
    const parsed = parsearNmap(raw, host).map(item => ({
      ...item,
      category: clasificarPuerto(item.port)
    }));

    return {
      status: 'success',
      raw,
      parsed,
      findings: [],
      metrics: {
        puertos_abiertos: parsed.length,
        puertos_datos: parsed.filter(item => item.category === 'data-store').length,
        source: 'nmap'
      }
    };
  } catch (error) {
    if (!pareceNmapNoInstalado(error)) {
      console.log(`[ports] nmap fallo, usando fallback TCP: ${error.message}`);
    }

    const parsed = (await fallbackTcp(host, targetPorts, perPortTimeoutMs)).map(item => ({
      ...item,
      category: clasificarPuerto(item.port)
    }));

    return {
      status: 'success',
      raw: JSON.stringify(parsed, null, 2),
      parsed,
      findings: [],
      warning: pareceNmapNoInstalado(error)
        ? 'nmap no esta instalado; se uso scanner TCP ligero'
        : `nmap fallo; se uso scanner TCP ligero: ${error.message}`,
      metrics: {
        puertos_abiertos: parsed.length,
        puertos_datos: parsed.filter(item => item.category === 'data-store').length,
        source: 'tcp-fallback'
      }
    };
  }
}

module.exports = {
  ejecutarPorts
};
