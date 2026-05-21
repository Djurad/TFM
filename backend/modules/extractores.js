const { normalizarFindings } = require('./normalizacion');
const { esAssetEstatico } = require('./clasificadorFindings');

const PALABRAS_SENSIBLES = [
  'login',
  'signin',
  'auth',
  'upload',
  'file',
  'graphql',
  'api',
  'swagger',
  'openapi',
  'docs',
  'debug',
  'console',
  'actuator',
  'phpmyadmin',
  'backup',
  'config',
  'token',
  'reset',
  'password'
];

const SUPERFICIE_SWAGGER_RUIDOSA = [
  '/swagger/audio/',
  '/swagger/video/',
  '/swagger/image/',
  '/swagger/multipart/'
];

const PATRONES_RUIDO_URL = [
  /%7c%7c/i,
  /call\(/i,
  /[?&]line=/i,
  /[?&]position=/i,
  /:[0-9]+:[0-9]+/,
  /\{.*\}/,
  /\s/
];

function obtenerPath(url) {
  try {
    return new URL(url).pathname.toLowerCase();
  } catch {
    return String(url || '').toLowerCase();
  }
}

function obtenerOrigenYRuta(url) {
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return String(url || '').split('?')[0];
  }
}

function normalizarUrlSuperficie(url = '') {
  try {
    const parsed = new URL(url);
    parsed.hash = '';
    const params = Array.from(parsed.searchParams.entries())
      .sort(([a], [b]) => a.localeCompare(b));
    parsed.search = '';
    params.forEach(([key, value]) => parsed.searchParams.append(key, value));
    return parsed.href.replace(/\/$/, '').toLowerCase();
  } catch {
    return String(url || '').trim().replace(/\/$/, '').toLowerCase();
  }
}

function parsearNucleiLinea(linea, index, target) {
  const limpia = String(linea || '').trim();
  const match = limpia.match(/\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)/);

  if (!match) return null;

  const [, id, tipo, severity, url] = match;

  return {
    id: `nuclei-${id}-${index + 1}`,
    tool: 'nuclei',
    type: severity === 'info' ? 'reconocimiento' : 'vulnerability',
    title: id.replace(/[-_]/g, ' '),
    description: `Nuclei detecto el hallazgo ${id} de tipo ${tipo}.`,
    severity,
    confidence: severity === 'info' ? 'low' : ['high', 'critical'].includes(severity) ? 'high' : 'medium',
    cvss: null,
    cwe: null,
    affected_asset: target,
    affected_url: url,
    evidence: limpia,
    impact: '',
    recommendation: '',
    false_positive_risk: severity === 'info' ? 'medium' : 'low',
    raw_reference: limpia
  };
}

function findingsNuclei(toolResult, target) {
  const lineas = Array.isArray(toolResult.parsed)
    ? toolResult.parsed
    : String(toolResult.raw || '').split('\n').filter(Boolean);

  return normalizarFindings(
    lineas
      .map((linea, index) => parsearNucleiLinea(linea, index, target))
      .filter(Boolean),
    'nuclei',
    target
  );
}

function findingsDalfox(toolResult, target) {
  const items = Array.isArray(toolResult.parsed) ? toolResult.parsed : [];
  const grupos = new Map();

  items
    .filter(item => {
      const parsed = normalizarItemDalfox(item);
      const raw = JSON.stringify(parsed).toLowerCase();
      return raw.includes('xss') ||
        raw.includes('vulnerable') ||
        raw.includes('poc') ||
        raw.includes('payload') ||
        raw.includes('proof');
    })
    .forEach(item => {
      const parsed = normalizarItemDalfox(item);
      const url = parsed.url || parsed.target || parsed.data || null;
      const param = parsed.param || obtenerPrimerParametro(url);
      const payload = limpiarValorDalfox(parsed.payload || parsed.poc || '');
      const evidence = limpiarValorDalfox(parsed.evidence || parsed.message_str || '');
      const injectType = parsed.inject_type || parsed.type || 'desconocido';
      const severity = normalizarSeveridadDalfox(parsed.severity, parsed.type);
      const tipoDalfox = String(parsed.type || parsed.status || parsed.severity || '').toLowerCase();
      const confirmed = String(parsed.type || '').toUpperCase() === 'V' ||
        tipoDalfox.includes('confirmed') ||
        tipoDalfox.includes('triggered') ||
        Boolean(parsed.triggered);
      const rawReference = JSON.stringify(parsed);
      const groupKey = [
        obtenerOrigenYRuta(url || target),
        param || '',
        injectType,
        confirmed ? 'confirmed' : 'probable'
      ].join('|');

      if (!grupos.has(groupKey)) {
        grupos.set(groupKey, {
          url,
          param,
          injectType,
          severity,
          confirmed,
          payloads: [],
          evidences: [],
          rawReferences: []
        });
      }

      const grupo = grupos.get(groupKey);

      if (severity === 'high') grupo.severity = 'high';
      if (confirmed) grupo.confirmed = true;
      if (payload && grupo.payloads.length < 4 && !grupo.payloads.includes(payload)) grupo.payloads.push(payload);
      if (evidence && grupo.evidences.length < 4 && !grupo.evidences.includes(evidence)) grupo.evidences.push(evidence);
      if (rawReference && grupo.rawReferences.length < 4) grupo.rawReferences.push(rawReference);
    });

  return normalizarFindings(
    Array.from(grupos.values()).map((grupo, index) => {
      const readableEvidence = [
        `URL base: ${obtenerOrigenYRuta(grupo.url || target)}`,
        grupo.url ? `Ejemplo vulnerable: ${grupo.url}` : null,
        grupo.param ? `Parametro: ${grupo.param}` : null,
        `Tipo de inyeccion: ${grupo.injectType}`,
        grupo.payloads.length ? `Payloads observados:\n- ${grupo.payloads.join('\n- ')}` : null,
        grupo.evidences.length ? `Evidencias observadas:\n- ${grupo.evidences.join('\n- ')}` : null
      ].filter(Boolean).join('\n');

      return {
        id: `dalfox-xss-${index + 1}`,
        tool: 'dalfox',
        type: 'xss',
        title: grupo.confirmed ? 'XSS confirmado por Dalfox' : 'Posible XSS reflejado',
        description: `Dalfox detecto un posible XSS en el parametro ${grupo.param || 'identificado'} usando payloads reflejados en contexto ${grupo.injectType}.`,
        severity: grupo.confirmed ? 'high' : grupo.severity,
        confidence: grupo.confirmed ? 'confirmed' : 'probable',
        cvss: null,
        cwe: 'CWE-79',
        affected_asset: target,
        affected_url: grupo.url,
        evidence: readableEvidence,
        impact: '',
        recommendation: '',
        false_positive_risk: grupo.confirmed ? 'low' : 'medium',
        raw_reference: grupo.rawReferences.join('\n').slice(0, 1600)
      };
    }),
    'dalfox',
    target
  );
}

function parseJsonFlexible(texto) {
  if (!texto || typeof texto !== 'string') return null;

  const candidatos = [
    texto.trim(),
    texto.trim().replace(/,\s*$/, ''),
    texto.trim().replace(/,\s*}$/, '}')
  ];

  for (const candidato of candidatos) {
    try {
      return JSON.parse(candidato);
    } catch {
      // Se intenta el siguiente candidato.
    }
  }

  return null;
}

function normalizarItemDalfox(item) {
  if (!item || typeof item !== 'object') return {};

  if (item.raw) {
    const parsedRaw = parseJsonFlexible(item.raw);
    if (parsedRaw) return parsedRaw;
  }

  return item;
}

function limpiarValorDalfox(valor) {
  return String(valor || '')
    .replace(/\\u003c/g, '<')
    .replace(/\\u003e/g, '>')
    .replace(/\\u0026/g, '&')
    .replace(/\\r/g, ' ')
    .replace(/\\n/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function obtenerPrimerParametro(url) {
  try {
    return Array.from(new URL(url).searchParams.keys())[0] || null;
  } catch {
    return null;
  }
}

function normalizarSeveridadDalfox(severity, type) {
  if (String(type || '').toUpperCase() === 'V') return 'high';

  const lower = String(severity || '').toLowerCase();
  if (lower.includes('critical')) return 'critical';
  if (lower.includes('high')) return 'high';
  if (lower.includes('medium')) return 'medium';
  if (lower.includes('low')) return 'low';
  return 'medium';
}

function esAdminReal(url) {
  const texto = String(url || '');
  return /\/admin(\/|$|\?)/i.test(texto) ||
    /(^|[/?&=])admin([/?&=]|$)/i.test(texto);
}

function esRutaRuidosa(url) {
  const lower = String(url || '').toLowerCase();
  let path = lower;

  try {
    path = new URL(url).pathname.toLowerCase();
  } catch {
    // Se mantiene texto crudo.
  }

  return SUPERFICIE_SWAGGER_RUIDOSA.some(segmento => path.includes(segmento)) ||
    PATRONES_RUIDO_URL.some(regex => regex.test(lower)) ||
    lower.length > 240;
}

function recomendacionSuperficie(clave) {
  if (['login', 'signin', 'auth', 'reset', 'password'].includes(clave)) {
    return 'Revisar controles de autenticacion, proteccion anti-fuerza bruta y gestion de sesion.';
  }

  if (['swagger', 'openapi', 'docs', 'api-docs', 'swagger-json'].includes(clave)) {
    return 'Verificar que la documentacion no exponga endpoints sensibles y restringirla si no debe ser publica.';
  }

  return 'Revisar manualmente si este endpoint requiere controles adicionales.';
}

function tituloSuperficie(clave, swaggerJson = false) {
  if (['login', 'signin', 'auth'].includes(clave)) return 'Login descubierto';
  if (clave === 'admin') return 'Panel administrativo descubierto';
  if (clave === 'upload') return 'Endpoint de subida descubierto';
  if (clave === 'graphql') return 'Endpoint GraphQL descubierto';
  if (swaggerJson) return 'Endpoint OpenAPI descubierto';
  if (['swagger', 'openapi', 'docs', 'api-docs'].includes(clave)) return 'Documentacion Swagger descubierta';
  if (clave === 'debug') return 'Endpoint de debug descubierto';
  if (clave === 'actuator') return 'Endpoint Actuator descubierto';
  if (clave === 'phpmyadmin') return 'phpMyAdmin descubierto';
  if (['backup', 'config'].includes(clave)) return 'Ruta sensible de backup/config descubierta';
  return 'Superficie sensible descubierta';
}

function findingsSqlmap(toolResult, target) {
  const items = Array.isArray(toolResult.parsed) ? toolResult.parsed : [];

  return normalizarFindings(
    items
      .filter(item => ['confirmed_sqli', 'possible_sqli'].includes(item.status))
      .map((item, index) => ({
        id: `sqlmap-sqli-${index + 1}`,
        tool: 'sqlmap',
        type: 'vulnerability',
        title: item.status === 'confirmed_sqli'
          ? 'SQL Injection confirmada por sqlmap'
          : 'Posible SQL Injection detectada por sqlmap',
        description: item.status === 'confirmed_sqli'
          ? 'Sqlmap ha identificado un punto de inyeccion SQL confirmado.'
          : 'Sqlmap ha identificado indicios de inyeccion SQL que requieren validacion manual.',
        severity: item.status === 'confirmed_sqli' ? 'critical' : 'high',
        confidence: item.status === 'confirmed_sqli' ? 'high' : 'medium',
        cvss: null,
        cwe: 'CWE-89',
        affected_asset: target,
        affected_url: item.url,
        evidence: [
          item.evidencia,
          item.parametro ? `Parametro: ${item.parametro}` : null,
          item.payload ? `Payload: ${item.payload}` : null,
          item.dbms ? `DBMS: ${item.dbms}` : null,
          ...(item.resumen || [])
        ].filter(Boolean).join('\n'),
        impact: '',
        recommendation: '',
        false_positive_risk: item.status === 'confirmed_sqli' ? 'low' : 'medium',
        status: item.status,
        parametro: item.parametro || null,
        payload: item.payload || null,
        dbms: item.dbms || null,
        raw_reference: JSON.stringify(item).slice(0, 1200)
      })),
    'sqlmap',
    target
  );
}

function extraerFindingsDeterministas(tool, toolResult, target) {
  if (tool === 'katana') return findingsKatana(toolResult, target);
  if (tool === 'feroxbuster') return findingsFeroxbuster(toolResult, target);
  if (tool === 'gau') return findingsGau(toolResult, target);
  if (tool === 'gf') return findingsGf(toolResult, target);
  if (tool === 'nuclei') return findingsNuclei(toolResult, target);
  if (tool === 'dalfox') return findingsDalfox(toolResult, target);
  if (tool === 'sqlmap') return findingsSqlmap(toolResult, target);
  if (tool === 'trufflehog') return findingsTrufflehog(toolResult, target);
  return [];
}

function findingsGau(toolResult, target) {
  const endpoints = Array.isArray(toolResult.parsed) ? toolResult.parsed : [];
  const vistos = new Set();
  const relevantes = [];

  endpoints.forEach(endpoint => {
    const url = typeof endpoint === 'string' ? endpoint : endpoint.url;
    const key = normalizarUrlSuperficie(url);
    if (!url || vistos.has(key)) return;
    vistos.add(key);

    const clasificacion = clasificarEndpointSensible(url);
    if (clasificacion || endpoint.hasParams || endpoint.tieneParametros) {
      relevantes.push({
        endpoint,
        url,
        clasificacion
      });
    }
  });

  return normalizarFindings(
    relevantes.slice(0, 40).map((item, index) => ({
      id: `gau-historical-url-${index + 1}`,
      tool: 'gau',
      type: item.clasificacion ? 'surface' : 'historical-url',
      title: item.clasificacion?.title || 'URL historica parametrizada',
      description: item.clasificacion
        ? `${item.clasificacion.title} encontrada en fuentes historicas.`
        : 'GAU encontro una URL historica con parametros utiles para pruebas dirigidas.',
      severity: 'info',
      confidence: 'low',
      isVulnerability: false,
      affected_asset: target,
      affected_url: item.url,
      evidence: item.clasificacion?.evidence || `URL historica: ${item.url}`,
      impact: '',
      recommendation: item.clasificacion?.recommendation || 'Usar esta URL como entrada para pruebas manuales o herramientas especializadas; no tratarla como vulnerabilidad por si sola.',
      false_positive_risk: 'medium',
      raw_reference: JSON.stringify(item.endpoint).slice(0, 1200)
    })),
    'gau',
    target
  );
}

function tipoGfDesdeBucket(bucket = '') {
  return bucket
    .replace('Candidates', '')
    .replace('sqli', 'sqli')
    .replace('xss', 'xss');
}

function tituloGf(tipo) {
  const mapa = {
    xss: 'Candidato a XSS priorizado por GF',
    sqli: 'Candidato a SQL Injection priorizado por GF',
    ssrf: 'Candidato a SSRF priorizado por GF',
    redirect: 'Candidato a Open Redirect priorizado por GF',
    lfi: 'Candidato a LFI priorizado por GF',
    rce: 'Candidato a RCE priorizado por GF'
  };

  return mapa[tipo] || 'Candidato priorizado por GF';
}

function severidadGf(tipo) {
  if (['sqli', 'rce', 'ssrf'].includes(tipo)) return 'medium';
  return 'low';
}

function findingsGf(toolResult, target) {
  const buckets = toolResult.parsed || {};
  const findings = [];
  const vistos = new Set();

  Object.entries(buckets).forEach(([bucket, urls]) => {
    const tipo = tipoGfDesdeBucket(bucket);
    (Array.isArray(urls) ? urls : []).forEach(url => {
      const key = `${tipo}|${normalizarUrlSuperficie(url)}`;
      if (!url || vistos.has(key)) return;
      vistos.add(key);

      findings.push({
        id: `gf-${tipo}-${findings.length + 1}`,
        tool: 'gf',
        type: 'gf-candidate',
        vulnerability_type: tipo,
        title: tituloGf(tipo),
        description: `GF marco esta URL como candidata para pruebas de ${tipo.toUpperCase()}. No confirma explotabilidad.`,
        severity: severidadGf(tipo),
        confidence: 'medium',
        isVulnerability: true,
        affected_asset: target,
        affected_url: url,
        evidence: `Patron GF: ${tipo}\nURL: ${url}`,
        impact: 'Puede indicar un endpoint con parametros interesantes para validacion dirigida.',
        recommendation: 'Validar manualmente y con herramientas especificas antes de reportarlo como vulnerabilidad confirmada.',
        false_positive_risk: 'high',
        raw_reference: `${tipo}: ${url}`
      });
    });
  });

  return normalizarFindings(findings.slice(0, 60), 'gf', target);
}

function esExposicionFerox(url = '') {
  const lower = String(url).toLowerCase();
  return lower.includes('/.env') ||
    lower.includes('/.git') ||
    lower.includes('backup.zip') ||
    lower.includes('config.php') ||
    lower.includes('database.sql') ||
    lower.includes('dump.sql') ||
    /\.(zip|tar|tgz|tar\.gz|7z|rar|bak|backup|sql)(\?|$)/i.test(lower);
}

function findingsFeroxbuster(toolResult, target) {
  const endpoints = Array.isArray(toolResult.parsed) ? toolResult.parsed : [];
  const interesantes = endpoints.filter(endpoint => endpoint.category === 'suspicious' || esExposicionFerox(endpoint.url));

  return normalizarFindings(
    interesantes
      .slice(0, 30)
      .map((endpoint, index) => ({
        id: esExposicionFerox(endpoint.url)
          ? `feroxbuster-exposure-${index + 1}`
          : `feroxbuster-surface-${index + 1}`,
        tool: 'feroxbuster',
        type: esExposicionFerox(endpoint.url) ? 'vulnerability' : 'surface',
        exposure: esExposicionFerox(endpoint.url),
        title: endpoint.url.includes('/.env')
          ? 'Posible archivo .env expuesto'
          : endpoint.url.includes('/.git')
            ? 'Posible repositorio .git expuesto'
            : esExposicionFerox(endpoint.url)
              ? 'Posible archivo sensible expuesto'
              : 'Ruta sensible descubierta por Feroxbuster',
        description: esExposicionFerox(endpoint.url)
          ? 'Feroxbuster descubrio una ruta sensible accesible que requiere validacion manual.'
          : 'Feroxbuster descubrio superficie sensible. No es una vulnerabilidad confirmada.',
        severity: esExposicionFerox(endpoint.url) ? 'medium' : 'low',
        confidence: esExposicionFerox(endpoint.url) ? 'medium' : 'low',
        isVulnerability: esExposicionFerox(endpoint.url),
        affected_asset: target,
        affected_url: endpoint.url,
        evidence: [
          `URL: ${endpoint.url}`,
          endpoint.status ? `Status: ${endpoint.status}` : null,
          endpoint.contentLength ? `Content-Length: ${endpoint.contentLength}` : null
        ].filter(Boolean).join('\n'),
        recommendation: esExposicionFerox(endpoint.url)
          ? 'Restringir el acceso publico a archivos sensibles, backups, configuraciones o repositorios internos.'
          : 'Revisar manualmente si este endpoint requiere controles adicionales.',
        raw_reference: JSON.stringify(endpoint).slice(0, 1200)
      })),
    'feroxbuster',
    target
  );
}

function findingsTrufflehog(toolResult, target) {
  const items = Array.isArray(toolResult.parsed) ? toolResult.parsed : [];

  return normalizarFindings(
    items.map((item, index) => ({
      id: item.id || `trufflehog-secret-${index + 1}`,
      tool: 'trufflehog',
      type: 'exposed-secret',
      title: item.verified ? 'Secreto verificado detectado' : 'Posible secreto detectado',
      description: item.description || `TruffleHog detecto ${item.detectorName || 'un secreto'}.`,
      severity: item.verified ? 'high' : 'medium',
      confidence: item.verified ? 'high' : 'medium',
      isVulnerability: true,
      affected_asset: target,
      affected_url: item.source || item.affected_url || null,
      evidence: item.evidence || `${item.detectorName || 'Secreto'} detectado. El valor completo fue omitido por seguridad.`,
      recommendation: item.recommendation || 'Revocar y rotar el secreto si es real, y eliminarlo del recurso publico.',
      verified: Boolean(item.verified),
      detectorName: item.detectorName || null,
      raw_reference: item.raw_reference || JSON.stringify(item).slice(0, 1200)
    })),
    'trufflehog',
    target
  );
}

function clasificarEndpointSensible(url) {
  const lower = String(url || '').toLowerCase();
  const path = obtenerPath(url);

  if (!url || esAssetEstatico(url)) return null;
  if (esRutaRuidosa(url)) {
    console.log(`[Clasificador] descartado por ruta irrelevante: ${url}`);
    return null;
  }

  if (
    path.endsWith('/swagger/index.html') ||
    path === '/docs' ||
    path.includes('/docs/') ||
    path.includes('/api-docs') ||
    path.includes('swagger') ||
    path.includes('openapi')
  ) {
    const swaggerJson = path.endsWith('/swagger.json') || path.endsWith('/openapi.json');
    const clave = swaggerJson ? 'swagger-json' : path.includes('/api-docs') ? 'api-docs' : path.includes('openapi') ? 'openapi' : 'swagger';

    const resultado = {
      title: tituloSuperficie(clave, swaggerJson),
      severity: 'low',
      category: swaggerJson ? 'swagger-json' : 'suspicious',
      evidence: swaggerJson
        ? 'Esquema Swagger/OpenAPI descubierto por Katana. Es exposicion informativa, no vulnerabilidad confirmada.'
        : 'Ruta compatible con Swagger/OpenAPI descubierta por Katana. Es superficie util, no vulnerabilidad confirmada.',
      impact: '',
      recommendation: recomendacionSuperficie(clave)
    };

    console.log(`[Clasificador] superficie util: ${url}`);
    return resultado;
  }

  const palabra = esAdminReal(url)
    ? 'admin'
    : PALABRAS_SENSIBLES.find(token => {
        const regex = new RegExp(`(^|[/?&=._-])${token}([/?&=._-]|$)`, 'i');
        return regex.test(lower);
      });

  if (palabra) {
    const resultado = {
      title: tituloSuperficie(palabra),
      severity: 'low',
      category: 'suspicious',
      evidence: `Ruta con patron sensible "${palabra}" descubierta por Katana. Requiere revision manual, pero no es una vulnerabilidad confirmada.`,
      impact: '',
      recommendation: recomendacionSuperficie(palabra)
    };

    console.log(`[Clasificador] superficie util: ${url}`);
    return resultado;
  }

  return null;
}

function findingsKatana(toolResult, target) {
  const urls = Array.isArray(toolResult.parsed) ? toolResult.parsed : [];
  const vistos = new Set();
  const findings = [];

  urls.forEach(item => {
    const url = typeof item === 'string' ? item : item.url;
    const key = normalizarUrlSuperficie(url);

    if (!url || vistos.has(key)) return;
    vistos.add(key);

    const clasificacion = clasificarEndpointSensible(url);

    if (!clasificacion) return;

    findings.push({
      id: `katana-surface-${findings.length + 1}`,
      tool: 'katana',
      type: 'surface',
      category: clasificacion.category || 'suspicious',
      title: clasificacion.title,
      description: `${clasificacion.title} en ${url}.`,
      severity: clasificacion.severity,
      confidence: 'low',
      cvss: null,
      cwe: null,
      affected_asset: target,
      affected_url: url,
      evidence: clasificacion.evidence,
      impact: clasificacion.impact,
      recommendation: clasificacion.recommendation,
      false_positive_risk: 'medium',
      raw_reference: url
    });
  });

  return normalizarFindings(findings.slice(0, 20), 'katana', target);
}

module.exports = {
  extraerFindingsDeterministas
};
