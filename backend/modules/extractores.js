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
  try {
    const item = JSON.parse(limpia);
    const info = item.info || {};
    const id = item['template-id'] || item.templateID || item.template_id || item.id || `template-${index + 1}`;
    const severity = String(info.severity || item.severity || 'info').toLowerCase();
    const tags = Array.isArray(info.tags)
      ? info.tags
      : String(info.tags || '').split(',').map(tag => tag.trim()).filter(Boolean);
    const matched = item['matched-at'] || item.matched || item.host || item.url || target;

    return {
      id: `nuclei-${id}-${index + 1}`,
      tool: 'nuclei',
      templateID: id,
      template_id: id,
      tags,
      type: severity === 'info' ? 'reconocimiento' : 'vulnerability',
      title: info.name || id.replace(/[-_]/g, ' '),
      description: info.description || `Nuclei detecto el hallazgo ${id}.`,
      severity,
      confidence: severity === 'info' ? 'low' : ['high', 'critical'].includes(severity) ? 'high' : 'medium',
      cvss: info.classification?.['cvss-score'] || null,
      cwe: info.classification?.cwe || null,
      affected_asset: item.host || target,
      affected_url: matched,
      evidence: limpia,
      impact: info.impact || '',
      recommendation: info.remediation || '',
      false_positive_risk: severity === 'info' ? 'medium' : 'low',
      raw_reference: limpia
    };
  } catch {
    // Compatibilidad con la salida historica de Nuclei en texto.
  }

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
  const vistos = new Set();
  const findings = [];

  items.forEach(item => {
    const parsed = normalizarItemDalfox(item);
    if (!parsed || !Object.keys(parsed).length) return;

    const raw = JSON.stringify(parsed).toLowerCase();
    const relevante = raw.includes('xss') ||
      raw.includes('vulnerable') ||
      raw.includes('poc') ||
      raw.includes('payload') ||
      raw.includes('proof') ||
      String(parsed.type || '').toUpperCase() === 'V';

    if (!relevante) return;

    const url = parsed.data || parsed.url || parsed.target || null;
    const param = parsed.param || obtenerPrimerParametro(url);
    const payload = limpiarValorDalfox(parsed.payload || parsed.poc || '');
    const evidence = limpiarValorDalfox(parsed.evidence || parsed.message_str || '');
    const injectType = parsed.inject_type || 'desconocido';
    const tipoDalfox = String(parsed.type || parsed.status || parsed.severity || '').toLowerCase();
    const confirmed = String(parsed.type || '').toUpperCase() === 'V' ||
      tipoDalfox.includes('confirmed') ||
      tipoDalfox.includes('triggered') ||
      Boolean(parsed.triggered);
    const severity = confirmed ? 'high' : normalizarSeveridadDalfox(parsed.severity, parsed.type);
    const key = [
      obtenerOrigenYRuta(url || target),
      param || '',
      injectType,
      payload || '',
      confirmed ? 'confirmed' : 'probable'
    ].join('|');

    if (vistos.has(key)) return;
    vistos.add(key);

    const readableEvidence = [
      url ? `URL vulnerable: ${url}` : null,
      param ? `Parametro: ${param}` : null,
      injectType ? `Tipo de inyeccion: ${injectType}` : null,
      parsed.poc_type ? `POC type: ${parsed.poc_type}` : null,
      parsed.method ? `Metodo: ${parsed.method}` : null,
      payload ? `Payload: ${payload}` : null,
      evidence ? `Evidencia: ${evidence}` : null,
      parsed.message_str ? `Mensaje Dalfox: ${limpiarValorDalfox(parsed.message_str)}` : null
    ].filter(Boolean).join('\n');

    findings.push({
      id: `dalfox-xss-${findings.length + 1}`,
      tool: 'dalfox',
      type: confirmed ? 'confirmed_vulnerability' : 'possible_vulnerability',
      title: confirmed ? 'XSS confirmado por Dalfox' : 'Posible XSS reflejado por Dalfox',
      description: confirmed
        ? `Dalfox confirmo XSS en el parametro ${param || 'identificado'}.`
        : `Dalfox detecto indicios de XSS en el parametro ${param || 'identificado'} que requieren validacion.`,
      severity,
      confidence: confirmed ? 'high' : 'medium',
      cvss: null,
      cwe: parsed.cwe || 'CWE-79',
      affected_asset: target,
      affected_url: url,
      evidence: readableEvidence,
      impact: confirmed
        ? 'Permite ejecutar JavaScript en el navegador de usuarios que visiten el enlace manipulado.'
        : '',
      recommendation: confirmed
        ? 'Sanitizar entradas, escapar salidas segun contexto HTML/URL y reforzar Content-Security-Policy.'
        : '',
      false_positive_risk: confirmed ? 'low' : 'medium',
      isVulnerability: true,
      confirmed,
      reportable: true,
      requiresManualValidation: !confirmed,
      param,
      parametro: param,
      payload,
      inject_type: parsed.inject_type || null,
      poc_type: parsed.poc_type || null,
      method: parsed.method || null,
      message_str: parsed.message_str || null,
      dalfox_type: parsed.type || null,
      raw_reference: JSON.stringify(parsed).slice(0, 1600)
    });
  });

  return normalizarFindings(
    findings,
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
  if (tool === 'headers') return findingsHeaders(toolResult, target);
  if (tool === 'cookies') return findingsCookies(toolResult, target);
  if (tool === 'httpsRedirect') return findingsHttpsRedirect(toolResult, target);
  if (tool === 'tls') return findingsTls(toolResult, target);
  if (tool === 'robotsSitemap') return findingsRobotsSitemap(toolResult, target);
  if (tool === 'ports') return findingsPorts(toolResult, target);
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

function findingBase({ id, tool, type, title, description, severity, confidence, affected_url, affected_asset, evidence, impact, recommendation, isVulnerability, false_positive_risk = 'medium', extra = {} }) {
  return {
    id,
    tool,
    type,
    title,
    description,
    severity,
    confidence,
    affected_asset,
    affected_url,
    evidence,
    impact,
    recommendation,
    isVulnerability,
    isFalsePositiveLikely: false,
    false_positive_risk,
    ...extra
  };
}

function datosHeader(name) {
  const mapa = {
    'content-security-policy': {
      title: 'Content-Security-Policy ausente',
      severity: 'medium',
      impact: 'Aumenta el impacto potencial de XSS y cargas de contenido no autorizado.',
      recommendation: 'Definir una Content-Security-Policy restrictiva y adaptada a la aplicacion.'
    },
    'x-frame-options': {
      title: 'X-Frame-Options ausente',
      severity: 'medium',
      impact: 'Puede facilitar ataques de clickjacking si la aplicacion se embebe en frames externos.',
      recommendation: 'Configurar X-Frame-Options DENY/SAMEORIGIN o frame-ancestors en CSP.'
    },
    'strict-transport-security': {
      title: 'Strict-Transport-Security ausente',
      severity: 'medium',
      impact: 'Los navegadores no fuerzan HTTPS en visitas futuras, aumentando riesgo ante downgrades o enlaces HTTP.',
      recommendation: 'Configurar HSTS con max-age adecuado y evaluar includeSubDomains/preload cuando aplique.'
    },
    'x-content-type-options': {
      title: 'X-Content-Type-Options ausente',
      severity: 'medium',
      impact: 'Puede permitir MIME sniffing en navegadores y ampliar algunos vectores de carga de contenido.',
      recommendation: 'Configurar X-Content-Type-Options: nosniff.'
    },
    'referrer-policy': {
      title: 'Referrer-Policy ausente',
      severity: 'low',
      impact: 'Puede exponer rutas o parametros internos a sitios externos mediante la cabecera Referer.',
      recommendation: 'Definir una Referrer-Policy conservadora como strict-origin-when-cross-origin.'
    },
    'permissions-policy': {
      title: 'Permissions-Policy ausente',
      severity: 'low',
      impact: 'No se restringen explicitamente APIs sensibles del navegador.',
      recommendation: 'Definir Permissions-Policy deshabilitando capacidades que la aplicacion no necesita.'
    }
  };

  return mapa[name] || {
    title: `${name} ausente`,
    severity: 'low',
    impact: 'Falta una cabecera de hardening.',
    recommendation: 'Revisar la configuracion de cabeceras HTTP.'
  };
}

function findingsHeaders(toolResult, target) {
  const items = Array.isArray(toolResult.parsed) ? toolResult.parsed : [];
  const findings = [];

  items.forEach(item => {
    (item.missing || []).forEach(header => {
      const datos = datosHeader(header);
      findings.push(findingBase({
        id: `headers-missing-${header}-${findings.length + 1}`,
        tool: 'headers',
        type: 'missing_security_header',
        title: datos.title,
        description: `No se observo la cabecera ${header} en la respuesta HTTP.`,
        severity: datos.severity,
        confidence: 'medium',
        affected_asset: target,
        affected_url: item.url,
        evidence: `URL: ${item.url}\nStatus: ${item.statusCode}\nCabecera ausente: ${header}`,
        impact: datos.impact,
        recommendation: datos.recommendation,
        isVulnerability: true,
        false_positive_risk: 'medium',
        extra: { header }
      }));
    });

    (item.banners || []).forEach(banner => {
      findings.push(findingBase({
        id: `headers-banner-${banner.name}-${findings.length + 1}`,
        tool: 'headers',
        type: 'exposed_server_banner',
        title: `Banner HTTP expuesto: ${banner.name}`,
        description: `La respuesta expone informacion de tecnologia mediante ${banner.name}.`,
        severity: 'info',
        confidence: 'low',
        affected_asset: target,
        affected_url: item.url,
        evidence: `${banner.name}: ${banner.value}`,
        impact: 'Puede ayudar al fingerprinting, pero no implica explotabilidad por si solo.',
        recommendation: 'Reducir banners si no son necesarios y mantener componentes actualizados.',
        isVulnerability: false,
        false_positive_risk: 'low',
        extra: { header: banner.name }
      }));
    });
  });

  return normalizarFindings(findings, 'headers', target);
}

function cookieIssues(item, cookie) {
  const issues = [];
  const session = cookie.isSessionCookie;

  if (session && !cookie.httpOnly) {
    issues.push({ flag: 'HttpOnly', severity: 'medium', title: `Cookie de sesion sin HttpOnly: ${cookie.name}` });
  }
  if (session && item.isHttps && !cookie.secure) {
    issues.push({ flag: 'Secure', severity: 'medium', title: `Cookie de sesion sin Secure: ${cookie.name}` });
  }
  if (session && !cookie.sameSite) {
    issues.push({ flag: 'SameSite', severity: 'medium', title: `Cookie de sesion sin SameSite: ${cookie.name}` });
  }
  if (!session && item.isHttps && !cookie.secure) {
    issues.push({ flag: 'Secure', severity: 'low', title: `Cookie sin Secure: ${cookie.name}` });
  }
  if (!session && !cookie.sameSite) {
    issues.push({ flag: 'SameSite', severity: 'low', title: `Cookie sin SameSite: ${cookie.name}` });
  }

  return issues;
}

function findingsCookies(toolResult, target) {
  const items = Array.isArray(toolResult.parsed) ? toolResult.parsed : [];
  const findings = [];

  items.forEach(item => {
    (item.cookies || []).forEach(cookie => {
      const issues = cookieIssues(item, cookie);
      if (!issues.length) return;
      const severity = issues.some(issue => issue.severity === 'medium') ? 'medium' : 'low';
      const flags = issues.map(issue => issue.flag);

      findings.push(findingBase({
        id: `cookies-${cookie.name}-${findings.length + 1}`,
        tool: 'cookies',
        type: 'insecure_cookie',
        title: cookie.isSessionCookie
          ? `Cookie de sesion con flags incompletos: ${cookie.name}`
          : `Cookie con flags incompletos: ${cookie.name}`,
        description: `La cookie ${cookie.name} no incluye todos los atributos defensivos esperados.`,
        severity,
        confidence: severity === 'medium' ? 'medium' : 'low',
        affected_asset: target,
        affected_url: item.url,
        evidence: [
          `Cookie: ${cookie.name}`,
          `Flags ausentes: ${flags.join(', ')}`,
          `Sesion: ${cookie.isSessionCookie ? 'si' : 'no'}`,
          `Secure: ${cookie.secure ? 'si' : 'no'}`,
          `HttpOnly: ${cookie.httpOnly ? 'si' : 'no'}`,
          `SameSite: ${cookie.sameSite || 'ausente'}`,
          cookie.domain ? `Domain: ${cookie.domain}` : null,
          cookie.path ? `Path: ${cookie.path}` : null
        ].filter(Boolean).join('\n'),
        impact: cookie.isSessionCookie
          ? 'Puede aumentar el riesgo de robo, exposicion o envio indebido de cookies de sesion.'
          : 'Riesgo limitado salvo que la cookie contenga datos sensibles.',
        recommendation: 'Configurar cookies de sesion con Secure, HttpOnly y SameSite=Lax/Strict segun el flujo de la aplicacion.',
        isVulnerability: true,
        false_positive_risk: cookie.isSessionCookie ? 'medium' : 'high',
        extra: { cookieName: cookie.name, missingFlags: flags }
      }));
    });
  });

  return normalizarFindings(findings.slice(0, 80), 'cookies', target);
}

function findingsHttpsRedirect(toolResult, target) {
  const items = Array.isArray(toolResult.parsed) ? toolResult.parsed : [];

  return normalizarFindings(items.map((item, index) => {
    if (item.httpAccessibleWithoutRedirect) {
      return findingBase({
        id: `https-redirect-missing-${index + 1}`,
        tool: 'httpsRedirect',
        type: 'missing_https_redirect',
        title: 'HTTP accesible sin redireccion a HTTPS',
        description: 'El servicio HTTP responde sin forzar redireccion a HTTPS.',
        severity: 'medium',
        confidence: 'medium',
        affected_asset: target,
        affected_url: item.url,
        evidence: `Status HTTP: ${item.statusCode}\nLocation: ${item.location || 'ausente'}`,
        impact: 'Usuarios o enlaces HTTP pueden quedar expuestos a trafico sin cifrar o downgrade.',
        recommendation: 'Redirigir todo HTTP a HTTPS con 301/308 y mantener HSTS en HTTPS.',
        isVulnerability: true
      });
    }

    return findingBase({
      id: `https-redirect-ok-${index + 1}`,
      tool: 'httpsRedirect',
      type: 'reconocimiento',
      title: item.redirectsToHttps ? 'HTTP redirige correctamente a HTTPS' : 'HTTP no disponible o sin evidencia negativa',
      description: 'Resultado informativo de comprobacion HTTP a HTTPS.',
      severity: 'info',
      confidence: 'low',
      affected_asset: target,
      affected_url: item.url,
      evidence: `Status HTTP: ${item.statusCode}\nLocation: ${item.location || 'ausente'}`,
      impact: '',
      recommendation: '',
      isVulnerability: false
    });
  }), 'httpsRedirect', target);
}

function findingsTls(toolResult, target) {
  const items = Array.isArray(toolResult.parsed) ? toolResult.parsed : [];
  const findings = [];

  items.forEach((item, index) => {
    if (item.tlsError) {
      findings.push(findingBase({
        id: `tls-error-${index + 1}`,
        tool: 'tls',
        type: 'tls_certificate_issue',
        title: 'Error TLS al conectar',
        description: 'No se pudo completar correctamente la conexion TLS.',
        severity: 'medium',
        confidence: 'medium',
        affected_asset: item.host || target,
        affected_url: item.host ? `https://${item.host}` : null,
        evidence: item.error || 'Error TLS',
        impact: 'Puede impedir conexiones seguras o indicar configuracion TLS defectuosa.',
        recommendation: 'Revisar certificado, cadena de confianza, SNI y configuracion TLS.',
        isVulnerability: true
      }));
      return;
    }

    if (item.expired || item.nearExpiry || item.authorizationError) {
      findings.push(findingBase({
        id: `tls-cert-${index + 1}`,
        tool: 'tls',
        type: 'tls_certificate_issue',
        title: item.expired
          ? 'Certificado TLS expirado'
          : item.nearExpiry
            ? 'Certificado TLS proximo a expirar'
            : 'Certificado TLS con error de validacion',
        description: 'Se detecto un problema de validez o confianza del certificado TLS.',
        severity: item.expired ? 'high' : item.nearExpiry ? 'low' : 'medium',
        confidence: item.expired || item.authorizationError ? 'high' : 'medium',
        affected_asset: item.host || target,
        affected_url: item.host ? `https://${item.host}` : null,
        evidence: [
          `Host: ${item.host}`,
          `Valido hasta: ${item.validTo || 'desconocido'}`,
          typeof item.daysRemaining === 'number' ? `Dias restantes: ${item.daysRemaining}` : null,
          item.authorizationError ? `Error: ${item.authorizationError}` : null,
          item.issuer ? `Issuer: ${JSON.stringify(item.issuer)}` : null
        ].filter(Boolean).join('\n'),
        impact: 'Puede degradar la confianza del usuario o romper conexiones seguras.',
        recommendation: 'Renovar el certificado y corregir la cadena de confianza antes de la expiracion.',
        isVulnerability: true
      }));
      return;
    }

    findings.push(findingBase({
      id: `tls-info-${index + 1}`,
      tool: 'tls',
      type: 'reconocimiento',
      title: 'Certificado TLS valido',
      description: 'Informacion basica del certificado TLS observado.',
      severity: 'info',
      confidence: 'low',
      affected_asset: item.host || target,
      affected_url: item.host ? `https://${item.host}` : null,
      evidence: `Valido hasta: ${item.validTo || 'desconocido'}\nProtocolo: ${item.protocol || 'desconocido'}\nCipher: ${item.cipher || 'desconocido'}`,
      impact: '',
      recommendation: '',
      isVulnerability: false
    }));
  });

  return normalizarFindings(findings, 'tls', target);
}

function findingsRobotsSitemap(toolResult, target) {
  const items = Array.isArray(toolResult.parsed) ? toolResult.parsed : [];
  const findings = [];

  items.forEach((item, index) => {
    if (item.exists) {
      findings.push(findingBase({
        id: `robots-sitemap-info-${index + 1}`,
        tool: 'robotsSitemap',
        type: 'reconocimiento',
        title: `${item.path} encontrado`,
        description: 'Recurso publico de descubrimiento encontrado.',
        severity: 'info',
        confidence: 'low',
        affected_asset: target,
        affected_url: item.url,
        evidence: `Status: ${item.statusCode}\nEntradas: ${(item.entries || []).length}`,
        impact: 'Puede ayudar a entender estructura publica del sitio.',
        recommendation: 'No incluir rutas sensibles en robots.txt y revisar que sitemap solo publique contenido esperado.',
        isVulnerability: false
      }));
    }

    (item.sensitiveEntries || []).forEach(entry => {
      findings.push(findingBase({
        id: `robots-sensitive-${findings.length + 1}`,
        tool: 'robotsSitemap',
        type: 'robots_sensitive_path',
        title: 'robots.txt revela ruta sensible',
        description: 'robots.txt contiene una ruta que parece sensible o util para reconocimiento.',
        severity: 'low',
        confidence: 'low',
        affected_asset: target,
        affected_url: item.url,
        evidence: `${entry.directive}: ${entry.value}`,
        impact: 'Puede facilitar el descubrimiento manual de paneles, backups o rutas internas.',
        recommendation: 'No usar robots.txt como mecanismo de proteccion; proteger rutas sensibles con autenticacion/autorizacion.',
        isVulnerability: false,
        false_positive_risk: 'medium'
      }));
    });
  });

  return normalizarFindings(findings, 'robotsSitemap', target);
}

function findingsPorts(toolResult, target) {
  const items = Array.isArray(toolResult.parsed) ? toolResult.parsed : [];

  return normalizarFindings(items.map((item, index) => {
    if (item.category === 'data-store') {
      return findingBase({
        id: `ports-data-${item.port}-${index + 1}`,
        tool: 'ports',
        type: 'exposed_port',
        title: `Puerto de datos expuesto: ${item.port}`,
        description: 'Se detecto un puerto comun de base de datos/cache accesible por TCP.',
        severity: item.port === 6379 || item.port === 27017 ? 'critical' : 'high',
        confidence: 'high',
        affected_asset: item.host || target,
        affected_url: `${item.host || target}:${item.port}`,
        evidence: `Puerto ${item.port}/tcp abierto${item.service ? ` (${item.service})` : ''}. Fuente: ${item.source}`,
        impact: 'Un servicio de datos expuesto puede permitir acceso no autorizado si no esta protegido por red y autenticacion fuerte.',
        recommendation: 'Restringir por firewall/VPC, exigir autenticacion fuerte y no exponer bases de datos/cache a Internet.',
        isVulnerability: true,
        false_positive_risk: 'medium',
        extra: { port: item.port }
      });
    }

    return findingBase({
      id: `ports-open-${item.port}-${index + 1}`,
      tool: 'ports',
      type: item.category === 'web-alt' ? 'surface' : 'exposed_port',
      title: item.category === 'web-alt' ? `Puerto web alternativo expuesto: ${item.port}` : `Puerto abierto: ${item.port}`,
      description: 'Se detecto un puerto TCP abierto durante el escaneo ligero.',
      severity: item.category === 'web-alt' ? 'low' : 'info',
      confidence: 'low',
      affected_asset: item.host || target,
      affected_url: `${item.host || target}:${item.port}`,
      evidence: `Puerto ${item.port}/tcp abierto${item.service ? ` (${item.service})` : ''}. Fuente: ${item.source}`,
      impact: item.category === 'web-alt' ? 'Amplia la superficie web a revisar.' : 'Dato de exposicion de servicio para inventario.',
      recommendation: 'Validar si el servicio debe estar expuesto y aplicar filtrado de red cuando no sea necesario.',
      isVulnerability: false,
      false_positive_risk: 'medium',
      extra: { port: item.port }
    });
  }), 'ports', target);
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
        type: 'gf_candidate',
        category: 'candidate',
        vulnerability_type: tipo,
        title: tituloGf(tipo),
        description: `GF marco esta URL como candidata para pruebas de ${tipo.toUpperCase()}. No confirma explotabilidad.`,
        severity: severidadGf(tipo),
        confidence: 'low',
        isVulnerability: false,
        confirmed: false,
        reportable: false,
        requiresManualValidation: true,
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

function esExposicionFerox(url = '', status = null) {
  if (!(Number(status) >= 200 && Number(status) < 300)) return false;
  const lower = String(url).toLowerCase();
  return lower.includes('/.env') ||
    lower.includes('/.git') ||
    lower.includes('/backup') ||
    lower.includes('backup.zip') ||
    lower.includes('config.php') ||
    lower.includes('db.sql') ||
    lower.includes('database.sql') ||
    lower.includes('dump.sql') ||
    /\.(zip|tar|tgz|tar\.gz|7z|rar|bak|backup|sql|env|conf|ini)(\?|$)/i.test(lower);
}

function findingsFeroxbuster(toolResult, target) {
  const endpoints = Array.isArray(toolResult.parsed) ? toolResult.parsed : [];
  const interesantes = endpoints.filter(endpoint => endpoint.category === 'suspicious' || esExposicionFerox(endpoint.url, endpoint.status));

  return normalizarFindings(
    interesantes
      .slice(0, 30)
      .map((endpoint, index) => ({
        id: esExposicionFerox(endpoint.url, endpoint.status)
          ? `feroxbuster-exposure-${index + 1}`
          : `feroxbuster-surface-${index + 1}`,
        tool: 'feroxbuster',
        type: esExposicionFerox(endpoint.url, endpoint.status) ? 'vulnerability' : 'surface',
        exposure: esExposicionFerox(endpoint.url, endpoint.status),
        title: endpoint.url.includes('/.env')
          ? 'Posible archivo .env expuesto'
          : endpoint.url.includes('/.git')
            ? 'Posible repositorio .git expuesto'
            : esExposicionFerox(endpoint.url, endpoint.status)
              ? 'Posible archivo sensible expuesto'
              : 'Ruta sensible descubierta por Feroxbuster',
        description: esExposicionFerox(endpoint.url, endpoint.status)
          ? 'Feroxbuster descubrio una ruta sensible accesible que requiere validacion manual.'
          : 'Feroxbuster descubrio superficie sensible. No es una vulnerabilidad confirmada.',
        severity: esExposicionFerox(endpoint.url, endpoint.status) ? 'medium' : 'low',
        confidence: esExposicionFerox(endpoint.url, endpoint.status) ? 'medium' : 'low',
        isVulnerability: esExposicionFerox(endpoint.url, endpoint.status),
        affected_asset: target,
        affected_url: endpoint.url,
        evidence: [
          `URL: ${endpoint.url}`,
          endpoint.status ? `Status: ${endpoint.status}` : null,
          endpoint.contentLength ? `Content-Length: ${endpoint.contentLength}` : null
        ].filter(Boolean).join('\n'),
        recommendation: esExposicionFerox(endpoint.url, endpoint.status)
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
