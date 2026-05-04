function limpiarColoresANSI(texto) {
  return texto.replace(/\x1B\[[0-9;]*m/g, '');
}

function obtenerPath(url) {
  try {
    return new URL(url).pathname;
  } catch {
    return '';
  }
}

function obtenerParametros(url) {
  try {
    return Array.from(new URL(url).searchParams.keys());
  } catch {
    return [];
  }
}

function normalizarUrl(url) {
  return (url || '').split('#')[0];
}

function categorizarEndpoint(url) {
  const lower = url.toLowerCase();

  if (lower.includes('swagger')) return 'api-docs';
  if (lower.includes('admin')) return 'admin';
  if (lower.includes('login')) return 'login';
  if (lower.includes('search')) return 'busqueda';
  if (lower.includes('feedback')) return 'formulario';
  if (lower.includes('survey')) return 'formulario';
  if (lower.includes('subscribe')) return 'formulario';
  if (lower.endsWith('.js')) return 'javascript';
  if (lower.endsWith('.css')) return 'estatico';
  if (lower.includes('?')) return 'dinamico';

  return 'general';
}

function buscarInfoHttpx(url, herramientas) {
  return herramientas?.httpx?.find(item =>
    item.url === url ||
    item.input === url ||
    normalizarUrl(item.url) === normalizarUrl(url)
  ) || null;
}

function buscarHallazgosNuclei(url, hallazgos) {
  return hallazgos.filter(h =>
    h.url === url ||
    normalizarUrl(h.url) === normalizarUrl(url)
  );
}

function buscarHallazgosDalfox(url, herramientas) {
  return herramientas?.dalfox?.filter(item => {
    const raw = JSON.stringify(item);
    return raw.includes(url) || raw.includes(normalizarUrl(url));
  }) || [];
}

function buscarResultadoSqlmap(url, herramientas) {
  return herramientas?.sqlmap?.find(item =>
    item.url === url ||
    normalizarUrl(item.url) === normalizarUrl(url)
  ) || null;
}

function parsearEndpoint(url, herramientas = {}, hallazgos = []) {
  const parametros = obtenerParametros(url);
  const httpx = buscarInfoHttpx(url, herramientas);
  const nuclei = buscarHallazgosNuclei(url, hallazgos);
  const dalfox = buscarHallazgosDalfox(url, herramientas);
  const sqlmap = buscarResultadoSqlmap(url, herramientas);

  return {
    url,
    path: obtenerPath(url),
    tieneParametros: parametros.length > 0,
    parametros,
    categoria: categorizarEndpoint(url),

    evidencias: {
      http: httpx
        ? {
            statusCode: httpx.statusCode,
            title: httpx.title,
            tecnologias: httpx.tecnologias || [],
            webserver: httpx.webserver || null,
            contentLength: httpx.contentLength || null,
            location: httpx.location || null
          }
        : null,

      nuclei: nuclei.map(h => ({
        id: h.id,
        severidad: h.severidad,
        descripcion: h.descripcion,
        impacto: h.impacto,
        etiquetas: h.etiquetas
      })),

      xss: {
        probado: herramientas?.dalfox !== undefined,
        confirmado: dalfox.length > 0,
        resultados: dalfox
      },

      sqli: {
        probado: !!sqlmap,
        confirmado: !!sqlmap?.vulnerable,
        evidencia: sqlmap?.evidencia || null,
        resumen: sqlmap?.resumen || [],
        error: sqlmap?.error || null
      }
    }
  };
}

function parsearHallazgo(linea) {
  const limpia = limpiarColoresANSI(linea);

  const regex = /\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+([^\s]+)/;
  const match = limpia.match(regex);

  if (!match) {
    return {
      id: 'desconocido',
      tipo: 'desconocido',
      severidad: 'info',
      url: null,
      raw: limpia
    };
  }

  return {
    id: match[1],
    tipo: match[2],
    severidad: match[3],
    url: match[4],
    raw: limpia
  };
}

function enriquecerHallazgo(hallazgo) {
  const reglas = {
    'swagger-api': {
      descripcion: 'Se ha detectado una interfaz Swagger expuesta.',
      impacto: 'Puede revelar documentación de API, rutas internas y parámetros disponibles.',
      recomendacion: 'Restringir el acceso público a Swagger o protegerlo mediante autenticación.',
      etiquetas: ['api', 'swagger', 'exposicion']
    },
    'waf-detect': {
      descripcion: 'Se ha detectado un posible WAF o mecanismo de protección web.',
      impacto: 'Hallazgo informativo sobre defensas existentes.',
      recomendacion: 'Revisar la configuración del WAF y validar que protege los endpoints críticos.',
      etiquetas: ['waf', 'fingerprinting']
    },
    'weak-cipher-suites': {
      descripcion: 'Se han detectado suites criptográficas débiles.',
      impacto: 'Puede reducir la seguridad de las comunicaciones TLS.',
      recomendacion: 'Deshabilitar TLS antiguo y suites criptográficas débiles.',
      etiquetas: ['tls', 'ssl', 'cifrado']
    }
  };

  const clave = Object.keys(reglas).find(k => hallazgo.id.startsWith(k));

  return {
    ...hallazgo,
    ...(reglas[clave] || {
      descripcion: 'Hallazgo detectado por la herramienta de análisis.',
      impacto: 'Requiere revisión manual para determinar su impacto real.',
      recomendacion: 'Analizar el hallazgo y aplicar medidas correctivas si procede.',
      etiquetas: ['general']
    })
  };
}

function procesarResultados(reconocimiento) {
  const hallazgos = reconocimiento.vulnerabilidades
    .map(parsearHallazgo)
    .map(enriquecerHallazgo);

  const endpoints = reconocimiento.endpoints.map(endpoint =>
    parsearEndpoint(endpoint, reconocimiento.herramientas, hallazgos)
  );

  return {
    ...reconocimiento,
    endpoints,
    hallazgos
  };
}

module.exports = {
  procesarResultados
};