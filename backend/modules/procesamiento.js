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

function categorizarEndpoint(url) {
  const lower = url.toLowerCase();

  if (lower.includes('login')) return 'login';
  if (lower.includes('swagger')) return 'api-docs';
  if (lower.includes('admin')) return 'admin';
  if (lower.includes('search')) return 'busqueda';
  if (lower.includes('feedback')) return 'formulario';
  if (lower.includes('?')) return 'dinamico';
  if (lower.endsWith('.js')) return 'javascript';
  if (lower.endsWith('.css')) return 'estatico';

  return 'general';
}

function parsearEndpoint(url) {
  const parametros = obtenerParametros(url);

  return {
    url,
    path: obtenerPath(url),
    tieneParametros: parametros.length > 0,
    parametros,
    categoria: categorizarEndpoint(url)
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
  const endpoints = reconocimiento.endpoints.map(parsearEndpoint);

  const hallazgos = reconocimiento.vulnerabilidades
    .map(parsearHallazgo)
    .map(enriquecerHallazgo);

  return {
    ...reconocimiento,
    endpoints,
    hallazgos
  };
}

module.exports = {
  procesarResultados
};