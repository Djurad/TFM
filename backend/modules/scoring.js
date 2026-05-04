// Pesos base para hallazgos detectados por herramientas como Nuclei.
const PESOS_SEVERIDAD = {
  info: 1,
  low: 2,
  medium: 5,
  high: 8,
  critical: 10
};

// Pesos base para endpoints según su tipo funcional.
// Estos valores representan exposición potencial, no vulnerabilidad confirmada.
const PESOS_ENDPOINT = {
  general: 1,
  estatico: 0,
  javascript: 1,
  dinamico: 2,
  formulario: 3,
  busqueda: 3,
  login: 4,
  admin: 5,
  'api-docs': 3
};

// Convierte una severidad textual en un valor numérico de criticidad.
function obtenerCriticidadHallazgo(severidad) {
  return PESOS_SEVERIDAD[severidad] || 1;
}

// Calcula la criticidad de un endpoint combinando categoría, evidencias y contexto.
function obtenerCriticidadEndpoint(endpoint) {
  const evidencias = endpoint.evidencias || {};

  // Vulnerabilidades confirmadas
  // SQLi y XSS confirmadas tienen prioridad sobre cualquier otro cálculo.
  if (evidencias.sqli?.confirmado) return 10;
  if (evidencias.xss?.confirmado) return 8;

  // Hallazgos Nuclei asociados al endpoint
  const maxNuclei = Math.max(
    0,
    ...(evidencias.nuclei || []).map(h => obtenerCriticidadHallazgo(h.severidad))
  );

  // Parte del peso base según la categoría asignada durante el procesamiento.
  let criticidad = PESOS_ENDPOINT[endpoint.categoria] ?? 1;

  // Superficie de ataque
  // Los parámetros aumentan el riesgo porque suelen recibir entrada del usuario.
  if (endpoint.tieneParametros) criticidad += 1;

  // Parámetros usados en redirecciones o contenido dinámico elevan el riesgo potencial.
  if (endpoint.parametros?.includes('url')) criticidad += 2;
  if (endpoint.parametros?.includes('redirect')) criticidad += 2;
  if (endpoint.parametros?.includes('content')) criticidad += 1;

  const path = endpoint.path?.toLowerCase() || '';

  // Algunas palabras en la ruta indican funcionalidades sensibles.
  if (path.includes('admin')) criticidad += 2;
  if (path.includes('login')) criticidad += 1;
  if (path.includes('swagger')) criticidad += 1;

  // Contexto HTTP
  const status = evidencias.http?.statusCode;

  // Un recurso protegido reduce ligeramente la exposición directa.
  if (status === 401 || status === 403) {
    criticidad -= 1;
  }

  // Errores del servidor pueden indicar comportamiento inestable o información útil.
  if (status >= 500) {
    criticidad += 1;
  }

  // Si Nuclei detecta algo más grave, manda Nuclei
  criticidad = Math.max(criticidad, maxNuclei);

  // Limita el resultado final al rango 0-10.
  return Math.max(0, Math.min(criticidad, 10));
}

// Traduce la criticidad numérica a una etiqueta legible.
function nivelCriticidad(valor) {
  if (valor >= 9) return 'critico';
  if (valor >= 7) return 'alto';
  if (valor >= 4) return 'medio';
  if (valor >= 2) return 'bajo';
  return 'informativo';
}

// Cuenta cuántos hallazgos hay por severidad técnica.
function calcularDistribucionSeveridad(hallazgos) {
  const distribucion = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0
  };

  hallazgos.forEach(h => {
    if (distribucion[h.severidad] !== undefined) {
      distribucion[h.severidad]++;
    }
  });

  return distribucion;
}

// Cuenta cuántos endpoints hay por nivel de criticidad calculado.
function calcularDistribucionEndpoints(endpoints) {
  const distribucion = {
    informativo: 0,
    bajo: 0,
    medio: 0,
    alto: 0,
    critico: 0
  };

  endpoints.forEach(endpoint => {
    if (distribucion[endpoint.nivelCriticidad] !== undefined) {
      distribucion[endpoint.nivelCriticidad]++;
    }
  });

  return distribucion;
}

// Calcula un score global sumando hallazgos confirmados y exposición de endpoints.
function calcularScoreGlobal(hallazgos, endpoints) {
  // Los hallazgos pesan completos porque representan detecciones concretas.
  const scoreHallazgos = hallazgos.reduce(
    (total, h) => total + h.criticidad,
    0
  );

  // Los endpoints aportan contexto de superficie de ataque.
  const scoreEndpoints = endpoints.reduce(
    (total, e) => total + e.criticidad,
    0
  );

  // Los endpoints son superficie, no vulnerabilidades.
  const scoreSuperficie = Math.min(Math.round(scoreEndpoints * 0.2), 30);

  return scoreHallazgos + scoreSuperficie;
}

// Convierte el score global en una etiqueta de riesgo general.
function calcularRiesgoGlobal(score) {
  if (score >= 80) return 'critico';
  if (score >= 50) return 'alto';
  if (score >= 25) return 'medio';
  if (score >= 8) return 'bajo';
  return 'informativo';
}

// Añade scoring, resumen y distribuciones al objeto procesado.
function aplicarScoring(datos) {
  // Enriquece cada hallazgo con criticidad numérica y nivel textual.
  const hallazgos = datos.hallazgos.map(hallazgo => {
    const criticidad = obtenerCriticidadHallazgo(hallazgo.severidad);

    return {
      ...hallazgo,
      criticidad,
      nivelCriticidad: nivelCriticidad(criticidad)
    };
  });

  // Enriquece cada endpoint con criticidad calculada según reglas de riesgo.
  const endpoints = datos.endpoints.map(endpoint => {
    const criticidad = obtenerCriticidadEndpoint(endpoint);

    return {
      ...endpoint,
      criticidad,
      nivelCriticidad: nivelCriticidad(criticidad)
    };
  });

  const score = calcularScoreGlobal(hallazgos, endpoints);

  // Mantiene los datos originales y añade métricas agregadas para el informe.
  return {
    ...datos,
    endpoints,
    hallazgos,
    resumen: {
      totalSubdominios: datos.subdominios.length,
      totalActivos: datos.activos.length,
      totalEndpoints: endpoints.length,
      totalEndpointsCriticos: endpoints.filter(e => e.nivelCriticidad === 'critico').length,
      totalEndpointsAltos: endpoints.filter(e => e.nivelCriticidad === 'alto').length,
      totalHallazgos: hallazgos.length,
      riesgoGlobal: calcularRiesgoGlobal(score),
      score
    },
    distribucionSeveridad: calcularDistribucionSeveridad(hallazgos),
    distribucionCriticidadEndpoints: calcularDistribucionEndpoints(endpoints)
  };
}

module.exports = {
  aplicarScoring
};
