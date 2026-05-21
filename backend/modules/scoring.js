const PESOS_SEVERIDAD = {
  info: 0,
  low: 2,
  medium: 5,
  high: 8,
  critical: 10
};

function obtenerCriticidadHallazgo(severidad) {
  return PESOS_SEVERIDAD[severidad] || 0;
}

function esHallazgoPuntuable(hallazgo = {}) {
  return hallazgo.isVulnerability === true &&
    ['high', 'medium'].includes(hallazgo.confidence) &&
    hallazgo.isFalsePositiveLikely !== true &&
    !['reconocimiento', 'surface', 'discarded', 'hardening'].includes(hallazgo.type);
}

function obtenerCriticidadEndpoint(endpoint) {
  const evidencias = endpoint.evidencias || {};

  if (evidencias.sqli?.confirmado) return 10;
  if (evidencias.xss?.confirmado) return 8;

  return 0;
}

function nivelCriticidad(valor) {
  if (valor >= 9) return 'critico';
  if (valor >= 7) return 'alto';
  if (valor >= 4) return 'medio';
  if (valor >= 2) return 'bajo';
  return 'informativo';
}

function calcularDistribucionSeveridad(hallazgos) {
  const distribucion = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0
  };

  hallazgos.filter(esHallazgoPuntuable).forEach(h => {
    const severity = h.severity || h.severidad;
    if (distribucion[severity] !== undefined) {
      distribucion[severity]++;
    }
  });

  return distribucion;
}

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

function calcularScoreGlobal(hallazgos) {
  return hallazgos.filter(esHallazgoPuntuable).reduce(
    (total, h) => total + h.criticidad,
    0
  );
}

function calcularRiesgoGlobal(score) {
  if (score >= 80) return 'critico';
  if (score >= 50) return 'alto';
  if (score >= 25) return 'medio';
  if (score >= 8) return 'bajo';
  return 'informativo';
}

function aplicarScoring(datos) {
  console.log('[Scoring] usando solo confirmadas + posibles');

  const hallazgos = datos.hallazgos.map(hallazgo => {
    const criticidad = esHallazgoPuntuable(hallazgo)
      ? obtenerCriticidadHallazgo(hallazgo.severity || hallazgo.severidad)
      : 0;

    return {
      ...hallazgo,
      criticidad,
      nivelCriticidad: nivelCriticidad(criticidad)
    };
  });

  const endpoints = datos.endpoints.map(endpoint => {
    const criticidad = obtenerCriticidadEndpoint(endpoint);

    return {
      ...endpoint,
      criticidad,
      nivelCriticidad: nivelCriticidad(criticidad)
    };
  });

  const score = calcularScoreGlobal(hallazgos);
  const hallazgosPuntuables = hallazgos.filter(esHallazgoPuntuable);

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
      totalHallazgos: hallazgosPuntuables.length,
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
