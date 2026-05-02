const PESOS_SEVERIDAD = {
  info: 1,
  low: 2,
  medium: 5,
  high: 8,
  critical: 10
};

function obtenerCriticidad(severidad) {
  return PESOS_SEVERIDAD[severidad] || 1;
}

function calcularDistribucionSeveridad(hallazgos) {
  const distribucion = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0
  };

  hallazgos.forEach(hallazgo => {
    if (distribucion[hallazgo.severidad] !== undefined) {
      distribucion[hallazgo.severidad]++;
    }
  });

  return distribucion;
}

function calcularScore(hallazgos) {
  return hallazgos.reduce((total, hallazgo) => {
    return total + obtenerCriticidad(hallazgo.severidad);
  }, 0);
}

function calcularRiesgoGlobal(score) {
  if (score >= 50) return 'critico';
  if (score >= 26) return 'alto';
  if (score >= 11) return 'medio';
  if (score >= 4) return 'bajo';
  return 'informativo';
}

function aplicarScoring(datos) {
  const hallazgosConCriticidad = datos.hallazgos.map(hallazgo => ({
    ...hallazgo,
    criticidad: obtenerCriticidad(hallazgo.severidad)
  }));

  const score = calcularScore(hallazgosConCriticidad);
  const distribucionSeveridad = calcularDistribucionSeveridad(hallazgosConCriticidad);

  return {
    ...datos,
    hallazgos: hallazgosConCriticidad,
    resumen: {
      totalSubdominios: datos.subdominios.length,
      totalActivos: datos.activos.length,
      totalEndpoints: datos.endpoints.length,
      totalHallazgos: hallazgosConCriticidad.length,
      riesgoGlobal: calcularRiesgoGlobal(score),
      score
    },
    distribucionSeveridad
  };
}

module.exports = {
  aplicarScoring
};