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
  aplicarScoring,
  calcularRiskScore
};

const HARDENING_TYPES_SCORE = new Set([
  'missing_security_header',
  'insecure_cookie',
  'missing_https_redirect',
  'tls_certificate_issue',
  'hardening'
]);

const DATA_PORTS = new Set([3306, 5432, 6379, 9200, 27017]);
const WEB_ALT_PORTS = new Set([8080, 8443, 8000, 3000, 5000]);

function extraerPuerto(finding = {}) {
  if (finding.port) return Number(finding.port);
  const raw = finding.affected_url || finding.affected_asset || '';
  const match = String(raw).match(/:(\d+)(?:\/|$)/);
  return match ? Number(match[1]) : null;
}

function tieneEvidenciaSqlmap(finding = {}) {
  const texto = [
    finding.payload,
    finding.dbms,
    finding.parametro,
    finding.parameter,
    finding.evidence
  ].filter(Boolean).join(' ').toLowerCase();

  return Boolean(finding.payload || finding.dbms || finding.parametro || finding.parameter) &&
    !texto.includes('no confirmo');
}

function nivelRiesgo(score) {
  if (score === null || score === undefined) return 'N/D';
  if (score <= 20) return 'bajo';
  if (score <= 40) return 'moderado';
  if (score <= 60) return 'medio';
  if (score <= 80) return 'alto';
  return 'critico';
}

function gradoRiesgo(score) {
  if (score === null || score === undefined) return 'N/D';
  if (score <= 20) return 'A';
  if (score <= 40) return 'B';
  if (score <= 60) return 'C';
  if (score <= 80) return 'D';
  return 'E';
}

function sumarConCap(acumulado, key, valor, caps) {
  const actual = acumulado[key] || 0;
  const cap = caps[key] ?? Number.POSITIVE_INFINITY;
  const aplicado = Math.max(0, Math.min(valor, cap - actual));
  acumulado[key] = actual + aplicado;
  return aplicado;
}

function puntuarFinding(finding = {}, acumulado, caps) {
  const tool = String(finding.tool || '').toLowerCase();
  const type = String(finding.type || '').toLowerCase();
  const severity = String(finding.severity || 'info').toLowerCase();
  const confidence = String(finding.confidence || 'low').toLowerCase();

  if (type === 'discarded' || finding.isFalsePositiveLikely) return 0;
  if (tool === 'gf' || type === 'gf-candidate') return sumarConCap(acumulado, 'gf', 1, caps);

  if (tool === 'trufflehog' || type === 'exposed-secret') {
    return finding.verified || confidence === 'high' ? 40 : 15;
  }

  if (tool === 'ports') {
    const port = extraerPuerto(finding);
    if (DATA_PORTS.has(port)) return 25;
    if (WEB_ALT_PORTS.has(port)) return sumarConCap(acumulado, 'surface', 4, caps);
    return 0;
  }

  if (HARDENING_TYPES_SCORE.has(type)) {
    const valor = severity === 'medium' ? 4 : severity === 'low' ? 2 : severity === 'high' ? 8 : 0;
    return sumarConCap(acumulado, 'hardening', valor, caps);
  }

  if (type === 'surface') {
    return sumarConCap(acumulado, 'surface', severity === 'medium' ? 5 : 2, caps);
  }

  if (type === 'reconocimiento' || severity === 'info' || finding.isVulnerability !== true) return 0;

  if (tool === 'sqlmap' && finding.status === 'possible_sqli' && !tieneEvidenciaSqlmap(finding)) {
    return 3;
  }

  if (confidence === 'high' || confidence === 'confirmed') {
    if (severity === 'critical') return 45;
    if (severity === 'high') return 35;
    if (severity === 'medium') return 22;
    if (severity === 'low') return 10;
  }

  if (confidence === 'medium') {
    if (severity === 'high') return 15;
    if (severity === 'medium') return 8;
    if (severity === 'low') return 3;
  }

  return severity === 'low' ? 1 : 0;
}

function calcularRiskScore(findings = []) {
  if (!Array.isArray(findings) || findings.length === 0) {
    return {
      risk_score: null,
      risk_level: 'N/D',
      risk_grade: 'N/D'
    };
  }

  const caps = {
    hardening: 20,
    gf: 5,
    surface: 15
  };
  const acumulado = {};
  const total = findings.reduce((sum, finding) => sum + puntuarFinding(finding, acumulado, caps), 0);
  const risk_score = Math.min(100, Math.max(0, Math.round(total)));

  return {
    risk_score,
    risk_level: nivelRiesgo(risk_score),
    risk_grade: gradoRiesgo(risk_score)
  };
}
