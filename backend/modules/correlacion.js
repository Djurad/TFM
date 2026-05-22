const HARDENING_TYPES = new Set([
  'missing_security_header',
  'insecure_cookie',
  'missing_https_redirect',
  'tls_certificate_issue',
  'hardening'
]);

function normalizarUrl(valor = '') {
  try {
    const parsed = new URL(valor);
    parsed.hash = '';
    const params = Array.from(parsed.searchParams.entries()).sort(([a], [b]) => a.localeCompare(b));
    parsed.search = '';
    params.forEach(([key, value]) => parsed.searchParams.append(key, value));
    return `${parsed.origin}${parsed.pathname}${parsed.search}`.replace(/\/$/, '').toLowerCase();
  } catch {
    return String(valor || '').replace(/\/$/, '').toLowerCase();
  }
}

function origenYRuta(valor = '') {
  try {
    const parsed = new URL(valor);
    return `${parsed.origin}${parsed.pathname}`.replace(/\/$/, '').toLowerCase();
  } catch {
    return normalizarUrl(valor).split('?')[0];
  }
}

function parametro(finding = {}) {
  if (finding.parametro || finding.parameter || finding.param) {
    return String(finding.parametro || finding.parameter || finding.param).toLowerCase();
  }

  try {
    const url = new URL(finding.affected_url || '');
    return Array.from(url.searchParams.keys()).sort().join(',');
  } catch {
    return '';
  }
}

function mismaZona(a = {}, b = {}) {
  const urlA = a.affected_url || a.raw_reference || '';
  const urlB = b.affected_url || b.raw_reference || '';
  if (!urlA || !urlB) return false;
  const pathOk = origenYRuta(urlA) === origenYRuta(urlB) || normalizarUrl(urlA) === normalizarUrl(urlB);
  const paramA = parametro(a);
  const paramB = parametro(b);
  return pathOk && (!paramA || !paramB || paramA === paramB);
}

function crearRelacion({ severity = 'info', title, chain, description, findings }) {
  return {
    severity,
    title,
    chain,
    description,
    related_ids: findings.map(f => f.id).filter(Boolean)
  };
}

function addNota(finding, texto, correlationId) {
  if (!finding) return;
  finding.correlation_notes = Array.from(new Set([...(finding.correlation_notes || []), texto]));
  finding.related_findings = Array.from(new Set([...(finding.related_findings || []), correlationId].filter(Boolean)));
}

function correlacionarFindings(findings = [], toolResults = {}) {
  const enriquecidos = findings.map(finding => ({
    ...finding,
    related_findings: Array.isArray(finding.related_findings) ? finding.related_findings : [],
    correlation_notes: Array.isArray(finding.correlation_notes) ? finding.correlation_notes : []
  }));
  const correlations = [];

  const byTool = tool => enriquecidos.filter(f => f.tool === tool);
  const gf = byTool('gf');
  const katana = byTool('katana');
  const dalfox = byTool('dalfox');
  const sqlmap = byTool('sqlmap');
  const headers = byTool('headers');
  const httpsRedirect = enriquecidos.filter(f => f.type === 'missing_https_redirect' || f.tool === 'httpsredirect');
  const ports = byTool('ports');

  dalfox
    .filter(f => f.confidence === 'high' || f.confidence === 'confirmed')
    .forEach(xss => {
      const gfXss = gf.find(candidate =>
        String(candidate.vulnerability_type || '').toLowerCase() === 'xss' && mismaZona(candidate, xss)
      );
      const katanaEndpoint = katana.find(endpoint => mismaZona(endpoint, xss));

      if (gfXss || katanaEndpoint) {
        const related = [katanaEndpoint, gfXss, xss].filter(Boolean);
        const correlation = crearRelacion({
          severity: 'high',
          title: 'Cadena Katana/GF/Dalfox',
          chain: related.map(f => f.tool),
          description: 'Katana descubrio el endpoint, GF lo priorizo como candidato XSS y Dalfox confirmo explotacion reflejada.',
          findings: related
        });
        correlations.push(correlation);
        related.forEach(f => addNota(f, correlation.description, correlation.title));
      }

      const csp = headers.find(f => String(f.header || '').toLowerCase() === 'content-security-policy');
      if (csp) {
        const correlation = crearRelacion({
          severity: 'medium',
          title: 'XSS confirmado agravado por CSP ausente',
          chain: ['dalfox', 'headers'],
          description: 'La ausencia de CSP incrementa el impacto potencial del XSS confirmado en cliente.',
          findings: [xss, csp]
        });
        correlations.push(correlation);
        addNota(xss, correlation.description, correlation.title);
        addNota(csp, correlation.description, correlation.title);
      }
    });

  gf
    .filter(candidate => String(candidate.vulnerability_type || '').toLowerCase() === 'sqli')
    .forEach(candidate => {
      const sql = sqlmap.find(item => mismaZona(candidate, item));
      if (!sql) return;
      const confirmada = sql.status === 'confirmed_sqli' || sql.confidence === 'high';
      const description = confirmada
        ? 'GF priorizo el endpoint como candidato SQLi y sqlmap obtuvo evidencia de inyeccion.'
        : 'GF priorizo el endpoint como candidato SQLi, pero sqlmap no obtuvo evidencia concluyente.';
      const correlation = crearRelacion({
        severity: confirmada ? 'high' : 'low',
        title: confirmada ? 'GF/SQLMap confirmado' : 'GF/SQLMap no concluyente',
        chain: ['gf', 'sqlmap'],
        description,
        findings: [candidate, sql]
      });
      correlations.push(correlation);
      addNota(candidate, description, correlation.title);
      addNota(sql, description, correlation.title);
    });

  const hsts = headers.find(f => String(f.header || '').toLowerCase() === 'strict-transport-security');
  if (hsts && httpsRedirect.length) {
    const redirect = httpsRedirect[0];
    const correlation = crearRelacion({
      severity: 'medium',
      title: 'HTTPS redirect y HSTS ausentes',
      chain: ['httpsRedirect', 'headers'],
      description: 'La falta combinada de redireccion HTTPS y HSTS incrementa el riesgo de downgrade o navegacion insegura.',
      findings: [redirect, hsts]
    });
    correlations.push(correlation);
    addNota(redirect, correlation.description, correlation.title);
    addNota(hsts, correlation.description, correlation.title);
  }

  katana
    .filter(f => /swagger|openapi/i.test(`${f.title} ${f.affected_url} ${f.evidence}`))
    .forEach(swagger => {
      const correlation = crearRelacion({
        severity: 'info',
        title: 'Swagger expone superficie API',
        chain: ['katana'],
        description: 'Swagger expone superficie util para revision manual de endpoints API.',
        findings: [swagger]
      });
      correlations.push(correlation);
      addNota(swagger, correlation.description, correlation.title);
    });

  ports
    .filter(f => [8080, 8443, 8000, 3000, 5000].includes(Number(f.port)))
    .forEach(port => {
      const correlation = crearRelacion({
        severity: 'low',
        title: `Puerto web alternativo ${port.port}`,
        chain: ['ports'],
        description: `El puerto ${port.port} expone una superficie web alternativa que requiere revision.`,
        findings: [port]
      });
      correlations.push(correlation);
      addNota(port, correlation.description, correlation.title);
    });

  const vistos = new Set();
  const dedup = correlations.filter(correlation => {
    const key = `${correlation.title}|${correlation.related_ids.join(',')}`;
    if (vistos.has(key)) return false;
    vistos.add(key);
    return true;
  });

  return {
    findings: enriquecidos,
    correlations: dedup
  };
}

module.exports = {
  correlacionarFindings,
  normalizarUrl,
  origenYRuta,
  parametro
};
