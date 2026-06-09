const express = require('express');
const cors = require('cors');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env'), override: true });
const { generarPdfAuditoria } = require('./modules/pdf/pdfGenerator');
const { ejecutarReconocimiento } = require('./modules/reconocimiento/reconocimiento');
const { enriquecerFindingsIA } = require('./modules/ia/ia');
const { normalizarFindings } = require('./modules/procesamiento/normalizacion');
const { extraerFindingsDeterministas } = require('./modules/procesamiento/extractores');
const { clasificarFindings } = require('./modules/procesamiento/clasificadorFindings');
const { calcularRiskScore } = require('./modules/priorizacion/scoring');
const { correlacionarFindings, normalizarUrl, origenYRuta, parametro } = require('./modules/priorizacion/correlacion');
const { crearScanLogger } = require('./scanLogger');
const {
  buildDashboardMetrics,
  buildFindingGroups,
  normalizeFindingsForReporting
} = require('./modules/priorizacion/findingGroups');

const app = express();
const PORT = 3000;
app.use(cors());

app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, '..', 'frontend')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

function serializarToolResult(result) {
  return {
    status: result.status,
    findings: result.findings || [],
    parsed_count: Array.isArray(result.parsed) ? result.parsed.length : null,
    raw_length: typeof result.raw === 'string' ? result.raw.length : 0,
    error: result.error || null,
    warning: result.warning || null,
    metrics: result.metrics || {}
  };
}

function agruparFindings(findings = []) {
  return buildFindingGroups(findings);
}

function construirCandidatosGf(toolResults = {}) {
  const parsed = toolResults.gf?.parsed || {};
  return {
    xss: parsed.xssCandidates || [],
    sqli: parsed.sqliCandidates || [],
    ssrf: parsed.ssrfCandidates || [],
    redirect: parsed.redirectCandidates || [],
    lfi: parsed.lfiCandidates || [],
    rce: parsed.rceCandidates || []
  };
}

function construirResumenUI(grupos) {
  const confirmadas = grupos.confirmed?.length || grupos.confirmadas?.length || 0;
  const posibles = grupos.possible?.length || grupos.posibles?.length || 0;
  const gfCandidates = grupos.gfCandidates?.length || grupos.gf_candidates?.length || 0;
  const hardening = grupos.hardening?.length || 0;
  const superficie = grupos.attackSurface?.length || grupos.superficie?.length || 0;
  const informativos = grupos.informational?.length || grupos.reconocimiento?.length || 0;
  const descartados = grupos.discarded?.length || grupos.descartados?.length || 0;
  const falsePositives = grupos.falsePositives?.length || grupos.baja_confianza?.length || 0;

  return {
    confirmadas,
    posibles,
    gf_candidates: gfCandidates,
    total_vulnerabilidades: confirmadas + posibles,
    hardening,
    superficie,
    informativos,
    reconocimiento: informativos,
    descartados,
    false_positives: falsePositives
  };
}

function claveFinding(finding = {}) {
  const normalizedUrl = normalizarUrl(finding.affected_url || finding.affected_asset || '');
  const param = parametro(finding);

  if (finding.tool === 'ports' && finding.port) {
    return `ports|${finding.affected_asset || ''}|${finding.port}|tcp`.toLowerCase();
  }

  if (finding.tool === 'katana' && /swagger|openapi/i.test(`${finding.title} ${finding.affected_url}`)) {
    return `surface|swagger|${normalizedUrl}`.toLowerCase();
  }

  return [
    finding.type || '',
    finding.vulnerability_type || '',
    normalizedUrl,
    param,
    finding.type || '',
    finding.tool || ''
  ].join('|').toLowerCase();
}

function deduplicarFindings(findings = []) {
  const mapa = new Map();
  const confirmadosXss = new Set(
    findings
      .filter(f => f.tool === 'dalfox' && (f.confidence === 'high' || f.confidence === 'confirmed'))
      .map(f => `${origenYRuta(f.affected_url || '')}|${parametro(f)}`)
  );

  findings.forEach(finding => {
    if (finding.tool === 'gf' && finding.vulnerability_type === 'xss') {
      const keyXss = `${origenYRuta(finding.affected_url || '')}|${parametro(finding)}`;
      if (confirmadosXss.has(keyXss)) return;
    }

    const key = claveFinding(finding);
    if (!mapa.has(key)) mapa.set(key, finding);
  });

  return Array.from(mapa.values());
}

function etiquetaRiesgo(risk = {}) {
  if (risk.risk_score === null || risk.risk_score === undefined) return 'N/D';
  return `${risk.risk_score}/100 riesgo ${risk.risk_level}`;
}

function construirPipelineTimeline(toolResults = {}, counters = {}, correlations = [], risk = {}) {
  const orden = [
    'subfinder',
    'httpx',
    'headers',
    'cookies',
    'httpsRedirect',
    'tls',
    'robotsSitemap',
    'ports',
    'feroxbuster',
    'katana',
    'gau',
    'gf',
    'nuclei',
    'dalfox',
    'sqlmap',
    'trufflehog'
  ];

  const detalle = (tool, result = {}) => {
    const counter = counters[tool] || {};
    if (tool === 'subfinder') return `${counter.subdominios_encontrados || result.parsed_count || 0} subdominios`;
    if (tool === 'httpx') {
      const activos = counter.activos_vivos || result.metrics?.activos_vivos || result.parsed_count || 0;
      const respuestas = counter.respuestas_httpx || result.metrics?.respuestas_httpx || 0;
      return respuestas > activos && activos > 0
        ? `${respuestas} respuestas / ${activos} unico${activos === 1 ? '' : 's'}`
        : `${activos} vivos`;
    }
    if (tool === 'headers') return `${counter.cabeceras_ausentes || 0} ausentes / ${counter.banners_expuestos || 0} banners`;
    if (tool === 'cookies') return `${counter.cookies_inseguras || 0} inseguras / ${counter.cookies_sesion || 0} sesion`;
    if (tool === 'httpsRedirect') return `${counter.redirecciona_https || 0} HTTPS ok / ${counter.http_sin_redirect || 0} HTTP abierto`;
    if (tool === 'tls') return `${counter.certificados_analizados || 0} certs / ${counter.expirados || 0} expirados`;
    if (tool === 'robotsSitemap') return `${counter.recursos_encontrados || 0} recursos / ${counter.rutas_sensibles || 0} sensibles`;
    if (tool === 'ports') return `${counter.puertos_abiertos || 0} abiertos${counter.source ? ` / ${counter.source}` : ''}`;
    if (tool === 'feroxbuster') return `${counter.rutas_descubiertas || 0} rutas / ${counter.rutas_sensibles || 0} sensibles`;
    if (tool === 'katana') return `${counter.endpoints_encontrados || result.parsed_count || 0} endpoints / ${counter.superficie_util || 0} superficie`;
    if (tool === 'gau') {
      const raw = counter.raw_urls || result.metrics?.raw_urls || 0;
      const selected = counter.seleccionadas_final || counter.endpoints_encontrados || result.parsed_count || 0;
      return `${raw} analizadas / ${selected} seleccionadas / ${counter.con_parametros || 0} params`;
    }
    if (tool === 'gf') return `${counter.xss || 0} XSS / ${counter.sqli || 0} SQLi / ${counter.ssrf || 0} SSRF`;
    if (tool === 'nuclei') return `${counter.vulnerabilidades_reales || 0} vulnerabilidades`;
    if (tool === 'dalfox') return `${(result.findings || []).length} hallazgos`;
    if (tool === 'sqlmap') return counter.no_ejecutada ? 'no ejecutada' : `${counter.confirmadas || 0} confirmadas / ${counter.posibles || 0} posibles`;
    if (tool === 'trufflehog') return `${counter.secretos_confirmados || 0} confirmados / ${counter.secretos_posibles || 0} posibles`;
    return `${(result.findings || []).length} hallazgos`;
  };

  return [
    ...orden.map(tool => {
      const result = toolResults[tool] || {};
      const status = result.status || 'skipped';
      const important = (result.findings || []).some(f => f.isVulnerability && !f.isFalsePositiveLikely && f.tool !== 'gf');
      return {
        tool,
        status,
        detail: detalle(tool, result),
        duration_ms: result.metrics?.duration_ms || null,
        important
      };
    }),
    {
      tool: 'correlacion',
      status: 'success',
      detail: `${correlations.length} relaciones detectadas`,
      duration_ms: null,
      important: correlations.length > 0
    },
    {
      tool: 'score final',
      status: risk.risk_score === null ? 'skipped' : 'success',
      detail: etiquetaRiesgo(risk),
      duration_ms: null,
      important: risk.risk_score >= 41
    },
    {
      tool: 'informe',
      status: 'ready',
      detail: 'PDF disponible',
      duration_ms: null,
      important: false
    }
  ];
}

function resumenHerramientas(reconocimiento, toolResults, findings) {
  const sqlmap = toolResults.sqlmap?.parsed || [];
  const gfParsed = toolResults.gf?.parsed || {};
  return {
    subfinder: {
      subdominios_encontrados: reconocimiento.subdominios?.length || 0
    },
    httpx: {
      respuestas_httpx: toolResults.httpx?.metrics?.respuestas_httpx || toolResults.httpx?.parsed_count || 0,
      activos_vivos: reconocimiento.activos?.length || toolResults.httpx?.metrics?.activos_vivos || 0,
      duplicados_httpx: toolResults.httpx?.metrics?.duplicados_httpx || 0,
      entradas_httpx: toolResults.httpx?.metrics?.entradas_httpx || 0
    },
    headers: {
      activos_analizados: toolResults.headers?.metrics?.activos_analizados || 0,
      cabeceras_ausentes: toolResults.headers?.metrics?.cabeceras_ausentes || 0,
      banners_expuestos: toolResults.headers?.metrics?.banners_expuestos || 0
    },
    cookies: {
      cookies_analizadas: toolResults.cookies?.metrics?.cookies_analizadas || 0,
      cookies_sesion: toolResults.cookies?.metrics?.cookies_sesion || 0,
      cookies_inseguras: toolResults.cookies?.metrics?.cookies_inseguras || 0
    },
    httpsRedirect: {
      redirecciona_https: toolResults.httpsRedirect?.metrics?.redirecciona_https || 0,
      http_sin_redirect: toolResults.httpsRedirect?.metrics?.http_sin_redirect || 0
    },
    tls: {
      certificados_analizados: toolResults.tls?.metrics?.certificados_analizados || 0,
      expirados: toolResults.tls?.metrics?.expirados || 0,
      proximos_expirar: toolResults.tls?.metrics?.proximos_expirar || 0,
      errores_tls: toolResults.tls?.metrics?.errores_tls || 0
    },
    robotsSitemap: {
      recursos_encontrados: toolResults.robotsSitemap?.metrics?.recursos_encontrados || 0,
      rutas_sensibles: toolResults.robotsSitemap?.metrics?.rutas_sensibles || 0
    },
    ports: {
      puertos_abiertos: toolResults.ports?.metrics?.puertos_abiertos || 0,
      puertos_datos: toolResults.ports?.metrics?.puertos_datos || 0,
      source: toolResults.ports?.metrics?.source || ''
    },
    katana: {
      endpoints_encontrados: toolResults.katana?.metrics?.endpoints_normalizados || reconocimiento.endpoints?.length || 0,
      raw_urls: toolResults.katana?.metrics?.raw_urls || 0,
      superficie_util: toolResults.katana?.metrics?.superficie_util || 0,
      descartados_ruido: toolResults.katana?.metrics?.descartados_ruido || 0,
      descartados_assets: toolResults.katana?.metrics?.descartados_assets || 0,
      duplicados_descartados: toolResults.katana?.metrics?.duplicados_descartados || 0
    },
    nuclei: {
      vulnerabilidades_reales: findings.filter(f => f.tool === 'nuclei' && f.isVulnerability).length
    },
    gau: {
      endpoints_encontrados: toolResults.gau?.metrics?.endpoints_encontrados || toolResults.gau?.parsed?.length || 0,
      raw_urls: toolResults.gau?.metrics?.raw_urls || 0,
      urls_validas: toolResults.gau?.metrics?.urls_validas || 0,
      urls_externas_descartadas: toolResults.gau?.metrics?.urls_externas_descartadas || 0,
      assets_descartados: toolResults.gau?.metrics?.assets_descartados || 0,
      duplicados_descartados: toolResults.gau?.metrics?.duplicados_descartados || 0,
      patrones_deduplicados: toolResults.gau?.metrics?.patrones_deduplicados || 0,
      con_parametros: toolResults.gau?.metrics?.con_parametros || 0,
      seleccionadas_final: toolResults.gau?.metrics?.seleccionadas_final || toolResults.gau?.parsed?.length || 0,
      enviadas_gf: toolResults.gau?.metrics?.enviadas_gf || 0,
      enviadas_ia: toolResults.gau?.metrics?.enviadas_ia || toolResults.gau?.metrics?.enviados_ia || 0
    },
    gf: {
      xss: toolResults.gf?.metrics?.xss ?? gfParsed.xssCandidates?.length ?? 0,
      sqli: toolResults.gf?.metrics?.sqli ?? gfParsed.sqliCandidates?.length ?? 0,
      ssrf: toolResults.gf?.metrics?.ssrf ?? gfParsed.ssrfCandidates?.length ?? 0,
      redirect: toolResults.gf?.metrics?.redirect ?? gfParsed.redirectCandidates?.length ?? 0,
      lfi: toolResults.gf?.metrics?.lfi ?? gfParsed.lfiCandidates?.length ?? 0,
      rce: toolResults.gf?.metrics?.rce ?? gfParsed.rceCandidates?.length ?? 0
    },
    feroxbuster: {
      rutas_descubiertas: toolResults.feroxbuster?.metrics?.endpoints_encontrados || 0,
      rutas_sensibles: toolResults.feroxbuster?.metrics?.rutas_interesantes || 0,
      posibles_vulnerabilidades: toolResults.feroxbuster?.metrics?.posibles_vulnerabilidades || 0
    },
    trufflehog: {
      secretos_confirmados: toolResults.trufflehog?.metrics?.secretos_verificados || 0,
      secretos_posibles: toolResults.trufflehog?.metrics?.secretos_posibles || 0,
      recursos_candidatos: toolResults.trufflehog?.metrics?.recursos_candidatos || 0,
      recursos_descargados: toolResults.trufflehog?.metrics?.recursos_descargados || 0,
      recursos_fallidos: toolResults.trufflehog?.metrics?.recursos_fallidos || 0
    },
    sqlmap: {
      confirmadas: sqlmap.filter(item => item.status === 'confirmed_sqli').length,
      posibles: sqlmap.filter(item => item.status === 'possible_sqli').length,
      no_ejecutada: toolResults.sqlmap?.status === 'skipped'
    }
  };
}

function aplicarFallbackIa(findings = []) {
  return findings.map(finding => ({
    ...finding,
    ai_status: 'failed',
    ai_error: 'No se pudo conectar con Ollama',
    impact: finding.impact || 'Requiere revision tecnica para valorar el impacto real con la evidencia disponible.',
    recommendation: finding.recommendation || 'Revisar el endpoint o recurso indicado y aplicar controles de validacion, autorizacion o exposicion segun corresponda.'
  }));
}

function debeAnalizarHallazgoIA(finding = {}) {
  return finding.type !== 'discarded';
}

app.post('/analizar', async (req, res) => {
  try {
    const enviar = () => {};
    const entrada = req.body.prompt || req.body.target;

    if (!entrada || typeof entrada !== 'string' || !entrada.trim()) {
      return res.status(400).json({
        error: 'No se recibio ningun dominio o URL.'
      });
    }

    const reconocimiento = await ejecutarReconocimiento(entrada.trim());
    const toolResults = reconocimiento.tool_results || {};
    const findings = [];

    if (Object.keys(toolResults).length === 0) {
      return res.status(500).json({
        error: 'El modulo de reconocimiento no devolvio resultados por herramienta.'
      });
    }

    for (const [tool, result] of Object.entries(toolResults)) {
      const findingsDeterministas = clasificarFindings(
        extraerFindingsDeterministas(tool, result, reconocimiento.target)
      );
      const descartadosInfo = findingsDeterministas.filter(f => !f.isVulnerability || f.type === 'reconocimiento').length;
      const findingsParaIA = findingsDeterministas.filter(debeAnalizarHallazgoIA);

      result.findings = findingsDeterministas;
      result.metrics = {
        ...(result.metrics || {}),
        producidos: result.metrics?.producidos ?? (Array.isArray(result.parsed) ? result.parsed.length : 0),
        descartados_info_fingerprinting: descartadosInfo,
        descartados_assets: result.metrics?.descartados_assets ?? findingsDeterministas.filter(f => f.type === 'discarded').length,
        enviados_ia: result.metrics?.enviados_ia ?? findingsParaIA.length,
        no_enviados_ia: result.metrics?.no_enviados_ia ?? (findingsDeterministas.length - findingsParaIA.length)
      };

      if (tool === 'katana') {
        const superficieUtil = findingsDeterministas.filter(f => f.type === 'surface').length;
        result.metrics.superficie_util = superficieUtil;
        result.metrics.descartados_ruido = Math.max(
          0,
          (result.metrics.endpoints_normalizados || result.metrics.producidos || 0) - superficieUtil
        );
        result.metrics.enviados_ia = 0;
      }

      console.log(`[pipeline] ${tool}: producidos=${result.metrics.producidos}, descartados_info=${descartadosInfo}, enviados_ia=${findingsParaIA.length}, no_enviados_ia=${result.metrics.no_enviados_ia}`);

      if (findingsParaIA.length > 0) {
        try {
          const findingsIA = await enriquecerFindingsIA(
            reconocimiento.target,
            tool,
            findingsParaIA
          );

          if (findingsIA.length > 0) {
            const enriquecidos = new Map(clasificarFindings(findingsIA).map(f => [f.id, f]));
            result.findings = result.findings.map(f => enriquecidos.get(f.id) || f);
          }
        } catch (error) {
          result.error = [
            result.error,
            `IA no pudo enriquecer ${tool}: ${error.message}`
          ].filter(Boolean).join(' | ');
          result.findings = result.findings.map(f =>
            findingsParaIA.some(item => item.id === f.id)
              ? aplicarFallbackIa([f])[0]
              : f
          );
        }
      }

      result.findings = normalizeFindingsForReporting(result.findings || []);
      findings.push(...(result.findings || []));
    }

    const findingsDeduplicadosBase = deduplicarFindings(findings);
    const correlacion = correlacionarFindings(findingsDeduplicadosBase, toolResults);
    const findingsDeduplicados = normalizeFindingsForReporting(correlacion.findings);
    const grupos = agruparFindings(findingsDeduplicados);
    const findingsInforme = [
      ...grupos.confirmed,
      ...grupos.possible
    ];
    const summaryUi = construirResumenUI(grupos);

    console.log(`[UI] vulnerabilidades reportables: ${summaryUi.total_vulnerabilidades}`);
    console.log(`[UI] superficie mostrada: ${summaryUi.superficie}`);
    console.log(`[UI] superficie ocultada por ruido: ${Math.max(0, (toolResults.katana?.parsed?.length || 0) - summaryUi.superficie)}`);

    const toolCounters = resumenHerramientas(reconocimiento, toolResults, findingsDeduplicados);
    const risk = calcularRiskScore(findingsDeduplicados);
    const serializedToolResults = Object.fromEntries(
      Object.entries(toolResults).map(([tool, result]) => [
        tool,
        serializarToolResult(result)
      ])
    );
    const pipelineTimeline = construirPipelineTimeline(serializedToolResults, toolCounters, correlacion.correlations, risk);
    const dashboardMetrics = buildDashboardMetrics(findingsDeduplicados, serializedToolResults);

    enviar({ type: 'progress', tool: 'correlacion', status: 'success', message: `${correlacion.correlations.length} relaciones detectadas` });
    enviar({ type: 'progress', tool: 'score final', status: risk.risk_score === null ? 'skipped' : 'success', message: etiquetaRiesgo(risk) });
    enviar({ type: 'progress', tool: 'informe', status: 'ready', message: 'PDF disponible tras finalizar' });

    const respuesta = {
      target: reconocimiento.target,
      status: 'completed',
      findings: findingsDeduplicados,
      findings_reportables: findingsInforme,
      groups: grupos,
      dashboard_metrics: dashboardMetrics,
      gf_candidates: construirCandidatosGf(toolResults),
      tool_results: serializedToolResults,
      tool_counters: toolCounters,
      correlations: correlacion.correlations,
      pipeline_timeline: pipelineTimeline,
      risk_score: risk.risk_score,
      risk_level: risk.risk_level,
      risk_grade: risk.risk_grade,
      sqlmap_notice: toolResults.sqlmap?.status === 'skipped' ? toolResults.sqlmap.error : null,
      ai_notice: findings.some(f => f.ai_status === 'failed')
        ? 'La IA no respondió, se muestra análisis técnico básico.'
        : null,
      summary_ui: summaryUi,
      summary: dashboardMetrics.severityDistribution.reportable
    };

    console.log('\n========== ANALISIS POR HERRAMIENTAS ==========');
    console.log(JSON.stringify(respuesta, null, 2));
    console.log('===============================================\n');

    res.json(respuesta);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/analizar-stream', async (req, res) => {
  const enviar = payload => {
    res.write(`${JSON.stringify(payload)}\n`);
  };
  let scanLogger = null;

  res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('X-Accel-Buffering', 'no');

  try {
    const entrada = req.body.prompt || req.body.target;

    if (!entrada || typeof entrada !== 'string' || !entrada.trim()) {
      enviar({ type: 'error', error: 'No se recibio ningun dominio o URL.' });
      return;
    }

    scanLogger = crearScanLogger(entrada.trim());
    scanLogger.variable('entrada', entrada.trim());

    const reconocimiento = await ejecutarReconocimiento(entrada.trim(), {
      scanLogger,
      onProgress: progress => {
        enviar({
          type: 'progress',
          ...progress,
          at: new Date().toISOString()
        });
      }
    });
    const toolResults = reconocimiento.tool_results || {};
    const findings = [];

    scanLogger.variable('reconocimiento', reconocimiento);
    scanLogger.variable('toolResults', toolResults);

    for (const [tool, result] of Object.entries(toolResults)) {
      scanLogger.toolResult(tool, result);
    }

    if (Object.keys(toolResults).length === 0) {
      scanLogger.section('ERROR', 'El modulo de reconocimiento no devolvio resultados por herramienta.');
      enviar({ type: 'error', error: 'El modulo de reconocimiento no devolvio resultados por herramienta.' });
      return;
    }

    for (const [tool, result] of Object.entries(toolResults)) {
      scanLogger.progress(tool, 'running', `Clasificando hallazgos de ${tool}`);
      enviar({ type: 'progress', tool, status: 'running', message: `Clasificando hallazgos de ${tool}` });
      const findingsDeterministas = clasificarFindings(
        extraerFindingsDeterministas(tool, result, reconocimiento.target)
      );
      const descartadosInfo = findingsDeterministas.filter(f => !f.isVulnerability || f.type === 'reconocimiento').length;
      const findingsParaIA = findingsDeterministas.filter(debeAnalizarHallazgoIA);

      result.findings = findingsDeterministas;
      result.metrics = {
        ...(result.metrics || {}),
        producidos: result.metrics?.producidos ?? (Array.isArray(result.parsed) ? result.parsed.length : 0),
        descartados_info_fingerprinting: descartadosInfo,
        descartados_assets: result.metrics?.descartados_assets ?? findingsDeterministas.filter(f => f.type === 'discarded').length,
        enviados_ia: result.metrics?.enviados_ia ?? findingsParaIA.length,
        no_enviados_ia: result.metrics?.no_enviados_ia ?? (findingsDeterministas.length - findingsParaIA.length)
      };

      scanLogger.variable(`findingsDeterministas.${tool}`, findingsDeterministas);
      scanLogger.variable(`descartadosInfo.${tool}`, descartadosInfo);
      scanLogger.variable(`findingsParaIA.${tool}`, findingsParaIA);
      scanLogger.variable(`result.metrics.${tool}`, result.metrics);

      if (tool === 'katana') {
        const superficieUtil = findingsDeterministas.filter(f => f.type === 'surface').length;
        result.metrics.superficie_util = superficieUtil;
        result.metrics.descartados_ruido = Math.max(
          0,
          (result.metrics.endpoints_normalizados || result.metrics.producidos || 0) - superficieUtil
        );
        result.metrics.enviados_ia = 0;
      }

      if (findingsParaIA.length > 0) {
        try {
          scanLogger.progress(`ia/${tool}`, 'running', `IA explicando hallazgos de ${tool}`, {
            findings: findingsParaIA.length
          });
          scanLogger.variable(`findingsParaIA.${tool}`, findingsParaIA);
          enviar({ type: 'progress', tool: `ia/${tool}`, status: 'running', message: `IA explicando hallazgos de ${tool}` });
          const findingsIA = await enriquecerFindingsIA(
            reconocimiento.target,
            tool,
            findingsParaIA,
            scanLogger
          );
          scanLogger.variable(`findingsIA.${tool}`, findingsIA);

          if (findingsIA.length > 0) {
            const enriquecidos = new Map(clasificarFindings(findingsIA).map(f => [f.id, f]));
            result.findings = result.findings.map(f => enriquecidos.get(f.id) || f);
          }
          scanLogger.variable(`result.findings.${tool}`, result.findings);
          scanLogger.progress(`ia/${tool}`, 'done', `IA finalizada para ${tool}`);
          enviar({ type: 'progress', tool: `ia/${tool}`, status: 'done', message: `IA finalizada para ${tool}` });
        } catch (error) {
          scanLogger.progress(`ia/${tool}`, 'error', error.message);
          scanLogger.section(`ERROR IA: ${tool}`, {
            error: error.message,
            stack: error.stack || null,
            findings_enviados: findingsParaIA
          });
          enviar({ type: 'progress', tool: `ia/${tool}`, status: 'error', message: error.message });
          result.error = [
            result.error,
            `IA no pudo enriquecer ${tool}: ${error.message}`
          ].filter(Boolean).join(' | ');
          result.findings = result.findings.map(f =>
            findingsParaIA.some(item => item.id === f.id)
              ? aplicarFallbackIa([f])[0]
              : f
          );
          scanLogger.variable(`result.findings.${tool}`, result.findings);
        }
      }

      if (findingsParaIA.length === 0) {
        scanLogger.variable(`result.findings.${tool}`, result.findings);
      }

      result.findings = normalizeFindingsForReporting(result.findings || []);
      scanLogger.variable(`result.findings.normalized.${tool}`, result.findings);
      findings.push(...(result.findings || []));
    }

    scanLogger.progress('correlacion', 'running', 'Correlacionando hallazgos');
    enviar({ type: 'progress', tool: 'correlacion', status: 'running', message: 'Correlacionando hallazgos' });
    scanLogger.variable('findings', findings);
    const findingsDeduplicadosBase = deduplicarFindings(findings);
    scanLogger.variable('findingsDeduplicadosBase', findingsDeduplicadosBase);
    const correlacion = correlacionarFindings(findingsDeduplicadosBase, toolResults);
    scanLogger.variable('correlacion', correlacion);
    const findingsDeduplicados = normalizeFindingsForReporting(correlacion.findings);
    const grupos = agruparFindings(findingsDeduplicados);
    scanLogger.variable('findingsDeduplicados', findingsDeduplicados);
    scanLogger.variable('grupos', grupos);
    const findingsInforme = [
      ...grupos.confirmed,
      ...grupos.possible
    ];
    scanLogger.variable('findingsInforme', findingsInforme);
    const summaryUi = construirResumenUI(grupos);
    const toolCounters = resumenHerramientas(reconocimiento, toolResults, findingsDeduplicados);
    const risk = calcularRiskScore(findingsDeduplicados);
    scanLogger.variable('summaryUi', summaryUi);
    scanLogger.variable('toolCounters', toolCounters);
    scanLogger.variable('risk', risk);
    const serializedToolResults = Object.fromEntries(
      Object.entries(toolResults).map(([tool, result]) => [
        tool,
        serializarToolResult(result)
      ])
    );
    scanLogger.variable('serializedToolResults', serializedToolResults);
    const pipelineTimeline = construirPipelineTimeline(serializedToolResults, toolCounters, correlacion.correlations, risk);
    scanLogger.variable('pipelineTimeline', pipelineTimeline);
    const dashboardMetrics = buildDashboardMetrics(findingsDeduplicados, serializedToolResults);
    scanLogger.variable('dashboardMetrics', dashboardMetrics);


    const respuesta = {
      target: reconocimiento.target,
      status: 'completed',
      findings: findingsDeduplicados,
      findings_reportables: findingsInforme,
      groups: grupos,
      dashboard_metrics: dashboardMetrics,
      gf_candidates: construirCandidatosGf(toolResults),
      tool_results: serializedToolResults,
      tool_counters: toolCounters,
      correlations: correlacion.correlations,
      pipeline_timeline: pipelineTimeline,
      risk_score: risk.risk_score,
      risk_level: risk.risk_level,
      risk_grade: risk.risk_grade,
      sqlmap_notice: toolResults.sqlmap?.status === 'skipped' ? toolResults.sqlmap.error : null,
      ai_notice: findings.some(f => f.ai_status === 'failed')
        ? 'La IA no respondio, se muestra analisis tecnico basico.'
        : null,
      summary_ui: summaryUi,
      summary: dashboardMetrics.severityDistribution.reportable
    };

    scanLogger.variable('respuesta', respuesta);
    scanLogger.progress('analisis', 'done', 'Analisis completado');
    scanLogger.done();
    enviar({ type: 'progress', tool: 'analisis', status: 'done', message: 'Analisis completado' });
    enviar({ type: 'result', data: respuesta });
  } catch (error) {
    if (scanLogger) scanLogger.error(error);
    enviar({ type: 'error', error: error.message });
  } finally {
    res.end();
  }
});

app.post('/generar-informe', async (req, res) => {
  try {
    const target = req.body.target || req.body.prompt;

    if (!target || typeof target !== 'string' || !target.trim()) {
      return res.status(400).json({ error: 'Debes enviar un target valido.' });
    }

    if (!Array.isArray(req.body.findings)) {
      return res.status(400).json({ error: 'Debes enviar un array de findings.' });
    }

    const findings = normalizeFindingsForReporting(
      clasificarFindings(normalizarFindings(req.body.findings, 'otra', target.trim()))
    );
    generarPdfAuditoria(res, target.trim(), findings, {
      gfCandidates: req.body.gf_candidates || {},
      toolResults: req.body.tool_results || {},
      toolCounters: req.body.tool_counters || {},
      correlations: req.body.correlations || [],
      pipelineTimeline: req.body.pipeline_timeline || [],
      risk_score: req.body.risk_score,
      risk_level: req.body.risk_level,
      risk_grade: req.body.risk_grade,
      sqlmap_notice: req.body.sqlmap_notice,
      ai_notice: req.body.ai_notice
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const server = app.listen(PORT, () => {
  console.log(`Servidor en http://localhost:${PORT}`);
});

server.timeout = 0;
server.requestTimeout = 0;
server.headersTimeout = 0;
