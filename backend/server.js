const express = require('express');
const cors = require('cors');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env'), override: true });
const { generarPdfRespuesta, generarPdfDesdeInforme } = require('./utils/pdf');
const { ejecutarReconocimiento } = require('./modules/reconocimiento');
const { enriquecerFindingsIA } = require('./modules/ia');
const { normalizarFindings, resumenSeveridad } = require('./modules/normalizacion');
const { generarInformeDesdeFindings } = require('./modules/informe');
const { extraerFindingsDeterministas } = require('./modules/extractores');
const { clasificarFindings, debeEnviarIA } = require('./modules/clasificadorFindings');

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
  return {
    confirmadas: findings.filter(f => f.isVulnerability && f.confidence === 'high' && !f.isFalsePositiveLikely),
    posibles: findings.filter(f => f.isVulnerability && f.confidence === 'medium' && !f.isFalsePositiveLikely),
    baja_confianza: findings.filter(f => f.isVulnerability && (f.confidence === 'low' || f.isFalsePositiveLikely)),
    superficie: findings.filter(f => f.type === 'surface'),
    reconocimiento: findings.filter(f => (!f.isVulnerability || f.type === 'reconocimiento') && f.type !== 'surface' && f.type !== 'discarded'),
    descartados: findings.filter(f => f.type === 'discarded')
  };
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
  const confirmadas = grupos.confirmadas?.length || 0;
  const posibles = grupos.posibles?.length || 0;
  const superficie = grupos.superficie?.length || 0;
  const reconocimiento = grupos.reconocimiento?.length || 0;
  const descartados = (grupos.descartados?.length || 0) + (grupos.baja_confianza?.length || 0);

  return {
    confirmadas,
    posibles,
    total_vulnerabilidades: confirmadas + posibles,
    superficie,
    reconocimiento,
    descartados
  };
}

function claveFinding(finding = {}) {
  return [
    finding.tool || '',
    finding.type || '',
    finding.vulnerability_type || '',
    finding.title || '',
    finding.affected_url || finding.affected_asset || ''
  ].join('|').toLowerCase();
}

function deduplicarFindings(findings = []) {
  const mapa = new Map();

  findings.forEach(finding => {
    const key = claveFinding(finding);
    if (!mapa.has(key)) mapa.set(key, finding);
  });

  return Array.from(mapa.values());
}

function resumenHerramientas(reconocimiento, toolResults, findings) {
  const sqlmap = toolResults.sqlmap?.parsed || [];
  const gfParsed = toolResults.gf?.parsed || {};
  return {
    subfinder: {
      subdominios_encontrados: reconocimiento.subdominios?.length || 0
    },
    httpx: {
      activos_vivos: reconocimiento.activos?.length || 0
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
      con_parametros: toolResults.gau?.metrics?.con_parametros || 0
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

app.post('/analizar', async (req, res) => {
  try {
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
      const findingsParaIA = findingsDeterministas.filter(debeEnviarIA);

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

      findings.push(...(result.findings || []));
    }

    const findingsDeduplicados = deduplicarFindings(findings);
    const grupos = agruparFindings(findingsDeduplicados);
    const findingsInforme = [
      ...grupos.confirmadas,
      ...grupos.posibles
    ];
    const summaryUi = construirResumenUI(grupos);

    console.log(`[UI] vulnerabilidades reportables: ${summaryUi.total_vulnerabilidades}`);
    console.log(`[UI] superficie mostrada: ${summaryUi.superficie}`);
    console.log(`[UI] superficie ocultada por ruido: ${Math.max(0, (toolResults.katana?.parsed?.length || 0) - summaryUi.superficie)}`);

    const respuesta = {
      target: reconocimiento.target,
      status: 'completed',
      findings: findingsDeduplicados,
      findings_reportables: findingsInforme,
      groups: grupos,
      gf_candidates: construirCandidatosGf(toolResults),
      tool_results: Object.fromEntries(
        Object.entries(toolResults).map(([tool, result]) => [
          tool,
          serializarToolResult(result)
        ])
      ),
      tool_counters: resumenHerramientas(reconocimiento, toolResults, findingsDeduplicados),
      sqlmap_notice: toolResults.sqlmap?.status === 'skipped' ? toolResults.sqlmap.error : null,
      ai_notice: findings.some(f => f.ai_status === 'failed')
        ? 'La IA no respondió, se muestra análisis técnico básico.'
        : null,
      summary_ui: summaryUi,
      summary: resumenSeveridad(findingsInforme)
    };

    console.log('\n========== ANALISIS POR HERRAMIENTAS ==========');
    console.log(JSON.stringify(respuesta, null, 2));
    console.log('===============================================\n');

    res.json(respuesta);
  } catch (error) {
    res.status(500).json({ error: error.message });
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

    const findings = normalizarFindings(req.body.findings, 'otra', target.trim());
    const informe = await generarInformeDesdeFindings(target.trim(), findings, {
      gfCandidates: req.body.gf_candidates || {},
      toolResults: req.body.tool_results || {}
    });

    generarPdfDesdeInforme(res, target.trim(), informe);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Endpoint antiguo mantenido por compatibilidad.
app.post('/descargar', async (req, res) => {
  try {
    const { prompt, respuesta } = req.body;

    if (!prompt || typeof prompt !== 'string' || !prompt.trim()) {
      return res.status(400).json({ error: 'Debes enviar un prompt valido.' });
    }

    if (!respuesta || typeof respuesta !== 'string' || !respuesta.trim()) {
      return res.status(400).json({ error: 'Debes enviar una respuesta valida.' });
    }

    generarPdfRespuesta(res, prompt, respuesta);
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
