const express = require('express');
const cors = require('cors');
const path = require('path');
const { generarPdfRespuesta, generarPdfDesdeInforme } = require('./utils/pdf');
const { ejecutarReconocimiento } = require('./modules/reconocimiento');
const { enriquecerFindingsIA } = require('./modules/ia');
const { normalizarFindings, resumenSeveridad } = require('./modules/normalizacion');
const { generarInformeDesdeFindings } = require('./modules/informe');
const { extraerFindingsDeterministas } = require('./modules/extractores');

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
    error: result.error || null
  };
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
      const findingsDeterministas = extraerFindingsDeterministas(tool, result, reconocimiento.target);
      result.findings = findingsDeterministas;

      if (findingsDeterministas.length > 0) {
        try {
          const findingsIA = await enriquecerFindingsIA(
            reconocimiento.target,
            tool,
            findingsDeterministas
          );

          if (findingsIA.length > 0) {
            result.findings = findingsIA;
          }
        } catch (error) {
          result.error = [
            result.error,
            `IA no pudo enriquecer ${tool}: ${error.message}`
          ].filter(Boolean).join(' | ');
        }
      }

      findings.push(...(result.findings || []));
    }

    const respuesta = {
      target: reconocimiento.target,
      status: 'completed',
      findings,
      tool_results: Object.fromEntries(
        Object.entries(toolResults).map(([tool, result]) => [
          tool,
          serializarToolResult(result)
        ])
      ),
      summary: resumenSeveridad(findings)
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
    const informe = await generarInformeDesdeFindings(target.trim(), findings);

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

app.listen(PORT, () => {
  console.log(`Servidor en http://localhost:${PORT}`);
});
