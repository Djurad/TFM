const path = require('path');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
require('dotenv').config({ path: path.join(__dirname, '..', '.env'), override: true });

const { parsearJsonIAFlexible } = require('../procesamiento/normalizacion');
const {
  getFinalSeverity,
  getFinalStatus,
  getPotentialSeverity,
  findingVectorType,
  normalizeSeverity,
  normalizeStatus,
  resolveFindingToolDisplay,
  validateProbabilityDecision
} = require('../priorizacion/findingGroups');

const MODEL = process.env.OLLAMA_MODEL || 'llama3';
const OLLAMA_REINTENTOS = 3;
const INTENTOS_ENRIQUECIMIENTO_IA = Number(process.env.IA_INTENTOS_ENRIQUECIMIENTO || 2);
// El modo completo no admite timeouts: Ollama puede tardar, pero cada hallazgo
// reportable debe recibir una respuesta o quedar explicitamente pendiente.
const AI_DISABLE_TIMEOUTS = true;
const AI_WAIT_LOG_INTERVAL_MS = Math.max(1000, Number(process.env.AI_WAIT_LOG_INTERVAL_MS || 60000));

function resolveAiTimeoutMs(...values) {
  if (AI_DISABLE_TIMEOUTS) return 0;
  for (const value of values) {
    if (value === undefined || value === null || value === '') continue;
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed > 0 ? parsed : 0;
  }
  return 0;
}

const OLLAMA_TIMEOUT_MS = resolveAiTimeoutMs(
  process.env.OLLAMA_REQUEST_TIMEOUT_MS,
  process.env.AI_TIMEOUT_MS,
  process.env.OLLAMA_TIMEOUT_MS,
  process.env.OLLAMA_TIMEOUT
);
const AI_SINGLE_FINDING_TIMEOUT_MS = resolveAiTimeoutMs(
  process.env.AI_SINGLE_FINDING_TIMEOUT_MS,
  OLLAMA_TIMEOUT_MS
);

function getAiRuntimeConfig() {
  return {
    disableTimeouts: AI_DISABLE_TIMEOUTS,
    requireAllFindings: true,
    templatesDisabled: true,
    mode: 'complete',
    timeoutMs: OLLAMA_TIMEOUT_MS,
    singleFindingTimeoutMs: AI_SINGLE_FINDING_TIMEOUT_MS,
    waitLogIntervalMs: AI_WAIT_LOG_INTERVAL_MS,
    model: MODEL,
    url: OLLAMA_URL
  };
}

function construirOllamaUrl() {
  const host = process.env.OLLAMA_HOST || 'localhost';
  const base = host.startsWith('http://') || host.startsWith('https://')
    ? host
    : `http://${host}`;

  return base.match(/:\d+$/)
    ? `${base}/api/generate`
    : `${base}:11434/api/generate`;
}

const OLLAMA_URL = construirOllamaUrl();
let ollamaHealthConfirmed = false;

function construirOllamaHealthUrl() {
  const parsed = new URL(OLLAMA_URL);
  parsed.pathname = '/api/tags';
  parsed.search = '';
  return parsed.toString();
}

function checkOllamaHealth(scanLogger = null) {
  if (ollamaHealthConfirmed) return Promise.resolve({ ok: true, cached: true });
  const url = construirOllamaHealthUrl();
  return new Promise(resolve => {
    const parsed = new URL(url);
    const client = parsed.protocol === 'https:' ? https : http;
    const req = client.request({
      hostname: parsed.hostname,
      port: parsed.port,
      path: `${parsed.pathname}${parsed.search}`,
      method: 'GET'
    }, res => {
      res.resume();
      res.on('end', () => {
        const ok = res.statusCode >= 200 && res.statusCode < 300;
        ollamaHealthConfirmed = ok;
        logAISeverity(scanLogger, '[AI-OLLAMA-HEALTH]', { url, ok, httpStatus: res.statusCode });
        resolve({ ok, httpStatus: res.statusCode, url });
      });
    });
    req.setTimeout(0);
    req.on('error', error => {
      logAISeverity(scanLogger, '[AI-OLLAMA-HEALTH]', { url, ok: false, error: error.message });
      resolve({ ok: false, error: error.message, url });
    });
    req.end();
  });
}

function esperar(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function detalleErrorFetch(error) {
  return [
    error.message,
    error.code,
    error.cause?.code,
    error.cause?.message
  ].filter(Boolean).join(' - ');
}

function crearErrorIA(prefijo, error) {
  const wrapped = new Error(`${prefijo}: ${detalleErrorFetch(error)}`);
  wrapped.code = error?.code || error?.cause?.code || 'OLLAMA_REQUEST_FAILED';
  wrapped.cause = error;
  return wrapped;
}

async function llamarOllama(body, intentos = OLLAMA_REINTENTOS, timeoutMs = OLLAMA_TIMEOUT_MS, context = {}) {
  let ultimoError = null;

  for (let intento = 1; intento <= intentos; intento++) {
    try {
      return await postJsonSinTimeout(OLLAMA_URL, body, timeoutMs, context);
    } catch (error) {
      ultimoError = error;
      console.error(`Intento ${intento}/${intentos} fallido contra Ollama (${OLLAMA_URL}):`, detalleErrorFetch(error));

      if (intento < intentos) {
        await esperar(1500 * intento);
      }
    }
  }

  throw crearErrorIA(`No se pudo conectar con Ollama tras ${intentos} intentos`, ultimoError);
}

function postJsonSinTimeout(url, body, timeoutMs = OLLAMA_TIMEOUT_MS, context = {}) {
  return new Promise((resolve, reject) => {
    const startedAt = Date.now();
    const parsed = new URL(url);
    const payload = JSON.stringify(body);
    const client = parsed.protocol === 'https:' ? https : http;
    const requestOptions = {
      hostname: parsed.hostname,
      port: parsed.port,
      path: `${parsed.pathname}${parsed.search}`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    };

    if (timeoutMs > 0) {
      requestOptions.timeout = timeoutMs;
    }

    logAISeverity(context.scanLogger, '[AI-OLLAMA-REQUEST]', {
      findingId: context.findingId || 'general',
      url,
      stream: body.stream === true,
      timeoutMs,
      timeoutDisabled: timeoutMs === 0,
      model: body.model || MODEL
    });

    const waitingLog = timeoutMs === 0
      ? setInterval(() => {
          logAISeverity(context.scanLogger, '[AI-OLLAMA-WAITING]', {
            findingId: context.findingId || 'general',
            elapsedMs: Date.now() - startedAt,
            message: 'IA sigue procesando; no se cancela por tiempo'
          });
        }, AI_WAIT_LOG_INTERVAL_MS)
      : null;
    if (waitingLog && typeof waitingLog.unref === 'function') waitingLog.unref();
    const stopWaitingLog = () => {
      if (waitingLog) clearInterval(waitingLog);
    };

    const req = client.request(
      requestOptions,
      res => {
        const chunks = [];

        res.on('data', chunk => chunks.push(chunk));
        res.on('aborted', () => {
          stopWaitingLog();
          const error = new Error('Ollama cerro la respuesta antes de completarla.');
          error.code = 'OLLAMA_RESPONSE_ABORTED';
          reject(error);
        });
        res.on('error', error => {
          stopWaitingLog();
          reject(error);
        });
        res.on('end', () => {
          stopWaitingLog();
          const texto = Buffer.concat(chunks).toString('utf8');
          logAISeverity(context.scanLogger, '[AI-OLLAMA-RESPONSE]', {
            findingId: context.findingId || 'general',
            durationMs: Date.now() - startedAt,
            httpStatus: res.statusCode,
            responseLength: texto.length
          });

          if (res.statusCode < 200 || res.statusCode >= 300) {
            const error = new Error(`Error de Ollama: ${res.statusCode}${texto ? ` - ${texto.slice(0, 300)}` : ''}`);
            error.code = `OLLAMA_HTTP_${res.statusCode}`;
            reject(error);
            return;
          }

          try {
            resolve(JSON.parse(texto));
          } catch (error) {
            const parseError = new Error(`Ollama no devolvio JSON HTTP valido: ${error.message}`);
            parseError.code = 'OLLAMA_INVALID_HTTP_JSON';
            reject(parseError);
          }
        });
      }
    );

    if (timeoutMs > 0) {
      req.setTimeout(timeoutMs, () => req.destroy(new Error('timeout conectando con Ollama')));
    } else {
      req.setTimeout(0);
    }
    req.on('error', error => {
      stopWaitingLog();
      reject(error);
    });
    req.write(payload);
    req.end();
  });
}

async function generarRespuestaIA(prompt) {
  try {
    const data = await llamarOllama({
      model: MODEL,
      prompt,
      stream: false,
      keep_alive: '15m',
      system: `
Eres un generador de informes tecnicos de ciberseguridad.
Redactas informes claros, profesionales y suficientemente detallados.
Respondes siempre en espanol.
Tu salida debe ser un informe profesional, no una explicacion del JSON recibido.
No uses tono conversacional.
No menciones que eres una IA.
`,
      options: {
        temperature: 0.1,
        num_predict: 1400,
        num_ctx: 5000,
        num_thread: 4
      }
    });

    return data.response || '';
  } catch (error) {
    throw crearErrorIA('Fallo al conectar con la IA', error);
  }
}

async function generarJsonIA(prompt, timeoutMs = OLLAMA_TIMEOUT_MS, intentos = OLLAMA_REINTENTOS, context = {}) {
  try {
    const data = await llamarOllama({
      model: MODEL,
      prompt,
      stream: false,
      keep_alive: '15m',
      format: 'json',
      system: `
Eres un analista senior de ciberseguridad.
Respondes siempre con JSON valido, sin Markdown y sin texto fuera del JSON.
Redactas todos los valores visibles exclusivamente en espanol; las claves JSON pueden permanecer en ingles.
No inventes hallazgos, CVE, CVSS ni CWE sin evidencia.
`,
      options: {
        temperature: 0,
        num_predict: 1600,
        num_ctx: 4096,
        num_thread: 2
      }
    }, intentos, timeoutMs, context);

    return data.response || '';
  } catch (error) {
    throw crearErrorIA('Fallo al conectar con la IA', error);
  }
}

function limitarTexto(texto = '', max = 2500) {
  const limpio = String(texto || '').trim();

  if (limpio.length <= max) return limpio;

  return `${limpio.slice(0, max)}\n\n[Salida truncada: ${limpio.length - max} caracteres omitidos]`;
}

function trocearArray(items, tamano) {
  const chunks = [];

  for (let i = 0; i < items.length; i += tamano) {
    chunks.push(items.slice(i, i + tamano));
  }

  return chunks;
}

function limpiarCampoIA(valor) {
  return typeof valor === 'string' ? valor.trim() : '';
}

function normalizarCriticidadIA(valor) {
  const lower = limpiarCampoIA(valor).toLowerCase();
  const mapa = {
    critica: 'critical',
    critico: 'critical',
    critical: 'critical',
    alta: 'high',
    alto: 'high',
    high: 'high',
    media: 'medium',
    medio: 'medium',
    medium: 'medium',
    baja: 'low',
    bajo: 'low',
    low: 'low',
    informativa: 'info',
    informativo: 'info',
    informational: 'info',
    info: 'info'
  };

  return mapa[lower] || '';
}

function direccionCambioSeveridad(original, nueva) {
  const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const before = rank[original] ?? 0;
  const after = rank[nueva] ?? before;
  if (after > before) return 'upgraded';
  if (after < before) return 'downgraded';
  return 'unchanged';
}

function tieneEvidenciaConcreta(finding = {}) {
  return Boolean(
    finding.payload ||
    finding.dbms ||
    finding.parametro ||
    finding.parameter ||
    finding.param ||
    /payload|poc|triggered|matched-at|dbms|extracted|vulnerable/i.test(String(finding.evidence || ''))
  );
}

function validarDecisionSeveridadIA(finding = {}, aiResult = {}) {
  const baseSeverity = normalizarCriticidadIA(finding.potentialSeverity || finding.baseSeverity || finding.finalSeverity || finding.severity) || 'info';
  const suggestedSeverity = normalizarCriticidadIA(aiResult.suggestedSeverity || aiResult.severity || aiResult.criticidad) || baseSeverity;
  const status = getFinalStatus(finding);
  const tool = String(finding.tool || '').toLowerCase();
  const type = String(finding.type || '').toLowerCase();
  const text = [
    finding.title,
    finding.description,
    finding.evidence,
    finding.affected_url,
    finding.affected_asset,
    ...(Array.isArray(finding.correlation_notes) ? finding.correlation_notes : []),
    ...(Array.isArray(finding.related_findings) ? finding.related_findings : []),
    aiResult.severityReason
  ].filter(Boolean).join(' ').toLowerCase();
  const reason = limpiarCampoIA(aiResult.severityReason || aiResult.classificationReason || aiResult.aiReasoningSummary);
  const hasReason = reason.length >= 24;
  let finalSeverity = suggestedSeverity;
  let validationNote = '';

  // La IA puede ajustar criticidad, pero estas reglas evitan incoherencias evidentes:
  // GF sigue siendo candidato, hardening sigue siendo configuracion defensiva y
  // superficie expuesta no pasa a critica/alta sin evidencia de impacto sensible.
  if (!hasReason && suggestedSeverity !== baseSeverity) {
    finalSeverity = baseSeverity;
    validationNote = 'Cambio de criticidad descartado: la IA no justifico el ajuste con suficiente detalle.';
  }

  if (status === 'candidate') {
    const deterministicPotential = getPotentialSeverity(finding);
    if (finalSeverity !== deterministicPotential) {
      finalSeverity = deterministicPotential;
      validationNote = validationNote || `La severidad ${deterministicPotential} expresa el impacto potencial del vector; el estado candidate y la probabilidad baja expresan que no esta confirmado.`;
    }
  }

  if (status === 'hardening' && finalSeverity === 'critical') {
    finalSeverity = 'medium';
    validationNote = validationNote || 'Hardening aislado no se marca como critico sin cadena explotable demostrada.';
  }

  if (status === 'surface' && ['critical', 'high', 'medium'].includes(finalSeverity) && !/admin|panel|secret|token|credential|sensible|database|db|internal|swagger|openapi|8080|8443/.test(text)) {
    finalSeverity = 'low';
    validationNote = validationNote || 'Superficie expuesta limitada a low: no hay evidencia de servicio sensible o explotacion.';
  }

  if (tool === 'sqlmap' && status === 'possible' && /possible_sqli|sql/i.test(`${finding.source_status || ''} ${finding.title || ''}`) && !tieneEvidenciaConcreta(finding)) {
    finalSeverity = 'high';
    validationNote = validationNote || 'SQL Injection mantiene impacto potencial high; la falta de payload, DBMS y extraccion se refleja en su probabilidad y estado possible.';
  }

  if ((tool === 'headers' || type.includes('header')) && finalSeverity === 'critical' && !/xss|sesion|session|cookie|cadena|correlacion/.test(text)) {
    finalSeverity = 'medium';
    validationNote = validationNote || 'Cabecera ausente aislada no justifica severidad critica.';
  }

  if (status === 'hardening' && /content-security-policy|\bcsp\b/.test(text) && /xss/.test(text) && ['low', 'info'].includes(finalSeverity)) {
    finalSeverity = 'medium';
    validationNote = 'CSP ausente correlacionada con XSS confirmado: se mantiene como hardening medium.';
  }

  return {
    baseSeverity,
    aiSuggestedSeverity: suggestedSeverity,
    finalSeverity,
    severityChangedByAI: finalSeverity !== baseSeverity,
    severityChangeDirection: direccionCambioSeveridad(baseSeverity, finalSeverity),
    severityChangeReason: validationNote || reason,
    validationNote
  };
}

function validateAISeverityDecision(finding = {}, aiResult = {}) {
  return validarDecisionSeveridadIA(finding, aiResult);
}

function hasDemonstratedCriticalImpact(finding = {}) {
  const evidence = [finding.evidence, finding.raw_reference, finding.impact]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
  return finding.sessionCompromise === true ||
    finding.sensitiveDataAccess === true ||
    finding.unauthorizedAccess === true ||
    finding.dataExtraction === true ||
    finding.authenticationBypass === true ||
    finding.writeAccess === true ||
    /robo de sesion demostrado|extraccion de datos confirmada|acceso no autorizado demostrado|ejecucion privilegiada demostrada/.test(evidence);
}

function validateAIEnrichmentResult(finding = {}, aiResult = {}) {
  const severityValidation = validateAISeverityDecision(finding, aiResult);
  const statusBefore = getFinalStatus(finding);
  const aiSuggestedStatus = normalizeStatus(
    aiResult.aiSuggestedStatus || aiResult.suggestedStatus || aiResult.status,
    ''
  );
  const reasons = [];
  let overriddenByRule = false;
  let finalSeverity = severityValidation.finalSeverity;
  let finalConfidence = String(aiResult.confidence || finding.confidence || 'low').toLowerCase();
  if (!['high', 'medium', 'low'].includes(finalConfidence)) finalConfidence = finding.confidence || 'low';

  // El estado tecnico pertenece a la herramienta. La IA puede proponerlo para
  // trazabilidad, pero nunca promociona ni degrada el hallazgo por si sola.
  if (aiSuggestedStatus && aiSuggestedStatus !== statusBefore) {
    overriddenByRule = true;
    reasons.push(`Estado IA ${aiSuggestedStatus} ignorado; se conserva ${statusBefore} validado tecnicamente.`);
  }

  if (finding.lockedSeverity === true) {
    const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
    const minimum = normalizeSeverity(finding.technicalMinimumSeverity || finding.baseSeverity || finding.finalSeverity);
    if ((rank[finalSeverity] ?? 0) < (rank[minimum] ?? 0)) {
      finalSeverity = minimum;
      overriddenByRule = true;
      reasons.push(`Se conserva la severidad tecnica minima ${minimum}.`);
    }

    if (
      String(finding.tool || '').toLowerCase() === 'dalfox' &&
      finalSeverity === 'critical' &&
      !hasDemonstratedCriticalImpact(finding)
    ) {
      finalSeverity = 'high';
      overriddenByRule = true;
      reasons.push('XSS confirmado sin impacto critico demostrado se mantiene en high.');
    }
  }

  const vector = minimalFindingFamily(finding);
  const potentialCriticalCandidate = statusBefore === 'candidate' && vector === 'rce';
  const confirmedRce = statusBefore === 'confirmed' && vector === 'rce';
  if (finalSeverity === 'critical' && !potentialCriticalCandidate && !confirmedRce && !hasDemonstratedCriticalImpact(finding)) {
    finalSeverity = ['confirmed', 'possible'].includes(statusBefore) ? 'high' : 'medium';
    overriddenByRule = true;
    reasons.push('Severidad critical rechazada: no existe impacto critico demostrado en la evidencia tecnica.');
  }

  if (statusBefore === 'candidate') finalConfidence = 'low';
  if (finding.lockedStatus === true && statusBefore === 'confirmed') finalConfidence = 'high';

  return {
    ...severityValidation,
    potentialSeverity: finalSeverity,
    finalSeverity,
    severityChangedByAI: finalSeverity !== severityValidation.baseSeverity,
    severityChangeDirection: direccionCambioSeveridad(severityValidation.baseSeverity, finalSeverity),
    aiSuggestedStatus: aiSuggestedStatus || statusBefore,
    finalStatus: statusBefore,
    technicalStatus: finding.technicalStatus || finding.technical_status || statusBefore,
    confidence: finalConfidence,
    overriddenByRule,
    overrideReason: reasons.join(' '),
    reportable: ['confirmed', 'possible', 'candidate', 'hardening', 'surface'].includes(statusBefore),
    isVulnerability: ['confirmed', 'possible'].includes(statusBefore)
  };
}

function validateSingleAIResult(finding = {}, aiResult = {}) {
  return validateAIEnrichmentResult(finding, aiResult);
}

function clampNumber(value, min, max, fallback = min) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function normalizeAiProbabilityPercent(value) {
  if (value === null || value === undefined || value === '') return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return null;
  return Math.round(clampNumber(parsed <= 1 ? parsed * 100 : parsed, 0, 100));
}

function validateCvssLikeAIResult(finding = {}, aiResult = {}) {
  const status = getFinalStatus(finding);
  const vectorType = minimalFindingFamily(finding);
  const text = [finding.tool, finding.type, finding.family, finding.vulnerability_type, finding.title, finding.evidence]
    .filter(Boolean).join(' ').toLowerCase();
  const severityValidation = validateAIEnrichmentResult(finding, aiResult);
  let potentialSeverity = severityValidation.potentialSeverity;
  let scoreMin = { critical: 9, high: 7, medium: 4, low: 0.1, info: 0 }[potentialSeverity] ?? 0;
  let scoreMax = { critical: 10, high: 8.9, medium: 6.9, low: 3.9, info: 0 }[potentialSeverity] ?? 10;
  let probability = normalizeAiProbabilityPercent(aiResult.probabilityAISuggested);
  let probabilityMin = 0;
  let probabilityMax = 100;

  if (status === 'candidate') {
    if (vectorType === 'rce') {
      potentialSeverity = 'critical'; scoreMin = 9; scoreMax = 10; probabilityMin = 5; probabilityMax = 20;
    } else if (vectorType === 'sqli') {
      potentialSeverity = 'high'; scoreMin = 7; scoreMax = 8.9; probabilityMin = 10; probabilityMax = 30;
    } else if (vectorType === 'ssrf') {
      potentialSeverity = 'high'; scoreMin = 7; scoreMax = 8.9; probabilityMin = 5; probabilityMax = 25;
    } else if (vectorType === 'lfi' || /\blfi\b|local file inclusion/.test(text)) {
      potentialSeverity = 'high'; scoreMin = 7; scoreMax = 8.9; probabilityMin = 8; probabilityMax = 25;
    } else if (vectorType === 'redirect' || /open.?redirect|redireccion abierta/.test(text)) {
      potentialSeverity = 'medium'; scoreMin = 4; scoreMax = 6.9; probabilityMin = 10; probabilityMax = 35;
    } else if (vectorType === 'xss') {
      if (!['medium', 'high'].includes(potentialSeverity)) potentialSeverity = 'medium';
      scoreMin = potentialSeverity === 'high' ? 7 : 5.5;
      scoreMax = potentialSeverity === 'high' ? 8.5 : 6.9;
      probabilityMin = 10; probabilityMax = 30;
    } else {
      probabilityMin = 5; probabilityMax = 35;
    }
  } else if (status === 'confirmed' && vectorType === 'rce') {
    potentialSeverity = 'critical'; scoreMin = 9; scoreMax = 10; probabilityMin = 90; probabilityMax = 99;
  } else if (status === 'confirmed' && vectorType === 'xss') {
    potentialSeverity = hasDemonstratedCriticalImpact(finding) ? 'critical' : 'high';
    scoreMin = potentialSeverity === 'critical' ? 9 : 7;
    scoreMax = potentialSeverity === 'critical' ? 10 : 8.5;
    probabilityMin = 90; probabilityMax = 98;
  } else if (status === 'possible' && vectorType === 'sqli') {
    potentialSeverity = 'high'; scoreMin = 7; scoreMax = 8.9; probabilityMin = 25; probabilityMax = 45;
  } else if (status === 'possible' && vectorType === 'xss') {
    if (!['medium', 'high'].includes(potentialSeverity)) potentialSeverity = 'medium';
    scoreMin = 5.5; scoreMax = 7.5; probabilityMin = 35; probabilityMax = 60;
  } else if (status === 'confirmed') {
    probabilityMin = 70; probabilityMax = 99;
  } else if (status === 'possible') {
    probabilityMin = 20; probabilityMax = 70;
  }

  if (['hardening', 'surface', 'informational'].includes(status)) probability = null;
  else probability = clampNumber(probability, probabilityMin, probabilityMax, probabilityMin);

  const rawScore = aiResult.cvssLikeScore;
  const cvssLikeScore = Number(clampNumber(rawScore, scoreMin, scoreMax, (scoreMin + scoreMax) / 2).toFixed(1));
  const allowed = {
    attackVector: ['network', 'adjacent', 'local', 'physical', 'not_applicable'],
    attackComplexity: ['low', 'high', 'not_applicable'],
    privilegesRequired: ['none', 'low', 'high', 'not_applicable'],
    userInteraction: ['none', 'required', 'not_applicable'],
    scope: ['unchanged', 'changed', 'not_applicable'],
    confidentialityImpact: ['high', 'low', 'none', 'not_applicable'],
    integrityImpact: ['high', 'low', 'none', 'not_applicable'],
    availabilityImpact: ['high', 'low', 'none', 'not_applicable'],
    exploitMaturity: ['confirmed', 'functional', 'poc', 'unproven', 'not_applicable'],
    evidenceStrength: ['confirmed', 'strong', 'medium', 'weak', 'observed', 'informational']
  };
  const inputVector = aiResult.cvssVectorApprox || {};
  const cvssVectorApprox = Object.fromEntries(Object.entries(allowed).map(([key, values]) => {
    const raw = String(inputVector[key] || '').toLowerCase();
    let fallback = 'not_applicable';
    if (key === 'attackVector' && !['hardening', 'surface', 'informational'].includes(status)) fallback = 'network';
    if (key === 'evidenceStrength') fallback = status === 'confirmed' ? 'confirmed' : status === 'possible' ? 'medium' : status === 'candidate' ? 'weak' : 'observed';
    if (key === 'exploitMaturity') fallback = status === 'confirmed' ? 'confirmed' : status === 'candidate' ? 'unproven' : 'not_applicable';
    return [key, values.includes(raw) ? raw : fallback];
  }));

  return {
    ok: true,
    potentialSeverity,
    cvssLikeSeverity: potentialSeverity,
    cvssLikeScore,
    probabilityAISuggested: probability,
    practicalRisk: normalizarCriticidadIA(aiResult.practicalRisk) || 'info',
    cvssVectorApprox,
    corrected: potentialSeverity !== normalizarCriticidadIA(aiResult.potentialSeverity || aiResult.cvssLikeSeverity || aiResult.suggestedSeverity) ||
      Number(rawScore) !== cvssLikeScore || normalizeAiProbabilityPercent(aiResult.probabilityAISuggested) !== probability
  };
}

function logAISeverity(scanLogger, label, payload = {}) {
  const inline = Object.entries(payload)
    .map(([key, value]) => `${key}=${value}`)
    .join(' ');
  console.log(`${label}${inline ? ` ${inline}` : ''}`);
  if (scanLogger?.variable) {
    scanLogger.variable(label.replace(/[\[\]-]+/g, '').replace(/\s+/g, '_').toLowerCase(), payload);
  }
}

function buildCompactFindingForAI(finding = {}) {
  const toolDisplay = resolveFindingToolDisplay(finding);
  const endpoint = finding.endpoint || finding.affected_url || finding.affected_asset;
  let inferredParameter = finding.parameter || finding.parametro || finding.param || null;
  if (!inferredParameter && endpoint) {
    try {
      inferredParameter = new URL(endpoint).searchParams.keys().next().value || null;
    } catch {
      inferredParameter = null;
    }
  }
  return {
    id: finding.id,
    tool: finding.tool,
    displayTool: toolDisplay.displayTool,
    sourceTools: toolDisplay.sourceTools,
    type: finding.type,
    family: finding.family || finding.vulnerability_type || finding.familia || null,
    currentStatus: getFinalStatus(finding),
    currentSeverity: finding.potentialSeverity || getPotentialSeverity(finding),
    endpoint,
    parameter: inferredParameter,
    payload: limitarTexto(finding.payload, 350),
    evidence: String(finding.evidence || finding.rawEvidenceSummary || finding.raw_reference || '').trim().slice(0, 800),
    evidenceStrength: finding.cvssVectorApprox?.evidenceStrength || finding.evidenceStrength || null,
    isConfirmed: getFinalStatus(finding) === 'confirmed',
    isGF: getFinalStatus(finding) === 'candidate' || String(finding.tool || '').toLowerCase() === 'gf',
    isHardening: getFinalStatus(finding) === 'hardening',
    isSurface: getFinalStatus(finding) === 'surface',
    probabilityBase: finding.probabilityBase ?? null,
    correlations: Array.isArray(finding.correlation_notes) ? finding.correlation_notes.slice(0, 3).map(item => limitarTexto(item, 240)) : []
  };
}

const compactarFindingParaIA = buildCompactFindingForAI;

function minimalPromptGuidance(finding = {}) {
  const status = normalizeStatus(finding.currentStatus || finding.finalStatus || finding.status, 'informational');
  const tool = String(finding.tool || finding.sourceTool || finding.displayTool || '').toLowerCase();
  const toolContext = [tool, finding.sourceTool, finding.displayTool, ...(finding.sourceTools || [])].filter(Boolean).join(' ').toLowerCase();
  const family = String(finding.family || finding.vulnerability_type || finding.type || '').toLowerCase();
  const text = [toolContext, family, finding.type, finding.evidence, finding.title, finding.endpoint].filter(Boolean).join(' ').toLowerCase();

  if (['surface', 'informational'].includes(status) && /feroxbuster|\bferox\b/.test(toolContext)) {
    return `Ayuda especifica Feroxbuster: este hallazgo es superficie descubierta por feroxbuster, no una vulnerabilidad confirmada.
- Impacto: menciona la ruta o recurso, que amplia la superficie publica o facilita reconocimiento y que no demuestra explotacion.
- Recomendacion: indica si la ruta debe seguir expuesta; si no es necesaria, restringirla con autenticacion o filtrado de red, eliminarla, documentar rutas publicas esperadas y descartar rutas sin contenido util.
- Menciona expresamente Feroxbuster y el endpoint recibido.`;
  }
  if (tool === 'gf' && /\bssrf\b/.test(text)) {
    return `Ayuda especifica GF SSRF: es un candidato detectado por patron GF, no SSRF confirmado.
- Impacto: menciona endpoint, parametro si existe, patron GF SSRF, ausencia de peticion server-side, callback externo o acceso a red interna, e impacto high solo si se confirma.
- Recomendacion: validar peticiones salientes con un dominio controlado; aplicar allowlist de destinos; bloquear localhost, IP privadas y metadata cloud; rechazar esquemas no permitidos; limitar redirecciones y usar payloads seguros.`;
  }
  if (tool === 'gf' && /\blfi\b|local file inclusion|path traversal/.test(text)) {
    return `Ayuda especifica GF LFI: es un candidato detectado por patron GF y no existe lectura de archivos confirmada.
- Impacto: menciona endpoint, parametro si existe, patron GF LFI, ausencia de lectura confirmada y posible exposicion de archivos sensibles solo si se confirma.
- Recomendacion: comprobar si el parametro resuelve archivos; usar identificadores logicos y allowlist; normalizar rutas; bloquear rutas absolutas, doble codificacion y secuencias ../; anadir pruebas controladas.`;
  }
  if (['surface', 'informational'].includes(status) && /swagger|openapi|api-docs/.test(text)) {
    return `Ayuda especifica Swagger/OpenAPI: es superficie, no una vulnerabilidad confirmada.
- Impacto: explica en espanol que la ruta publica puede revelar estructura de API, endpoints, parametros o metadatos utiles para reconocimiento.
- Recomendacion: restringir con autenticacion o filtrado de red, o deshabilitar en produccion si no es necesaria; comprobar endpoints internos, hosts privados, tokens, ejemplos sensibles e informacion de depuracion.
- Atribuye el descubrimiento unicamente a ${finding.displayTool || tool || 'la herramienta indicada'}.`;
  }

  if (status === 'confirmed' && (tool === 'dalfox' || /\bxss\b/.test(text))) {
    return 'Ayuda: explica que existe un payload XSS reproducible y no lo eleves a critico sin evidencia de robo de sesion o datos sensibles.';
  }
  if (status === 'possible' && (tool === 'sqlmap' || /sql.?injection|\bsqli\b/.test(text))) {
    return 'Ayuda: explica que hay indicios de SQLi, pero no confirmacion de payload, DBMS ni extraccion de datos.';
  }
  if (tool === 'gf' && /\brce\b|command|ejecucion de comandos/.test(text)) {
    return 'Ayuda: el impacto potencial seria critico, pero GF solo detecta un patron y no hay ejecucion confirmada.';
  }
  if (tool === 'gf' && /sql.?injection|\bsqli\b/.test(text)) {
    return 'Ayuda: el impacto potencial seria alto, pero sigue siendo candidato hasta validarlo manualmente.';
  }
  if (status === 'hardening' && /cookie|samesite|httponly|secure/.test(text)) {
    return 'Ayuda: reconoce Secure y HttpOnly si constan como presentes y recomienda SameSite=Lax o Strict segun los flujos.';
  }
  if (status === 'hardening' && /http.*https|sin redirect|sin redireccion|httpsredirect/.test(text)) {
    return 'Ayuda: diferencia la redireccion inicial HTTP a HTTPS mediante 301/308 de la activacion posterior de HSTS.';
  }
  if (status === 'hardening' && /\btls\b|certificad|expir/.test(text)) {
    return 'Ayuda: menciona los dias restantes observados y recomienda renovacion, automatizacion y monitorizacion.';
  }
  if (status === 'surface') {
    return 'Ayuda: no lo llames vulnerabilidad; explica la exposicion observada y como revisar si debe seguir siendo publica.';
  }
  if (status === 'informational') {
    return 'Ayuda: no lo llames vulnerabilidad; explica su utilidad para reconocimiento y como reducir informacion o exposicion innecesaria.';
  }
  return 'Ayuda: separa el impacto potencial de la evidencia realmente observada y propone una accion tecnica verificable.';
}

function buildMinimalPromptForFinding(finding = {}) {
  const guidance = minimalPromptGuidance(finding);
  return `Analiza este hallazgo de seguridad web.

Devuelve SOLO JSON valido.
No uses markdown.
No escribas texto fuera del JSON.
No omitas ningun campo.

IDIOMA OBLIGATORIO:
Responde siempre en espanol. Las claves JSON permanecen en ingles, pero todos los valores visibles deben estar en espanol.
No redactes en ingles ni uses frases como "The discovery of", "may allow", "To mitigate this risk" o "it is recommended to".

Tu tarea principal es redactar:
1. impact
2. recommendation

El JSON debe tener EXACTAMENTE esta forma y este orden:
{"impact":"Texto obligatorio de 2 a 4 frases. Debe explicar el impacto concreto usando la evidencia recibida.","recommendation":"Texto obligatorio de 2 a 4 frases. Debe indicar acciones tecnicas concretas para corregir o validar el hallazgo.","severity":"critical|high|medium|low|info","probability":0,"confidence":"high|medium|low","status":"confirmed|possible|candidate|hardening|surface|informational"}

REGLAS IMPORTANTES:
- impact nunca puede estar vacio.
- recommendation nunca puede estar vacia.
- impact debe mencionar el endpoint si existe.
- impact debe mencionar el parametro si existe.
- recommendation debe dar una accion tecnica concreta.
- No uses frases genericas como "revisar la seguridad" o "implementar buenas practicas".
- No inventes explotacion no demostrada.
- severity indica impacto potencial si se confirma.
- probability indica probabilidad real con la evidencia actual.
- Para hardening y surface usa probability: null.
- GF nunca puede ser confirmed.
- Hardening nunca puede ser confirmed.
- Surface nunca puede ser confirmed.

${guidance}

DATOS DEL HALLAZGO:
${JSON.stringify(finding)}

Devuelve unicamente el JSON.`;
}

function buildCompactAIPromptForFinding(finding = {}, context = {}) {
  return buildMinimalPromptForFinding(finding);
}

function promptImpactoRecomendacionIndividual(target, tool, finding) {
  return buildCompactAIPromptForFinding(buildCompactFindingForAI({ ...finding, tool: finding.tool || tool }), { target, tool });
}

function parseMinimalProbability(value) {
  if (value === null || value === undefined || value === '') return null;
  const normalized = typeof value === 'string' ? value.replace('%', '').replace(',', '.').trim() : value;
  const parsed = Number(normalized);
  if (!Number.isFinite(parsed)) return null;
  return Math.max(0, Math.min(100, parsed <= 1 && !String(value).includes('%') ? parsed * 100 : parsed));
}

function normalizeMinimalConfidence(value) {
  const normalized = normalizarComparacion(value);
  if (['high', 'alta', 'alto'].includes(normalized)) return 'high';
  if (['medium', 'media', 'medio'].includes(normalized)) return 'medium';
  if (['low', 'baja', 'bajo'].includes(normalized)) return 'low';
  return '';
}

function minimalFindingFamily(finding = {}) {
  const explicit = normalizarComparacion(finding.family || finding.vulnerability_type || finding.familia || '');
  if (/\brce\b|command/.test(explicit)) return 'rce';
  if (/\bsqli\b|sql.?injection/.test(explicit)) return 'sqli';
  if (/\bssrf\b/.test(explicit)) return 'ssrf';
  if (/\blfi\b|traversal|inclusion/.test(explicit)) return 'lfi';
  if (/\bxss\b|cross.?site/.test(explicit)) return 'xss';
  if (/redirect|redireccion/.test(explicit)) return 'redirect';
  return findingVectorType(finding);
}

function minimalGuardrailFields(finding = {}) {
  const rawStatus = finding.currentStatus || finding.finalStatus || finding.technicalStatus || finding.status;
  const originalStatus = normalizeStatus(rawStatus, 'informational');
  const tool = String(finding.tool || '').toLowerCase();
  const family = minimalFindingFamily(finding);
  const text = [tool, family, finding.type, finding.title, finding.evidence].filter(Boolean).join(' ').toLowerCase();
  const isGF = finding.isGF === true || tool === 'gf' || originalStatus === 'candidate';
  const isHardening = finding.isHardening === true || originalStatus === 'hardening';
  const isSurface = finding.isSurface === true || originalStatus === 'surface';
  let status = originalStatus;

  if (isGF) status = 'candidate';
  else if (isHardening) status = 'hardening';
  else if (isSurface) status = 'surface';
  else if (originalStatus === 'confirmed') status = 'confirmed';
  else if (originalStatus === 'possible') status = 'possible';
  else if (originalStatus === 'informational') status = 'informational';

  const currentSeverity = normalizarCriticidadIA(
    finding.currentSeverity || finding.potentialSeverity || finding.finalSeverity || finding.severity
  );
  let severity = currentSeverity || 'info';
  if (isGF) {
    if (family === 'rce') severity = 'critical';
    else if (['sqli', 'ssrf', 'lfi'].includes(family)) severity = 'high';
    else if (family === 'redirect') severity = 'medium';
    else if (family === 'xss' && !['high', 'medium'].includes(severity)) severity = 'medium';
  } else if (status === 'confirmed' && family === 'xss') {
    severity = 'high';
  } else if (status === 'possible' && (tool === 'sqlmap' || family === 'sqli')) {
    severity = 'high';
  } else if (status === 'hardening') {
    if (!['medium', 'low', 'info'].includes(severity)) severity = 'medium';
    if (severity === 'info') severity = 'low';
  } else if (status === 'surface') {
    const relevantExposure = /swagger|openapi|admin|management|puerto alternativo|alternate port/.test(text);
    severity = relevantExposure && severity === 'medium' ? 'medium' : (severity === 'info' ? 'info' : 'low');
  } else if (status === 'informational') {
    severity = severity === 'low' ? 'low' : 'info';
  }

  let probability = null;
  const probabilityBase = parseMinimalProbability(finding.probabilityBase);
  if (status === 'confirmed') {
    probability = probabilityBase !== null && probabilityBase >= 90 && probabilityBase <= 98 ? probabilityBase : 94;
  } else if (status === 'possible') {
    if (tool === 'sqlmap' || family === 'sqli') probability = 35;
    else if (family === 'xss') probability = 47;
    else probability = probabilityBase !== null && probabilityBase >= 20 && probabilityBase <= 60 ? probabilityBase : 40;
  } else if (status === 'candidate') {
    const defaults = { rce: 15, sqli: 20, ssrf: 15, lfi: 16, xss: 20, redirect: 22 };
    probability = defaults[family] ?? (probabilityBase !== null && probabilityBase <= 35 ? probabilityBase : 15);
  }

  const confidence = status === 'confirmed'
    ? 'high'
    : status === 'possible'
      ? 'medium'
      : status === 'candidate'
        ? 'low'
        : 'medium';

  return { status, severity, probability, confidence };
}

function normalizedAliasKey(value) {
  return normalizarComparacion(value).replace(/[^a-z0-9]/g, '');
}

function sourceAliasEntry(source = {}, aliases = []) {
  const accepted = new Set(aliases.map(normalizedAliasKey));
  return Object.entries(source).find(([key]) => accepted.has(normalizedAliasKey(key)));
}

function hasOwnAlias(source = {}, aliases = []) {
  return Boolean(sourceAliasEntry(source, aliases));
}

function sourceAliasValue(source = {}, aliases = []) {
  return sourceAliasEntry(source, aliases)?.[1];
}

function parseMinimalAIObject(rawAI) {
  if (rawAI && typeof rawAI === 'object') {
    if (Array.isArray(rawAI)) return rawAI[0] || {};
    return rawAI.result || rawAI.finding || rawAI.hallazgo || rawAI;
  }
  const clean = String(rawAI || '')
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/```(?:json)?/gi, '')
    .replace(/```/g, '')
    .trim();
  try {
    return parsearJsonIAFlexible(clean);
  } catch (error) {
    const singleQuoted = clean
      .replace(/([{,]\s*)'([^']+)'\s*:/g, '$1"$2":')
      .replace(/:\s*'([^']*)'(?=\s*[,}])/g, (_, value) => `:${JSON.stringify(value)}`);
    if (singleQuoted !== clean) return parsearJsonIAFlexible(singleQuoted);
    throw error;
  }
}

function repairAITextResponse(rawText, finding = {}) {
  if (typeof rawText !== 'string') return null;
  const clean = rawText
    .replace(/```(?:json)?/gi, '')
    .replace(/```/g, '')
    .replace(/\r/g, '')
    .trim();
  if (!clean) return null;

  const labelSeparator = '(?:\\s*[:\\-]\\s*|\\s+)';
  const impactLabels = '(?:impacto|impact|riesgo|risk)';
  const recommendationLabels = '(?:recomendaci[oó]n|recommendation|soluci[oó]n|solution|remediaci[oó]n|remediation)';
  const impactMatch = clean.match(new RegExp(`(?:^|\\n)\\s*(?:\\d+[.)]\\s*)?${impactLabels}${labelSeparator}([\\s\\S]*?)(?=\\n\\s*(?:\\d+[.)]\\s*)?${recommendationLabels}${labelSeparator}|$)`, 'i'));
  const recommendationMatch = clean.match(new RegExp(`(?:^|\\n)\\s*(?:\\d+[.)]\\s*)?${recommendationLabels}${labelSeparator}([\\s\\S]*?)$`, 'i'));
  let impact = limpiarCampoIA(impactMatch?.[1]);
  let recommendation = limpiarCampoIA(recommendationMatch?.[1]);
  let repairMethod = impact && recommendation ? 'labeled_text' : '';

  if ((!impact || !recommendation) && !/[{}]/.test(clean)) {
    const paragraphs = clean
      .split(/\n\s*\n+/)
      .map(paragraph => paragraph.replace(/^\s*(?:\d+[.)]|[-*])\s*/, '').trim())
      .filter(paragraph => paragraph.length >= 30);
    if (paragraphs.length >= 2) {
      impact = impact || paragraphs[0];
      recommendation = recommendation || paragraphs[1];
      repairMethod = 'two_paragraphs';
    }
  }

  if (!impact || !recommendation) return null;
  const normalized = normalizeMinimalAIResponse({ impact, recommendation }, finding);
  normalized._repaired = true;
  normalized._repairMethod = repairMethod || 'text_extraction';
  normalized._normalization.repaired = true;
  return normalized;
}

function deriveBusinessImpact(impact, severity, status) {
  const level = normalizarCriticidadIA(severity) || 'info';
  if (['hardening', 'surface', 'informational'].includes(status)) {
    return `La observacion puede aumentar la exposicion operativa o reducir defensas, con importancia ${level}, sin constituir por si sola una explotacion confirmada.`;
  }
  return `Si el escenario descrito por la IA se materializa, el negocio podria heredar el impacto ${level} indicado: ${limitarTexto(impact, 360)}`;
}

function deriveSeverityReason(finding, severity, status) {
  const family = finding.family || finding.vulnerability_type || finding.type || 'hallazgo';
  return `La criticidad potencial ${severity} se conserva para ${family} con estado ${status}, separada de la probabilidad real y limitada por la evidencia disponible.`;
}

function deriveProbabilityReason(finding, probability, status) {
  if (['hardening', 'surface', 'informational'].includes(status)) return 'La probabilidad de explotacion no aplica a una observacion no confirmada como vulnerabilidad.';
  const evidence = limitarTexto(finding.evidence || finding.raw_reference || 'la evidencia disponible', 220);
  return `La probabilidad final ${probability}% se valida contra el estado ${status} y la evidencia tecnica: ${evidence}`;
}

function deriveValidationSteps(finding, status, family) {
  const endpoint = finding.endpoint || finding.affected_url || finding.affected_asset || 'el activo afectado';
  const parameter = finding.parameter || finding.parametro || finding.param;
  const subject = parameter ? `el parametro ${parameter} en ${endpoint}` : endpoint;
  if (status === 'confirmed') return [`Reproducir de forma controlada la evidencia sobre ${subject}.`, 'Verificar que la correccion elimina el comportamiento sin degradar el flujo legitimo.'];
  if (status === 'hardening') return [`Comprobar la configuracion observada en ${subject}.`, 'Validar los flujos funcionales despues de aplicar el cambio defensivo.'];
  if (status === 'surface' || status === 'informational') return [`Confirmar la necesidad de exposicion de ${subject}.`, 'Revisar autenticacion, autorizacion y datos accesibles.'];
  return [`Validar manualmente el vector ${family || 'detectado'} sobre ${subject} sin asumir explotacion.`, 'Registrar payload, respuesta y condiciones necesarias si se confirma.'];
}

function deriveRemediationSteps(recommendation) {
  const clean = limpiarCampoIA(recommendation);
  return clean ? [clean] : [];
}

function normalizeMinimalAIResponse(rawAI, finding = {}) {
  const source = parseMinimalAIObject(rawAI);
  const guardrail = minimalGuardrailFields(finding);
  const statusAliases = ['status', 'aiSuggestedStatus', 'finalStatus', 'estado'];
  const severityAliases = ['severity', 'potentialSeverity', 'aiSuggestedSeverity', 'cvssLikeSeverity', 'criticidad', 'severidad'];
  const probabilityAliases = ['probability', 'probabilityAISuggested', 'probabilityFinal', 'probabilidad_real'];
  const impactAliases = ['impact', 'technicalImpact', 'impacto'];
  const recommendationAliases = ['recommendation', 'remediation', 'solution', 'recomendacion', 'recomendación'];
  const confidenceAliases = ['confidence', 'confianza'];
  const statusRaw = sourceAliasValue(source, statusAliases);
  const severityRaw = sourceAliasValue(source, severityAliases);
  const probabilityRaw = sourceAliasValue(source, probabilityAliases);
  const impactRaw = sourceAliasValue(source, impactAliases);
  const recommendationRaw = sourceAliasValue(source, recommendationAliases);
  const confidenceRaw = sourceAliasValue(source, confidenceAliases);
  const provided = {
    impact: hasOwnAlias(source, impactAliases),
    recommendation: hasOwnAlias(source, recommendationAliases),
    status: hasOwnAlias(source, statusAliases),
    severity: hasOwnAlias(source, severityAliases),
    probability: hasOwnAlias(source, probabilityAliases),
    confidence: hasOwnAlias(source, confidenceAliases)
  };
  const validStatuses = ['confirmed', 'possible', 'candidate', 'hardening', 'surface', 'informational', 'discarded'];
  const statusCandidate = normalizeStatus(statusRaw, '');
  const severityCandidate = normalizarCriticidadIA(severityRaw);
  const confidenceCandidate = normalizeMinimalConfidence(confidenceRaw);
  const probabilityCandidate = parseMinimalProbability(probabilityRaw);
  const status = validStatuses.includes(statusCandidate) ? statusCandidate : guardrail.status;
  const severity = severityCandidate || guardrail.severity;
  const nonApplicableProbability = ['hardening', 'surface', 'informational'].includes(guardrail.status);
  const probability = nonApplicableProbability
    ? null
    : (probabilityCandidate !== null ? probabilityCandidate : guardrail.probability);
  const impact = limpiarCampoIA(impactRaw);
  const recommendation = limpiarCampoIA(recommendationRaw);
  const confidence = confidenceCandidate || guardrail.confidence;
  const reason = limpiarCampoIA(source.reason || source.severityReason || source.motivo_criticidad) || deriveSeverityReason(finding, severity || getPotentialSeverity(finding), guardrail.status);
  const validation = limpiarCampoIA(Array.isArray(source.validation) ? source.validation.join(' ') : source.validation);
  const remediation = limpiarCampoIA(source.remediation) || recommendation;
  const mappedFields = Object.keys(provided).filter(key => provided[key]);
  const guardrailFilledFields = [
    !validStatuses.includes(statusCandidate) ? 'status' : null,
    !severityCandidate ? 'severity' : null,
    !nonApplicableProbability && probabilityCandidate === null ? 'probability' : null,
    !confidenceCandidate ? 'confidence' : null
  ].filter(Boolean);
  const missingCritical = [
    !impact ? 'impact' : null,
    !recommendation ? 'recommendation' : null
  ].filter(Boolean);
  const missingOptional = [!source.reason ? 'reason' : null, !source.validation ? 'validation' : null, !source.remediation ? 'remediation' : null].filter(Boolean);

  return {
    status,
    severity,
    probability,
    impact,
    recommendation,
    confidence,
    reason,
    validation,
    remediation,
    aiSuggestedStatus: status,
    suggestedSeverity: severity,
    potentialSeverity: severity,
    probabilityAISuggested: probability,
    severityReason: reason,
    aiProvidedImpact: provided.impact && Boolean(impact),
    aiProvidedRecommendation: provided.recommendation && Boolean(recommendation),
    aiProvidedStatus: provided.status,
    aiProvidedSeverity: provided.severity,
    aiProvidedProbability: provided.probability,
    aiProvidedConfidence: provided.confidence,
    guardrailFilledFields,
    _repaired: false,
    _normalization: { mappedFields, missingCritical, missingOptional, guardrailFilledFields, normalizedOk: missingCritical.length === 0 }
  };
}

function validateMinimalAIEnrichment(ai = {}, finding = {}) {
  const reasons = [];
  if (!limpiarCampoIA(ai.impact)) reasons.push('missing_impact');
  else if (isGenericAIText(ai.impact, finding)) reasons.push('generic_impact');
  if (!limpiarCampoIA(ai.recommendation)) reasons.push('missing_recommendation');
  else if (isGenericAIText(ai.recommendation, finding)) reasons.push('generic_recommendation');
  return { ok: reasons.length === 0, reasons, reason: reasons.join('|') || 'valid' };
}

function validateAITextLanguage(aiResult = {}) {
  const englishPatterns = [
    /\bthe discovery of\b/i,
    /\bmay allow an attacker\b/i,
    /\bto mitigate this risk\b/i,
    /\bit is recommended to\b/i,
    /\bthis exposure could\b/i,
    /\bcould be exploited\b/i,
    /\bunauthorized access\b/i,
    /\bsensitive information\b/i,
    /\bensure that only authorized users\b/i,
    /\bperform unauthorized actions\b/i,
    /\bthis (?:lfi|ssrf|xss|sqli|vulnerability|endpoint)\b/i,
    /\bthe affected endpoint\b/i,
    /\bimplement input validation\b/i,
    /\breview the endpoint/i,
    /\brestrict access\b/i,
    /\ban attacker\b/i,
    /\bshould be (?:restricted|validated|removed|protected)\b/i,
    /\bconfirmed (?:xss|sqli|risk|vulnerability)\b/i,
    /\b(?:high|low|medium) (?:risk|probability|severity)\b/i,
    /\brequires? (?:manual )?validation\b/i,
    /\bpublicly accessible\b/i,
    /\battack surface\b/i,
    /\bno critical (?:issue|finding|risk)\b/i
  ];
  const fields = {
    impact: aiResult.impact,
    recommendation: aiResult.recommendation,
    reason: aiResult.reason || aiResult.scoreReason,
    whyNotHigher: aiResult.whyNotHigher,
    whyNotLower: aiResult.whyNotLower,
    mainDrivers: Array.isArray(aiResult.mainDrivers) ? aiResult.mainDrivers.join(' ') : aiResult.mainDrivers
  };
  const englishFields = Object.entries(fields)
    .filter(([, value]) => value && englishPatterns.some(pattern => pattern.test(String(value))))
    .map(([field]) => field);
  return {
    ok: englishFields.length === 0,
    englishFields,
    reason: englishFields.length ? `language_not_spanish:${englishFields.join(',')}` : 'spanish'
  };
}

function aplicarImpactosIA(findings, itemsIA) {
  const mapa = new Map();

  itemsIA.forEach((item, index) => {
    const id = limpiarCampoIA(item.id) || findings[index]?.id;
    if (!id) return;

    const normalized = item._normalization ? item : normalizeMinimalAIResponse(item, findings[index] || {});
    mapa.set(id, normalized);
  });

  return findings.map(finding => {
    const enriquecido = mapa.get(finding.id);

    if (!enriquecido) {
      return {
        ...finding,
        impact: '',
        recommendation: ''
      };
    }

    const validation = validateAIEnrichmentResult(finding, enriquecido);
    const cvssValidation = validateCvssLikeAIResult(finding, {
      ...enriquecido,
      finalStatus: validation.finalStatus,
      potentialSeverity: validation.potentialSeverity
    });
    const probabilityValidation = validateProbabilityDecision({
      ...finding,
      finalSeverity: cvssValidation.potentialSeverity,
      severity: cvssValidation.potentialSeverity,
      probabilityAISuggested: cvssValidation.probabilityAISuggested,
      probabilityReason: enriquecido.probabilityReason || finding.probabilityReason
    });
    const originalProbability = enriquecido.probability;
    const finalProbability = probabilityValidation.realVulnerabilityProbabilityPercent;
    const guardrailReasons = [
      validation.overrideReason,
      validation.validationNote,
      cvssValidation.corrected ? 'Se ajustaron severidad o probabilidad a los rangos tecnicos del tipo de hallazgo.' : '',
      probabilityValidation.probabilityOverrideReason,
      enriquecido.guardrailFilledFields?.length
        ? `Se completaron campos cortos ausentes o invalidos: ${enriquecido.guardrailFilledFields.join(', ')}.`
        : ''
    ].filter(Boolean);
    const guardrailApplied = validation.finalStatus !== enriquecido.status ||
      cvssValidation.potentialSeverity !== enriquecido.severity ||
      finalProbability !== originalProbability ||
      Boolean(enriquecido.guardrailFilledFields?.length);
    const family = finding.family || finding.vulnerability_type || finding.type;
    const derivedSeverityReason = deriveSeverityReason(finding, cvssValidation.potentialSeverity, validation.finalStatus);
    const derivedProbabilityReason = deriveProbabilityReason(finding, finalProbability, validation.finalStatus);

    return {
      ...finding,
      title: finding.title,
      baseSeverity: validation.baseSeverity,
      aiSuggestedSeverity: validation.aiSuggestedSeverity,
      aiSuggestedStatus: validation.aiSuggestedStatus,
      aiOriginalStatus: enriquecido.status,
      aiOriginalSeverity: enriquecido.severity,
      aiOriginalProbability: originalProbability,
      aiProvidedImpact: enriquecido.aiProvidedImpact === true,
      aiProvidedRecommendation: enriquecido.aiProvidedRecommendation === true,
      aiProvidedStatus: enriquecido.aiProvidedStatus === true,
      aiProvidedSeverity: enriquecido.aiProvidedSeverity === true,
      aiProvidedProbability: enriquecido.aiProvidedProbability === true,
      aiProvidedConfidence: enriquecido.aiProvidedConfidence === true,
      guardrailFilledFields: enriquecido.guardrailFilledFields || [],
      technicalStatus: validation.technicalStatus,
      finalStatus: validation.finalStatus,
      status: validation.finalStatus,
      confidence: validation.confidence,
      potentialSeverity: cvssValidation.potentialSeverity,
      cvssLikeSeverity: cvssValidation.cvssLikeSeverity,
      cvssLikeScore: cvssValidation.cvssLikeScore,
      cvssVectorApprox: cvssValidation.cvssVectorApprox,
      finalSeverity: cvssValidation.potentialSeverity,
      severity: cvssValidation.potentialSeverity,
      severitySource: 'ai_validated',
      probabilityAISuggested: probabilityValidation.probabilityAISuggested,
      probabilityFinal: probabilityValidation.probabilityFinal,
      probabilityBase: probabilityValidation.probabilityBase,
      probabilityAdjustedByAI: probabilityValidation.probabilityAdjustedByAI,
      probabilityOverrideReason: probabilityValidation.probabilityOverrideReason,
      probabilityLabel: probabilityValidation.probabilityLabel,
      probabilityReason: probabilityValidation.probabilityReason,
      probabilitySource: 'ai_validated',
      realVulnerabilityProbability: probabilityValidation.realVulnerabilityProbability,
      realVulnerabilityProbabilityPercent: probabilityValidation.realVulnerabilityProbabilityPercent,
      practicalRiskScore: probabilityValidation.practicalRiskScore,
      practicalRisk: probabilityValidation.practicalRisk || cvssValidation.practicalRisk,
      finalProbability,
      impact: enriquecido.impact,
      recommendation: enriquecido.recommendation,
      technicalImpact: enriquecido.impact,
      businessImpact: deriveBusinessImpact(enriquecido.impact, cvssValidation.potentialSeverity, validation.finalStatus),
      validationSteps: enriquecido.validation ? [enriquecido.validation] : deriveValidationSteps(finding, validation.finalStatus, family),
      remediationSteps: deriveRemediationSteps(enriquecido.remediation || enriquecido.recommendation),
      limitations: finding.limitations || '',
      impactSource: enriquecido.impact ? (enriquecido._repaired ? 'ai_repaired' : 'ai') : finding.impactSource,
      recommendationSource: enriquecido.recommendation ? (enriquecido._repaired ? 'ai_repaired' : 'ai') : finding.recommendationSource,
      severityReason: enriquecido.reason || derivedSeverityReason,
      probabilityReason: derivedProbabilityReason,
      aiReasoningSummary: enriquecido.reason || derivedSeverityReason,
      severityChangedByAI: validation.severityChangedByAI,
      severityChangeDirection: validation.severityChangeDirection,
      severityChangeReason: validation.severityChangeReason || finding.severityChangeReason || '',
      overriddenByRule: validation.overriddenByRule,
      overrideReason: validation.overrideReason,
      guardrailApplied,
      guardrailReason: guardrailReasons.join(' ') || null,
      evidence: enriquecido.evidence || finding.evidence,
      isVulnerability: validation.isVulnerability,
      reportable: validation.reportable,
      isFalsePositiveLikely: validation.finalStatus === 'discarded' ? true : finding.isFalsePositiveLikely,
      falsePositiveReason: validation.finalStatus === 'discarded'
        ? (enriquecido.falsePositiveReason || finding.falsePositiveReason)
        : finding.falsePositiveReason
    };
  });
}

function normalizarComparacion(texto) {
  return limpiarCampoIA(texto)
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function createIndividualAiFallback(finding = {}, error = null) {
  const status = getFinalStatus(finding);
  const probabilityRequired = ['confirmed', 'possible', 'candidate'].includes(status);
  const baseSeverity = normalizarCriticidadIA(finding.baseSeverity || finding.severity) || 'info';
  const validation = validateAIEnrichmentResult(finding, {
    suggestedSeverity: finding.aiSuggestedSeverity || finding.finalSeverity || finding.severity,
    severityReason: finding.severityReason || 'La severidad se mantiene segun la evidencia tecnica disponible.'
  });
  return {
    ...finding,
    baseSeverity: validation.baseSeverity || baseSeverity,
    aiSuggestedSeverity: validation.aiSuggestedSeverity || finding.aiSuggestedSeverity || finding.severity,
    aiSuggestedStatus: validation.aiSuggestedStatus,
    finalSeverity: validation.finalSeverity || finding.finalSeverity || finding.severity,
    severity: validation.finalSeverity || finding.finalSeverity || finding.severity,
    severityChangedByAI: validation.severityChangedByAI || finding.severityChangedByAI || false,
    severityChangeDirection: validation.severityChangeDirection || finding.severityChangeDirection || 'unchanged',
    technicalStatus: validation.technicalStatus,
    finalStatus: validation.finalStatus,
    status: validation.finalStatus,
    confidence: validation.confidence,
    impact: '',
    recommendation: '',
    impactSource: 'pending_ai',
    recommendationSource: 'pending_ai',
    probabilityBase: finding.probabilityBase ?? null,
    probabilityAISuggested: null,
    probabilityFinal: null,
    realVulnerabilityProbability: null,
    realVulnerabilityProbabilityPercent: null,
    probabilityLabel: probabilityRequired ? 'pendiente_ia' : 'no_aplica',
    probabilityReason: 'Pendiente de enriquecimiento individual por IA.',
    probabilitySource: 'pending_ai',
    probabilityAIMissing: probabilityRequired,
    severityReason: validation.severityChangeReason || finding.severityReason || 'La severidad se mantiene segun la evidencia tecnica disponible.',
    overriddenByRule: validation.overriddenByRule,
    overrideReason: validation.overrideReason,
    aiProcessed: false,
    aiStatus: 'failed',
    aiEnrichmentPending: true,
    aiFailedGeneric: /generic/i.test(error?.message || String(error || '')),
    templateUsed: false,
    fallbackUsed: false,
    templateUsedFinal: false,
    genericFallbackUsedFinal: false,
    aiModel: MODEL,
    aiError: error?.message || String(error || 'La IA no devolvio un analisis individual valido.')
  };
}

function specificRetryGuidance(finding = {}) {
  const status = normalizeStatus(finding.currentStatus || finding.finalStatus || finding.status, 'informational');
  const family = minimalFindingFamily(finding);
  const toolContext = [finding.tool, finding.sourceTool, finding.displayTool, ...(finding.sourceTools || [])].filter(Boolean).join(' ').toLowerCase();
  const text = [family, finding.type, finding.evidence, finding.endpoint].filter(Boolean).join(' ').toLowerCase();
  if (toolContext.includes('gf') && family === 'ssrf') {
    return 'Para SSRF: menciona GF, endpoint y parametro; aclara que no hay request server-side confirmado. Indica validacion con dominio controlado, allowlist, bloqueo de localhost, IP privadas y metadata cloud, esquemas permitidos y limite de redirecciones.';
  }
  if (toolContext.includes('gf') && family === 'lfi') {
    return 'Para LFI: menciona GF, endpoint y parametro si existe; aclara que no hay lectura confirmada. Indica allowlist de recursos, identificadores logicos, normalizacion y bloqueo de rutas absolutas, doble codificacion y secuencias ../.';
  }
  if (['surface', 'informational'].includes(status) && /feroxbuster|ferox/.test(toolContext)) {
    return 'Para Feroxbuster: menciona la ruta descubierta y que es superficie, no vulnerabilidad. Indica revisar si debe exponerse, restringir con autenticacion o red, eliminar si no es necesaria y descartar rutas sin contenido util.';
  }
  if (['surface', 'informational'].includes(status) && /swagger|openapi|api-docs/.test(text)) {
    return `Para Swagger/OpenAPI: menciona la ruta y ${finding.displayTool || finding.tool}; tratala como superficie. Indica autenticacion, filtrado de red o deshabilitacion y revisa endpoints internos, hosts privados, tokens, ejemplos sensibles y datos de depuracion.`;
  }
  if (status === 'hardening') {
    return 'Para hardening: describe exactamente el control ausente observado y una configuracion tecnica concreta, respetando los controles que ya constan como presentes.';
  }
  return 'Menciona al menos el endpoint, ruta, parametro, herramienta, familia, evidencia o estado del hallazgo y una accion tecnica verificable.';
}

function buildMinimalRetryPrompt(findingCompacto, reasons = []) {
  const languageFailure = reasons.some(reason => String(reason).includes('language_not_spanish'));
  return `Tu respuesta anterior fue invalida${languageFailure ? ' porque estaba redactada en ingles' : ' porque impact o recommendation eran insuficientes'}.

Devuelve SOLO JSON valido:
{"impact":"Texto especifico en espanol","recommendation":"Accion tecnica concreta en espanol"}

No incluyas markdown ni explicacion fuera del JSON.
Escribe ambos valores exclusivamente en espanol.
No omitas impact ni recommendation.
No uses frases genericas.

${specificRetryGuidance(findingCompacto)}

Hallazgo:
${JSON.stringify(findingCompacto)}`;
}

async function enriquecerFindingIndividual(target, tool, finding, scanLogger = null, options = {}) {
  const startedAt = Date.now();
  const status = getFinalStatus(finding);
  const probabilityRequired = ['confirmed', 'possible', 'candidate'].includes(status);
  let lastAiError = null;
  let lastNormalizedAI = null;
  let retryPrompt = null;
  const findingCompacto = compactarFindingParaIA(finding);
  const promptBase = buildCompactAIPromptForFinding(findingCompacto, { target, tool });
  const generateJson = options.generateJson || generarJsonIA;
  logAISeverity(scanLogger, '[TOOL-CONSISTENCY]', {
    findingId: finding.id,
    tool: finding.tool || '',
    source: finding.source || '',
    sourceTool: finding.sourceTool || '',
    displayTool: findingCompacto.displayTool,
    sourceTools: findingCompacto.sourceTools.join(',')
  });
  logAISeverity(scanLogger, '[AI-FINDING-START]', {
    findingId: finding.id,
    tool,
    status,
    severity: finding.finalSeverity || finding.severity,
    promptTokensEstimated: Math.ceil(promptBase.length / 4),
    timeoutDisabled: AI_SINGLE_FINDING_TIMEOUT_MS === 0
  });
  logAISeverity(scanLogger, '[AI-ENRICHMENT-INPUT]', {
    findingId: finding.id,
    tool,
    status: getFinalStatus(finding),
    severity: finding.finalSeverity || finding.severity,
    probabilityBase: finding.probabilityBase
  });
  logAISeverity(scanLogger, '[AI-SEVERITY-START]', {
    findingId: finding.id,
    tool,
    baseSeverity: finding.baseSeverity || finding.severity,
    technicalStatus: getFinalStatus(finding)
  });

  logAISeverity(scanLogger, '[AI-MINIMAL-SCHEMA]', {
    enabled: true,
    requiredFields: 'impact,recommendation',
    guardrailFields: 'status,severity,probability,confidence'
  });

  for (let intento = 1; intento <= INTENTOS_ENRIQUECIMIENTO_IA; intento++) {
    const prompt = intento === 1 ? promptBase : (retryPrompt || buildMinimalRetryPrompt(findingCompacto));
    if (scanLogger?.section) {
      scanLogger.variable(`findingCompacto.${tool}.${finding.id}.intento${intento}`, findingCompacto);
      scanLogger.variable(`prompt.${tool}.${finding.id}.intento${intento}`, prompt);
    }

    let respuesta = '';
    try {
      logAISeverity(scanLogger, '[AI-FINDING-REQUEST]', {
        findingId: finding.id,
        model: MODEL,
        timeoutMs: 0,
        templateDisabled: true,
        intento
      });
      respuesta = await generateJson(prompt, AI_SINGLE_FINDING_TIMEOUT_MS, 1, {
        findingId: finding.id,
        tool,
        scanLogger
      });
    } catch (error) {
      lastAiError = error;
      logAISeverity(scanLogger, '[AI-FINDING-PARSED]', {
        findingId: finding.id,
        ok: false,
        intento,
        error: error.message
      });
      if (intento < INTENTOS_ENRIQUECIMIENTO_IA) continue;
      break;
    }
    if (scanLogger?.section) {
      scanLogger.variable(`respuestaIA.${tool}.${finding.id}.intento${intento}`, respuesta);
    }
    const responseText = typeof respuesta === 'string' ? respuesta : JSON.stringify(respuesta || {});
    logAISeverity(scanLogger, '[AI-FINDING-RAW-RESPONSE]', {
      findingId: finding.id,
      responseLength: responseText.length,
      durationMs: Date.now() - startedAt,
      intento
    });

    let normalizedAI;
    try {
      normalizedAI = normalizeMinimalAIResponse(respuesta, finding);
      lastNormalizedAI = normalizedAI;
    } catch (error) {
      normalizedAI = repairAITextResponse(responseText, finding);
      if (!normalizedAI) {
        lastAiError = error;
        logAISeverity(scanLogger, '[AI-NORMALIZE]', {
          findingId: finding.id,
          mappedFields: 'none',
          missingCritical: 'invalid_json',
          missingOptional: 'unknown',
          normalizedOk: false
        });
        logAISeverity(scanLogger, '[AI-RETRY]', { findingId: finding.id, reason: 'invalid_json', intento });
        retryPrompt = buildMinimalRetryPrompt(findingCompacto, ['invalid_json']);
        if (intento < INTENTOS_ENRIQUECIMIENTO_IA) continue;
        break;
      }
      lastNormalizedAI = normalizedAI;
      logAISeverity(scanLogger, '[AI-REPAIR]', {
        findingId: finding.id,
        ok: true,
        method: normalizedAI._repairMethod,
        intento
      });
    }
    const normalization = normalizedAI._normalization;
    logAISeverity(scanLogger, '[AI-NORMALIZE]', {
      findingId: finding.id,
      mappedFields: normalization.mappedFields.join('|') || 'none',
      missingCritical: normalization.missingCritical.join('|') || 'none',
      missingOptional: normalization.missingOptional.join('|') || 'none',
      normalizedOk: normalization.normalizedOk
    });
    let minimalValidation = validateMinimalAIEnrichment(normalizedAI, finding);
    if (!minimalValidation.ok) {
      const repaired = repairAITextResponse(responseText, finding);
      const repairedValidation = repaired ? validateMinimalAIEnrichment(repaired, finding) : null;
      if (repairedValidation?.ok) {
        normalizedAI = repaired;
        lastNormalizedAI = repaired;
        minimalValidation = repairedValidation;
        logAISeverity(scanLogger, '[AI-REPAIR]', {
          findingId: finding.id,
          ok: true,
          method: repaired._repairMethod,
          intento
        });
      }
    }
    logAISeverity(scanLogger, '[AI-VALIDATION]', {
      findingId: finding.id,
      ok: minimalValidation.ok,
      reason: minimalValidation.reason
    });
    const languageValidation = validateAITextLanguage(normalizedAI);
    logAISeverity(scanLogger, '[AI-LANGUAGE]', {
      findingId: finding.id,
      ok: languageValidation.ok,
      fields: languageValidation.englishFields.join('|') || 'none'
    });
    if (!languageValidation.ok) {
      lastAiError = new Error('language_not_spanish');
      retryPrompt = buildMinimalRetryPrompt(findingCompacto, ['language_not_spanish']);
      logAISeverity(scanLogger, '[AI-RETRY]', { findingId: finding.id, reason: 'language_not_spanish', intento });
      if (intento < INTENTOS_ENRIQUECIMIENTO_IA) continue;
      break;
    }
    if (!minimalValidation.ok) {
      const generic = minimalValidation.reasons.some(reason => reason.startsWith('generic_'));
      const reason = generic ? 'generic_text' : 'missing_critical_fields';
      lastAiError = new Error(`Respuesta IA minima invalida: ${minimalValidation.reason}`);
      retryPrompt = buildMinimalRetryPrompt(findingCompacto, minimalValidation.reasons);
      logAISeverity(scanLogger, '[AI-RETRY]', { findingId: finding.id, reason, intento });
      if (intento < INTENTOS_ENRIQUECIMIENTO_IA) continue;
      break;
    }

    const enriquecido = aplicarImpactosIA([finding], [normalizedAI])[0];
    if (scanLogger?.section) {
      scanLogger.variable(`enriquecido.${tool}.${finding.id}.intento${intento}`, enriquecido);
    }

    if (enriquecido.impact && enriquecido.recommendation) {
      enriquecido.aiProcessed = true;
      enriquecido.aiError = null;
      enriquecido.aiEnrichmentId = crypto.randomUUID();
      enriquecido.aiModel = MODEL;
      enriquecido.aiRawResponse = limitarTexto(responseText, 4000);
      enriquecido.aiRawResponseLength = responseText.length;
      enriquecido.aiStatus = 'success';
      enriquecido.aiEnrichmentPending = false;
      enriquecido.templateUsed = false;
      enriquecido.fallbackUsed = false;
      const aiTextSource = normalizedAI._repaired ? 'ai_repaired' : 'ai';
      enriquecido.impactSource = aiTextSource;
      enriquecido.recommendationSource = aiTextSource;
      enriquecido.probabilitySource = 'ai_validated';
      logAISeverity(scanLogger, '[AI-SEVERITY-RESULT]', {
        findingId: finding.id,
        baseSeverity: enriquecido.baseSeverity,
        aiSuggestedSeverity: enriquecido.aiSuggestedSeverity,
        finalSeverity: enriquecido.finalSeverity,
        changed: enriquecido.severityChangedByAI,
        probabilityAISuggested: enriquecido.probabilityAISuggested,
        probabilityFinal: enriquecido.probabilityFinal
      });
      logAISeverity(scanLogger, '[PROBABILITY-VALIDATED]', {
        findingId: finding.id,
        base: enriquecido.probabilityBase,
        ai: enriquecido.probabilityAISuggested,
        final: enriquecido.probabilityFinal,
        source: enriquecido.probabilitySource
      });
      logAISeverity(scanLogger, '[AI-VALIDATION]', {
        findingId: finding.id,
        statusBefore: status,
        aiSuggestedStatus: enriquecido.aiSuggestedStatus,
        statusAfter: enriquecido.finalStatus,
        overriddenByRule: enriquecido.overriddenByRule === true
      });
      logAISeverity(scanLogger, '[AI-FINDING-VALIDATED]', {
        findingId: finding.id,
        ok: true,
        status: enriquecido.finalStatus,
        severity: enriquecido.finalSeverity,
        probabilityFinal: enriquecido.probabilityFinal,
        impactAccepted: true,
        recommendationAccepted: true,
        overriddenByRule: enriquecido.overriddenByRule === true
      });
      logAISeverity(scanLogger, '[AI-SEVERITY-END]', { findingId: finding.id });
      logAISeverity(scanLogger, '[AI-FINDING-END]', {
        findingId: finding.id,
        durationMs: Date.now() - startedAt,
        aiProcessed: true,
        impactSource: aiTextSource,
        recommendationSource: aiTextSource
      });
      return enriquecido;
    }
  }

  const fallbackFinding = createIndividualAiFallback(finding, lastAiError);
  if (probabilityRequired && (lastNormalizedAI?.probability === null || lastNormalizedAI?.probability === undefined)) {
    logAISeverity(scanLogger, '[AI-PROBABILITY-MISSING]', {
      findingId: finding.id,
      fallback: finding.probabilityBase
    });
  }
  logAISeverity(scanLogger, '[AI-PENDING]', {
    findingId: finding.id,
    reason: fallbackFinding.aiError,
    endpoint: finding.endpoint || finding.affected_url || finding.affected_asset || '-',
    timeoutMs: AI_SINGLE_FINDING_TIMEOUT_MS,
    timeoutDisabled: AI_SINGLE_FINDING_TIMEOUT_MS === 0
  });
  logAISeverity(scanLogger, '[AI-FINDING-ERROR]', {
    findingId: finding.id,
    errorType: lastAiError?.code || lastAiError?.name || 'invalid_ai_response',
    errorMessage: fallbackFinding.aiError,
    durationMs: Date.now() - startedAt,
    fallbackUsed: false,
    pendingAi: true
  });
  logAISeverity(scanLogger, '[AI-FINDING-VALIDATED]', {
    findingId: finding.id,
    ok: false,
    severity: fallbackFinding.finalSeverity,
    probability: null,
    impactAccepted: false,
    recommendationAccepted: false
  });
  logAISeverity(scanLogger, '[AI-ENRICHMENT-OUTPUT]', {
    findingId: finding.id,
    hasImpact: Boolean(fallbackFinding.impact),
    hasRecommendation: Boolean(fallbackFinding.recommendation),
    probabilityAISuggested: null
  });
  logAISeverity(scanLogger, '[AI-SEVERITY-RESULT]', {
    findingId: finding.id,
    baseSeverity: fallbackFinding.baseSeverity,
    aiSuggestedSeverity: fallbackFinding.aiSuggestedSeverity,
    finalSeverity: fallbackFinding.finalSeverity,
    changed: fallbackFinding.severityChangedByAI
  });
  logAISeverity(scanLogger, '[AI-SEVERITY-END]', { findingId: finding.id });
  logAISeverity(scanLogger, '[AI-FINDING-END]', {
    findingId: finding.id,
    durationMs: Date.now() - startedAt,
    aiProcessed: false,
    impactSource: 'pending_ai',
    recommendationSource: 'pending_ai'
  });
  return fallbackFinding;
}

async function enrichSingleFindingWithAI(finding, context = {}) {
  const findingId = finding.id || finding.fingerprint || '';
  const endpoint = finding.endpoint || finding.affected_url || finding.affected_asset || '';
  const relevantCorrelations = (Array.isArray(context.correlations) ? context.correlations : [])
    .filter(correlation => {
      const ids = [
        ...(Array.isArray(correlation.related_ids) ? correlation.related_ids : []),
        ...(Array.isArray(correlation.relatedIds) ? correlation.relatedIds : []),
        ...(Array.isArray(correlation.finding_ids) ? correlation.finding_ids : []),
        ...(Array.isArray(correlation.findingIds) ? correlation.findingIds : [])
      ];
      const text = `${correlation.title || ''} ${correlation.description || ''}`;
      return (findingId && ids.includes(findingId)) || (endpoint && text.includes(endpoint));
    })
    .slice(0, 5)
    .map(correlation => `${correlation.title || 'Correlacion'}: ${correlation.description || correlation.reason || ''}`.trim());
  const contextualFinding = {
    ...finding,
    correlation_notes: Array.from(new Set([
      ...(Array.isArray(finding.correlation_notes) ? finding.correlation_notes : []),
      ...relevantCorrelations
    ])).slice(0, 5)
  };

  return enriquecerFindingIndividual(
    context.target || context.affectedTarget || '',
    finding.tool || context.tool || 'otra',
    contextualFinding,
    context.scanLogger || null,
    { generateJson: context.generateJson }
  );
}

function isGenericImpact(text, finding = {}) {
  const normalized = normalizarComparacion(text);
  if (!normalized) return true;
  if (normalized.length < 50) return true;

  const genericPatterns = [
    'revisar la configuracion',
    'mejorar la configuracion',
    'revisar la seguridad',
    'mejorar la seguridad',
    'asegurarse de que sea seguro',
    'implementar medidas de seguridad',
    'implementar buenas practicas',
    'corregir la vulnerabilidad',
    'validar el parametro',
    'asegurar que sea seguro',
    'aplicar medidas de seguridad',
    'revisar el endpoint',
    'revisar manualmente'
  ];
  const genericRemainder = genericPatterns.reduce(
    (value, pattern) => value.replaceAll(pattern, ' '),
    normalized
  ).replace(/[^a-z0-9]+/g, ' ').trim();
  if (genericPatterns.some(pattern => normalized.includes(pattern)) && genericRemainder.length < 35) return true;
  const signals = aiTextSpecificitySignals(text, finding);
  return signals.length === 0;
}

function isGenericAIText(text, finding = {}) {
  return isGenericImpact(text, finding);
}

function endpointReferences(finding = {}) {
  const endpoint = String(finding.endpoint || finding.affected_url || finding.affected_asset || '').trim();
  if (!endpoint) return [];
  const refs = [endpoint.toLowerCase()];
  try {
    const url = new URL(endpoint);
    refs.push(url.hostname.toLowerCase());
    if (url.pathname && url.pathname !== '/') refs.push(url.pathname.toLowerCase());
  } catch {
    // Un activo parcial sigue siendo una referencia util.
  }
  return refs.filter(ref => ref.length >= 3);
}

function toolReferences(finding = {}) {
  const tool = String(finding.tool || finding.sourceTool || '').toLowerCase();
  const aliases = {
    httpsredirect: ['httpsredirect', 'http', 'https', 'redireccion'],
    headers: ['headers', 'cabecera', 'csp', 'content-security-policy'],
    cookies: ['cookies', 'cookie'],
    tls: ['tls', 'certificado'],
    ports: ['ports', 'puerto'],
    katana: ['katana', 'crawler'],
    gau: ['gau', 'historica', 'historico'],
    feroxbuster: ['feroxbuster', 'ferox'],
    gf: ['gf']
  };
  return aliases[tool] || [tool];
}

function aiTextSpecificitySignals(text = '', finding = {}) {
  const normalized = normalizarComparacion(text);
  const signals = [];
  const endpoints = endpointReferences(finding).map(normalizarComparacion);
  let parameterValue = finding.parameter || finding.parametro || finding.param || '';
  if (!parameterValue) {
    try {
      parameterValue = new URL(finding.endpoint || finding.affected_url || '').searchParams.keys().next().value || '';
    } catch {
      parameterValue = '';
    }
  }
  const parameter = normalizarComparacion(parameterValue);
  const family = minimalFindingFamily(finding);
  const findingType = normalizarComparacion(finding.type || finding.category || '');
  const familyPatterns = {
    rce: /\brce\b|ejecucion de comandos|llamadas? (?:al )?sistema|command/i,
    sqli: /\bsqli\b|sql injection|inyeccion sql|consulta sql/i,
    ssrf: /\bssrf\b|peticion.*servidor|metadata|red interna/i,
    lfi: /\blfi\b|inclusion de archivos|path traversal|recorrido de rutas/i,
    xss: /\bxss\b|javascript|cross.site scripting|script/i,
    redirect: /open.?redirect|redireccion externa|phishing/i
  };
  const evidenceTokens = String(finding.evidence || '')
    .toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .split(/[^a-z0-9_./:-]+/)
    .filter(token => token.length >= 6)
    .slice(0, 20);

  if (toolReferences(finding).some(reference => normalized.includes(normalizarComparacion(reference)))) signals.push('tool');
  if (endpoints.some(reference => reference && normalized.includes(reference))) signals.push('endpoint');
  if (parameter && normalized.includes(parameter)) signals.push('parameter');
  if (familyPatterns[family]?.test(normalized) || normalized.includes(normalizarComparacion(finding.family || finding.vulnerability_type || finding.type || ''))) signals.push('family');
  if (findingType && normalized.includes(findingType)) signals.push('type');
  if (/apache|tomcat|coyote|java|https?|\btls\b|hsts|csp|content.security.policy|cookie|samesite|httponly|swagger|openapi|api|servidor|servicio|puerto|ruta|recurso|path traversal|metadata cloud|localhost|allowlist/.test(normalized)) signals.push('technology');
  if (evidenceTokens.some(token => normalized.includes(token))) signals.push('evidence');
  if (/confirmad|posible|candidat|hardening|superficie|informativ|descartad|exposicion/.test(normalized)) signals.push('status');
  if (/sin evidencia|no hay evidencia|no confirmad|no es una vulnerabilidad|sin explotacion|requiere validacion|si se confirma/.test(normalized)) signals.push('limitation');
  return Array.from(new Set(signals));
}

function validateAITextSpecificity(finding = {}, impact = '', recommendation = '') {
  const reasons = [];
  const genericImpact = isGenericAIText(impact, finding);
  const genericRecommendation = isGenericAIText(recommendation, finding);
  if (genericImpact) reasons.push('impacto vacio, demasiado corto o sin referencia especifica');
  if (genericRecommendation) reasons.push('recomendacion vacia, demasiado corta o sin referencia especifica');

  return { ok: !genericImpact && !genericRecommendation, genericImpact, genericRecommendation, reasons };
}

async function generarSeccionInformeIA(target, tool, findings) {
  if (!findings.length) {
    return `## ${tool}\n\nNo se identificaron hallazgos relevantes para esta herramienta.\n`;
  }

  const prompt = `
Redacta en espanol una seccion profesional de informe de pentesting para la herramienta ${tool}.
No inventes hallazgos. Usa exclusivamente los findings recibidos.
Incluye descripcion tecnica, evidencia, impacto y recomendacion.
No uses Markdown de tabla.

Objetivo: ${target}
Findings:
${JSON.stringify(findings, null, 2)}
`;

  return generarRespuestaIA(prompt);
}

function debeRevisarIA(endpoint) {
  if (endpoint.evidencias?.sqli?.confirmado) return true;
  if (endpoint.evidencias?.xss?.confirmado) return true;
  if ((endpoint.evidencias?.nuclei || []).length > 0) return true;
  if (endpoint.tieneParametros) return true;
  return ['login', 'admin', 'formulario', 'api-docs'].includes(endpoint.categoria);
}

function filtrarEndpointsParaIA(endpoints) {
  return endpoints.filter(debeRevisarIA);
}

function clavePatron(endpoint) {
  const endpointPath = endpoint.path || '';
  const params = endpoint.parametros || [];
  if (params.length === 0) return endpointPath;
  return `${endpointPath}?${params.slice().sort().join('&')}`;
}

function agruparEndpoints(endpoints) {
  const mapa = new Map();

  endpoints.forEach(endpoint => {
    const clave = clavePatron(endpoint);

    if (!mapa.has(clave)) {
      mapa.set(clave, {
        patron: clave,
        ejemplo: endpoint.url,
        categoria: endpoint.categoria,
        parametros: endpoint.parametros,
        evidencias: endpoint.evidencias
      });
    }
  });

  return Array.from(mapa.values());
}

async function analizarEndpointsIA(datosAnalisis) {
  return generarRespuestaIA(JSON.stringify(datosAnalisis, null, 2));
}

module.exports = {
  aplicarImpactosIA,
  buildCompactFindingForAI,
  buildCompactAIPromptForFinding,
  buildMinimalPromptForFinding,
  buildMinimalRetryPrompt,
  checkOllamaHealth,
  createIndividualAiFallback,
  generarRespuestaIA,
  generarJsonIA,
  getAiRuntimeConfig,
  enrichSingleFindingWithAI,
  enriquecerFindingIndividual,
  isGenericImpact,
  isGenericAIText,
  normalizeMinimalAIResponse,
  repairAITextResponse,
  validateMinimalAIEnrichment,
  validateAITextLanguage,
  validateAITextSpecificity,
  validateSingleAIResult,
  validateCvssLikeAIResult,
  validateAIEnrichmentResult,
  validateAISeverityDecision,
  generarSeccionInformeIA,
  analizarEndpointsIA,
  filtrarEndpointsParaIA,
  agruparEndpoints,
  postJsonSinTimeout,
  promptImpactoRecomendacionIndividual,
  resolveAiTimeoutMs
};
