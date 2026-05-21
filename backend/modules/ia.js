const path = require('path');
const http = require('http');
const https = require('https');
require('dotenv').config({ path: path.join(__dirname, '..', '.env'), override: true });

const {
  extraerFindingsDesdeRespuestaIA,
  normalizarFindings,
  parsearJsonIAFlexible
} = require('./normalizacion');

const MODEL = process.env.OLLAMA_MODEL || 'llama3';
const OLLAMA_REINTENTOS = 3;
const INTENTOS_ENRIQUECIMIENTO_IA = Number(process.env.IA_INTENTOS_ENRIQUECIMIENTO || 3);
const OLLAMA_TIMEOUT_MS = Number(process.env.OLLAMA_TIMEOUT_MS || 0);

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

function esperar(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function detalleErrorFetch(error) {
  return [
    error.message,
    error.cause?.code,
    error.cause?.message
  ].filter(Boolean).join(' - ');
}

async function llamarOllama(body, intentos = OLLAMA_REINTENTOS) {
  let ultimoError = null;

  for (let intento = 1; intento <= intentos; intento++) {
    try {
      return await postJsonSinTimeout(OLLAMA_URL, body);
    } catch (error) {
      ultimoError = error;
      console.error(`Intento ${intento}/${intentos} fallido contra Ollama (${OLLAMA_URL}):`, detalleErrorFetch(error));

      if (intento < intentos) {
        await esperar(1500 * intento);
      }
    }
  }

  throw new Error(`No se pudo conectar con Ollama tras ${intentos} intentos: ${detalleErrorFetch(ultimoError)}`);
}

function postJsonSinTimeout(url, body) {
  return new Promise((resolve, reject) => {
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

    if (OLLAMA_TIMEOUT_MS > 0) {
      requestOptions.timeout = OLLAMA_TIMEOUT_MS;
    }

    const req = client.request(
      requestOptions,
      res => {
        const chunks = [];

        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => {
          const texto = Buffer.concat(chunks).toString('utf8');

          if (res.statusCode < 200 || res.statusCode >= 300) {
            reject(new Error(`Error de Ollama: ${res.statusCode}${texto ? ` - ${texto.slice(0, 300)}` : ''}`));
            return;
          }

          try {
            resolve(JSON.parse(texto));
          } catch (error) {
            reject(new Error(`Ollama no devolvio JSON HTTP valido: ${error.message}`));
          }
        });
      }
    );

    if (OLLAMA_TIMEOUT_MS > 0) {
      req.setTimeout(OLLAMA_TIMEOUT_MS, () => req.destroy(new Error('timeout conectando con Ollama')));
    } else {
      req.setTimeout(0);
    }
    req.on('error', reject);
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
    throw new Error(`Fallo al conectar con la IA: ${error.message}`);
  }
}

async function generarJsonIA(prompt) {
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
No inventes hallazgos, CVE, CVSS ni CWE sin evidencia.
`,
      options: {
        temperature: 0,
        num_predict: 1600,
        num_ctx: 4096,
        num_thread: 2
      }
    });

    return data.response || '';
  } catch (error) {
    throw new Error(`Fallo al conectar con la IA: ${error.message}`);
  }
}

function limitarTexto(texto = '', max = 2500) {
  const limpio = String(texto || '').trim();

  if (limpio.length <= max) return limpio;

  return `${limpio.slice(0, max)}\n\n[Salida truncada: ${limpio.length - max} caracteres omitidos]`;
}

function promptHerramienta(tool, target, payload) {
  return `Devuelve SOLO JSON valido con esta forma: {"findings":[{"titulo":"","criticidad":"info|baja|media|alta|critica","confianza":"baja|media|alta","es_vulnerabilidad":true,"posible_falso_positivo":false,"motivo_falso_positivo":"","impacto":"","recomendacion":"","evidencia_resumida":""}]}.
Si no hay vulnerabilidades reales, devuelve {"findings":[]}.
No conviertas fingerprints, WAF detect, wildcard DNS o tecnologias detectadas en vulnerabilidades.
Objetivo: ${target}. Herramienta: ${tool}.
Datos:
${limitarTexto(JSON.stringify(payload))}`;
}

async function analizarHerramientaIA(tool, target, toolResult) {
  if (!toolResult || toolResult.status === 'skipped') return [];

  const payload = {
    status: toolResult.status,
    parsed: Array.isArray(toolResult.parsed) ? toolResult.parsed.slice(0, 20) : toolResult.parsed,
    raw: limitarTexto(toolResult.raw || '', 1200),
    error: toolResult.error || null
  };

  const respuesta = await generarJsonIA(promptHerramienta(tool, target, payload));
  return extraerFindingsDesdeRespuestaIA(respuesta, tool, target);
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

function compactarFindingParaIA(finding) {
  return {
    id: finding.id,
    tool: finding.tool,
    type: finding.type,
    title: finding.title,
    description: finding.description,
    severity: finding.severity,
    confidence: finding.confidence,
    isVulnerability: finding.isVulnerability,
    isFalsePositiveLikely: finding.isFalsePositiveLikely,
    falsePositiveReason: finding.falsePositiveReason,
    cwe: finding.cwe,
    affected_asset: finding.affected_asset,
    affected_url: finding.affected_url,
    evidence: limitarTexto(finding.evidence, 700),
    raw_reference: limitarTexto(finding.raw_reference, 500)
  };
}

function promptImpactoRecomendacion(target, tool, findings) {
  return `Analiza individualmente cada vulnerabilidad y devuelve SOLO JSON valido.
No agrupes hallazgos. No uses una recomendacion generica repetida para todos.
Devuelve exactamente este formato: {"items":[{"id":"","impact":"","recommendation":""}]}.
Debe haber un item por cada id recibido.
Conserva el id exacto.
El campo impact debe explicar el impacto concreto de esa evidencia, parametro, URL o servicio.
El campo recommendation debe explicar como solucionarlo en ese caso concreto.
Cada impact y recommendation debe mencionar algun dato concreto del hallazgo: parametro, ruta, payload, servicio o URL.
Si no puedes determinar impact o recommendation para un id, devuelve ese campo como cadena vacia.
No inventes CVE, CVSS, CWE ni datos no presentes.
Objetivo: ${target}
Herramienta: ${tool}
Vulnerabilidades:
${limitarTexto(JSON.stringify(findings), 3200)}`;
}

function promptImpactoRecomendacionIndividual(target, tool, finding) {
  return `Analiza SOLO esta vulnerabilidad concreta.
Devuelve SOLO JSON valido con este formato exacto:
{
  "titulo": "",
  "criticidad": "info|baja|media|alta|critica",
  "confianza": "baja|media|alta",
  "es_vulnerabilidad": true,
  "posible_falso_positivo": false,
  "motivo_falso_positivo": "",
  "impacto": "",
  "recomendacion": "",
  "evidencia_resumida": ""
}

Reglas obligatorias:
- No conviertas fingerprints, WAF detect, wildcard DNS o tecnologias detectadas en vulnerabilidades.
- Si el hallazgo recibido no es una vulnerabilidad, es_vulnerabilidad debe ser false y criticidad debe ser info.
- impacto debe explicar el impacto de ESTE caso, no de la vulnerabilidad en general.
- recomendacion debe explicar la correccion de ESTE caso, no una recomendacion generica.
- impacto y recomendacion deben mencionar datos concretos presentes en el hallazgo: URL, ruta, parametro, payload, servicio o evidencia.
- Si hay parametro, mencionalo por nombre.
- Si hay payload, menciona el tipo de payload o contexto donde se refleja.
- No dejes impacto ni recomendacion vacios si es_vulnerabilidad es true.
- Si la evidencia es limitada, redacta una valoracion prudente basada solo en lo observado.
- No inventes CVE, CVSS, CWE ni datos no presentes.

Objetivo: ${target}
Herramienta: ${tool}
Hallazgo:
${JSON.stringify(finding, null, 2)}`;
}

function extraerItemsImpacto(texto) {
  const parsed = parsearJsonIAFlexible(texto);

  if (Array.isArray(parsed)) return parsed;

  if (parsed && typeof parsed === 'object' && (
    parsed.impacto ||
    parsed.recomendacion ||
    parsed.es_vulnerabilidad !== undefined ||
    parsed.titulo
  )) {
    return [parsed];
  }

  const items = parsed.items ||
    parsed.findings ||
    parsed.hallazgos ||
    parsed.results ||
    parsed.resultados ||
    parsed.vulnerabilities ||
    parsed.vulnerabilidades;

  if (Array.isArray(items)) return items;
  if (items && typeof items === 'object') return [items];
  if (parsed && typeof parsed === 'object' && (parsed.id || parsed.impact || parsed.recommendation)) return [parsed];

  return [];
}

function tokensConcretosFinding(finding) {
  const tokens = new Set();

  function add(valor) {
    const limpio = String(valor || '')
      .toLowerCase()
      .replace(/https?:\/\//g, '')
      .replace(/[^a-z0-9_./:-]+/g, ' ')
      .split(/\s+/)
      .map(token => token.trim())
      .filter(token => token.length >= 4 && token.length <= 80);

    limpio.forEach(token => tokens.add(token));
  }

  add(finding.affected_url);
  add(finding.affected_asset);
  add(finding.cwe);

  try {
    const url = new URL(finding.affected_url);
    add(url.pathname);
    Array.from(url.searchParams.keys()).forEach(add);
  } catch {
    // La URL puede ser nula o parcial.
  }

  const evidencia = String(finding.evidence || '');
  const payloadMatch = evidencia.match(/payloads? observados?:([\s\S]*?)(\n[A-Z]|$)/i) ||
    evidencia.match(/payload:\s*([^\n]+)/i);
  if (payloadMatch) add(payloadMatch[1]);

  return Array.from(tokens);
}

function esTextoConcreto(finding, texto) {
  const limpio = limpiarCampoIA(texto).toLowerCase();
  if (!limpio) return false;

  const tokens = tokensConcretosFinding(finding);
  if (!tokens.length) return true;

  return tokens.some(token => limpio.includes(token));
}

function aplicarImpactosIA(findings, itemsIA) {
  const mapa = new Map();

  itemsIA.forEach((item, index) => {
    const id = limpiarCampoIA(item.id) || findings[index]?.id;
    if (!id) return;

    mapa.set(id, {
      title: limpiarCampoIA(item.title || item.titulo),
      impact: limpiarCampoIA(item.impact || item.impacto),
      recommendation: limpiarCampoIA(item.recommendation || item.recomendacion),
      evidence: limpiarCampoIA(item.evidencia_resumida),
      isVulnerability: typeof item.es_vulnerabilidad === 'boolean' ? item.es_vulnerabilidad : undefined,
      isFalsePositiveLikely: typeof item.posible_falso_positivo === 'boolean' ? item.posible_falso_positivo : undefined,
      falsePositiveReason: limpiarCampoIA(item.motivo_falso_positivo)
    });
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

    return {
      ...finding,
      title: finding.title,
      impact: enriquecido.impact,
      recommendation: enriquecido.recommendation,
      evidence: enriquecido.evidence || finding.evidence,
      isVulnerability: enriquecido.isVulnerability ?? finding.isVulnerability,
      isFalsePositiveLikely: enriquecido.isFalsePositiveLikely ?? finding.isFalsePositiveLikely,
      falsePositiveReason: enriquecido.falsePositiveReason || finding.falsePositiveReason
    };
  });
}

function fallbackTecnico(finding) {
  const tipo = String(finding.type || finding.tool || '').toLowerCase();
  const titulo = String(finding.title || '').toLowerCase();

  if (tipo.includes('xss') || titulo.includes('xss')) {
    return {
      impact: 'Puede permitir ejecucion de JavaScript en el navegador de la victima dentro del contexto del sitio.',
      recommendation: 'Escapar la salida HTML, validar entradas y aplicar una Content Security Policy restrictiva.'
    };
  }

  if (tipo.includes('sqli') || titulo.includes('sql injection')) {
    return {
      impact: 'Puede permitir consultar o modificar datos mediante manipulacion de parametros enviados a la base de datos.',
      recommendation: 'Usar consultas parametrizadas, validar tipos de entrada y limitar privilegios de la cuenta de base de datos.'
    };
  }

  if (tipo.includes('secret') || titulo.includes('secreto')) {
    return {
      impact: 'La exposicion de secretos puede permitir acceso no autorizado a servicios, APIs o datos internos.',
      recommendation: 'Revocar y rotar el secreto afectado, retirarlo del recurso publico y moverlo a un almacen seguro.'
    };
  }

  return {
    impact: finding.impact || 'Requiere revision tecnica para valorar el impacto real con la evidencia disponible.',
    recommendation: finding.recommendation || 'Revisar el endpoint o recurso indicado, validar su necesidad de exposicion y aplicar controles de acceso si procede.'
  };
}

function normalizarComparacion(texto) {
  return limpiarCampoIA(texto)
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

async function enriquecerFindingIndividual(target, tool, finding) {
  for (let intento = 1; intento <= INTENTOS_ENRIQUECIMIENTO_IA; intento++) {
    const respuesta = await generarJsonIA(
      promptImpactoRecomendacionIndividual(target, tool, compactarFindingParaIA(finding))
    );
    const items = extraerItemsImpacto(respuesta);
    const enriquecido = aplicarImpactosIA([finding], items)[0];

    if (enriquecido.impact && enriquecido.recommendation) {
      return enriquecido;
    }
  }

  return finding;
}

async function enriquecerFindingsIA(target, tool, findings) {
  const base = normalizarFindings(findings, tool, target)
    .map(finding => ({
      ...finding,
      impact: '',
      recommendation: ''
    }));

  if (!base.length) return [];

  const enriquecidos = [];

  for (const finding of base) {
    try {
      enriquecidos.push(await enriquecerFindingIndividual(target, tool, finding));
    } catch (error) {
      console.error(`IA no pudo completar ${tool}/${finding.id}:`, error.message);
      const fallback = fallbackTecnico(finding);
      enriquecidos.push({
        ...finding,
        impact: finding.impact || fallback.impact,
        recommendation: finding.recommendation || fallback.recommendation,
        ai_status: 'failed',
        ai_error: 'No se pudo conectar con Ollama'
      });
    }
  }

  return normalizarFindings(enriquecidos, tool, target);
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
  generarRespuestaIA,
  generarJsonIA,
  analizarHerramientaIA,
  enriquecerFindingsIA,
  generarSeccionInformeIA,
  analizarEndpointsIA,
  filtrarEndpointsParaIA,
  agruparEndpoints
};
