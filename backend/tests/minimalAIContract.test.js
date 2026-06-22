const assert = require('assert');
const { PassThrough } = require('stream');
const {
  aplicarImpactosIA,
  buildCompactFindingForAI,
  buildMinimalPromptForFinding,
  buildMinimalRetryPrompt,
  enrichSingleFindingWithAI,
  enriquecerFindingIndividual,
  normalizeMinimalAIResponse,
  repairAITextResponse,
  validateAITextLanguage,
  validateMinimalAIEnrichment
} = require('../modules/ia/ia');
const {
  buildFinalRiskPrompt,
  computeFinalRiskScoreWithAI,
  enrichAllReportableFindingsWithAI,
  validateAIEnrichmentCoverage
} = require('../modules/ia/aiMandatoryPipeline');
const { generarPdfAuditoria } = require('../modules/pdf/pdfGenerator');
const { extraerFindingsDeterministas } = require('../modules/procesamiento/extractores');
const { normalizeFindingsForReporting } = require('../modules/priorizacion/findingGroups');

function finding(overrides = {}) {
  const status = overrides.finalStatus || 'candidate';
  return {
    id: overrides.id || 'gf-rce-minimal',
    tool: overrides.tool || 'gf',
    type: overrides.type || 'gf_candidate',
    family: overrides.family || 'rce',
    vulnerability_type: overrides.vulnerability_type || overrides.family || 'rce',
    title: overrides.title || 'Candidato RCE por GF',
    technicalStatus: status,
    finalStatus: status,
    baseSeverity: overrides.baseSeverity || 'critical',
    finalSeverity: overrides.finalSeverity || 'critical',
    severity: overrides.severity || 'critical',
    confidence: overrides.confidence || 'low',
    affected_url: overrides.affected_url || 'https://example.test/survey_questions.jsp?step=1',
    parameter: overrides.parameter || 'step',
    evidence: overrides.evidence || 'GF detecto el patron rce en el parametro step; no existe ejecucion confirmada.',
    ...overrides
  };
}

const minimalRce = {
  status: 'candidate',
  severity: 'critical',
  probability: '15%',
  impact: 'GF detecto el parametro step en /survey_questions.jsp como posible RCE, pero no hay ejecucion de comandos confirmada.',
  recommendation: 'Revisar si step llega a llamadas de sistema y aplicar allowlist estricta para el vector RCE.',
  confidence: 'low'
};

async function testMinimalResponseIsEnough() {
  const original = finding();
  const normalized = normalizeMinimalAIResponse(`texto previo\n\`\`\`json\n${JSON.stringify(minimalRce)}\n\`\`\`\ntexto posterior`, original);
  const validation = validateMinimalAIEnrichment(normalized, original);
  assert.strictEqual(validation.ok, true, validation.reason);
  assert.strictEqual(normalized.probability, 15);
  assert.deepStrictEqual(normalized._normalization.missingOptional.sort(), ['reason', 'remediation', 'validation']);

  const enriched = aplicarImpactosIA([original], [normalized])[0];
  assert.strictEqual(enriched.finalStatus, 'candidate');
  assert.strictEqual(enriched.finalSeverity, 'critical');
  assert.strictEqual(enriched.realVulnerabilityProbabilityPercent, 15);
  assert.strictEqual(enriched.technicalImpact, minimalRce.impact);
  assert.ok(enriched.businessImpact);
  assert.ok(enriched.severityReason);
  assert.ok(enriched.probabilityReason);
  assert.ok(enriched.validationSteps.length > 0);
  assert.ok(enriched.remediationSteps.length > 0);

  const processed = await enriquecerFindingIndividual('https://example.test', 'gf', original, null, {
    generateJson: async () => JSON.stringify(minimalRce)
  });
  assert.strictEqual(processed.aiProcessed, true);
  assert.strictEqual(processed.impactSource, 'ai');
  assert.strictEqual(processed.recommendationSource, 'ai');
}

function testAliasesAndCompactFinding() {
  const original = finding({ id: 'alias' });
  const normalized = normalizeMinimalAIResponse({
    finalStatus: 'candidate',
    aiSuggestedSeverity: 'critical',
    probabilityFinal: '12%',
    technicalImpact: minimalRce.impact,
    solution: minimalRce.recommendation,
    confidence: 'LOW'
  }, original);
  assert.strictEqual(normalized.severity, 'critical');
  assert.strictEqual(normalized.probability, 12);
  assert.strictEqual(validateMinimalAIEnrichment(normalized, original).ok, true);

  const spanishKeys = normalizeMinimalAIResponse({
    Impacto: minimalRce.impact,
    Recomendación: minimalRce.recommendation
  }, original);
  assert.strictEqual(validateMinimalAIEnrichment(spanishKeys, original).ok, true);
  assert.deepStrictEqual(spanishKeys.guardrailFilledFields.sort(), ['confidence', 'probability', 'severity', 'status']);

  const compact = buildCompactFindingForAI({
    ...original,
    evidence: 'x'.repeat(1200),
    correlation_notes: ['a', 'b', 'c', 'd']
  });
  assert.ok(compact.evidence.length <= 800);
  assert.strictEqual(compact.correlations.length, 3);
  assert.deepStrictEqual(Object.keys(compact), [
    'id', 'tool', 'displayTool', 'sourceTools', 'type', 'family', 'currentStatus', 'currentSeverity', 'endpoint', 'parameter',
    'payload', 'evidence', 'evidenceStrength', 'isConfirmed', 'isGF', 'isHardening', 'isSurface',
    'probabilityBase', 'correlations'
  ]);
}

function testHardeningAllowsNullProbability() {
  const original = finding({
    id: 'cookie', tool: 'cookies', type: 'hardening', family: 'cookie',
    finalStatus: 'hardening', finalSeverity: 'medium', severity: 'medium',
    affected_url: 'https://example.test/login', parameter: null,
    evidence: 'Cookie JSESSIONID con Secure y HttpOnly presentes; SameSite ausente.'
  });
  const normalized = normalizeMinimalAIResponse({
    status: 'hardening', severity: 'medium', probability: null,
    impact: 'Cookies observo en /login que JSESSIONID carece de SameSite, aunque Secure y HttpOnly estan presentes como controles defensivos.',
    recommendation: 'En /login, configurar SameSite=Lax o Strict para JSESSIONID y mantener Secure y HttpOnly en la cookie.',
    confidence: 'high'
  }, original);
  assert.strictEqual(normalized.probability, null);
  assert.strictEqual(validateMinimalAIEnrichment(normalized, original).ok, true);
}

async function testMissingImpactTriggersRetryContract() {
  const original = finding({ id: 'missing-impact' });
  const normalized = normalizeMinimalAIResponse({ ...minimalRce, impact: '' }, original);
  const validation = validateMinimalAIEnrichment(normalized, original);
  assert.strictEqual(validation.ok, false);
  assert.ok(validation.reasons.includes('missing_impact'));
  const retry = buildMinimalRetryPrompt(buildCompactFindingForAI(original));
  assert.match(retry, /impact o recommendation eran insuficientes/);
  assert.match(retry, /"impact"/);
  assert.doesNotMatch(retry, /severityReason|validationSteps|remediationSteps/);

  let calls = 0;
  const pending = await enriquecerFindingIndividual('https://example.test', 'gf', original, null, {
    generateJson: async () => {
      calls += 1;
      return JSON.stringify({ ...minimalRce, impact: '' });
    }
  });
  assert.strictEqual(calls, 2);
  assert.strictEqual(pending.aiProcessed, false);
  assert.strictEqual(pending.impactSource, 'pending_ai');
  assert.strictEqual(pending.recommendationSource, 'pending_ai');
}

async function testImpactAndRecommendationAreTheOnlyRequiredAiFields() {
  const original = finding({ id: 'short-fields-guardrail' });
  const textOnlyFields = {
    impact: 'GF observo en /survey_questions.jsp el parametro step asociado a un patron RCE, pero no existe evidencia de ejecucion de comandos.',
    recommendation: 'Validar manualmente si step alcanza llamadas al sistema y aplicar una allowlist estricta antes de usar el valor en operaciones sensibles.'
  };
  const normalized = normalizeMinimalAIResponse(textOnlyFields, original);
  assert.strictEqual(validateMinimalAIEnrichment(normalized, original).ok, true);
  assert.deepStrictEqual(normalized.guardrailFilledFields.sort(), ['confidence', 'probability', 'severity', 'status']);
  assert.strictEqual(normalized.status, 'candidate');
  assert.strictEqual(normalized.severity, 'critical');
  assert.strictEqual(normalized.probability, 15);
  assert.strictEqual(normalized.confidence, 'low');

  const processed = await enriquecerFindingIndividual('https://example.test', 'gf', original, null, {
    generateJson: async () => JSON.stringify(textOnlyFields)
  });
  assert.strictEqual(processed.aiProcessed, true);
  assert.strictEqual(processed.impactSource, 'ai');
  assert.strictEqual(processed.recommendationSource, 'ai');
  assert.deepStrictEqual(processed.guardrailFilledFields.sort(), ['confidence', 'probability', 'severity', 'status']);
  assert.strictEqual(processed.aiProvidedStatus, false);
  assert.strictEqual(processed.aiProvidedImpact, true);
}

async function testPlainTextResponseIsRepaired() {
  const original = finding({ id: 'plain-text-repair' });
  const raw = `Impacto: GF detecto el parametro step en /survey_questions.jsp como candidato RCE, aunque no existe ejecucion de comandos confirmada.\nRecomendacion: Validar si step llega a llamadas de sistema con una prueba controlada y aplicar una allowlist estricta antes de procesarlo.`;
  const repaired = repairAITextResponse(raw, original);
  assert.ok(repaired);
  assert.strictEqual(repaired._repaired, true);
  assert.strictEqual(validateMinimalAIEnrichment(repaired, original).ok, true);

  const processed = await enriquecerFindingIndividual('https://example.test', 'gf', original, null, {
    generateJson: async () => raw
  });
  assert.strictEqual(processed.aiProcessed, true);
  assert.strictEqual(processed.impactSource, 'ai_repaired');
  assert.strictEqual(processed.recommendationSource, 'ai_repaired');
  assert.strictEqual(validateAIEnrichmentCoverage([processed]).coveragePercent, 100);
  const pipelineResult = await enrichAllReportableFindingsWithAI([original], {
    enrichFinding: async () => processed
  });
  assert.strictEqual(pipelineResult.coverage.complete, true);
  assert.strictEqual(pipelineResult.findings[0].impactSource, 'ai_repaired');
  assert.strictEqual(pipelineResult.findings[0].recommendationSource, 'ai_repaired');

  const paragraphs = repairAITextResponse(
    'GF identifico el parametro step en /survey_questions.jsp como patron RCE candidato, sin evidencia de ejecucion de comandos confirmada.\n\nValidar step mediante una prueba controlada y aplicar una allowlist estricta antes de permitir que alcance llamadas del sistema.',
    original
  );
  assert.ok(paragraphs);
  assert.strictEqual(paragraphs._repairMethod, 'two_paragraphs');

  const numbered = repairAITextResponse(
    '1. Impacto GF detecto step en /survey_questions.jsp como posible RCE, pero no existe ejecucion de comandos confirmada con la evidencia actual.\n2. Recomendacion Validar step de forma controlada y aplicar una allowlist estricta antes de cualquier llamada al sistema.',
    original
  );
  assert.ok(numbered);
  assert.strictEqual(validateMinimalAIEnrichment(numbered, original).ok, true);
}

async function testRetryCanRecoverMissingImpactAndRecommendation() {
  const original = finding({
    id: 'sqlmap-retry', tool: 'sqlmap', family: 'sqli', vulnerability_type: 'sqli',
    finalStatus: 'possible', technicalStatus: 'possible', finalSeverity: 'high', severity: 'high',
    evidence: 'SQLMap encontro indicios de inyeccion, sin payload estable, DBMS ni extraccion confirmada.'
  });
  let calls = 0;
  const processed = await enriquecerFindingIndividual('https://example.test', 'sqlmap', original, null, {
    generateJson: async () => {
      calls += 1;
      if (calls === 1) return JSON.stringify({ status: 'possible', severity: 'high', probability: 35, confidence: 'medium' });
      return 'Impacto: SQLMap encontro indicios SQLi en /survey_questions.jsp sobre step, pero no confirmo payload, DBMS ni extraccion de datos.\nRecomendacion: Repetir la validacion controlada de step y parametrizar cualquier consulta SQL que reciba ese valor, registrando la respuesta del servidor.';
    }
  });
  assert.strictEqual(calls, 2);
  assert.strictEqual(processed.aiProcessed, true);
  assert.strictEqual(processed.finalStatus, 'possible');
  assert.strictEqual(processed.impactSource, 'ai_repaired');
}

function testPromptPrioritizesLongFieldsAndAddsTypeGuidance() {
  const compact = buildCompactFindingForAI(finding());
  const prompt = buildMinimalPromptForFinding(compact);
  assert.ok(prompt.indexOf('"impact"') < prompt.indexOf('"recommendation"'));
  assert.ok(prompt.indexOf('"recommendation"') < prompt.indexOf('"severity"'));
  assert.match(prompt, /tarea principal es redactar/i);
  assert.match(prompt, /GF solo detecta un patron/i);
  assert.match(prompt, /impact nunca puede estar vacio/i);
}

async function testInformationalBannerAndSurfacePortStayObservations() {
  const banner = finding({
    id: 'headers-banner-server', tool: 'headers', type: 'server_banner', family: 'technology',
    finalStatus: 'informational', technicalStatus: 'informational', finalSeverity: 'info', severity: 'info',
    parameter: null, affected_url: 'https://demo.testfire.net/', evidence: 'Cabecera Server: Apache-Coyote/1.1'
  });
  const bannerResult = await enriquecerFindingIndividual('https://demo.testfire.net', 'headers', banner, null, {
    generateJson: async () => JSON.stringify({
      impact: 'El endpoint https://demo.testfire.net/ expone el banner Apache-Coyote/1.1, revelando tecnologia Tomcat/Java util para reconocimiento. No confirma una vulnerabilidad explotable.',
      recommendation: 'Reducir o normalizar el banner Server y mantener actualizado el stack Tomcat/Java. Verificar que no haya versiones vulnerables ni endpoints administrativos publicos.'
    })
  });
  assert.strictEqual(bannerResult.aiProcessed, true);
  assert.strictEqual(bannerResult.finalStatus, 'informational');
  assert.strictEqual(bannerResult.isVulnerability, false);

  const port = finding({
    id: 'ports-open-443', tool: 'ports', type: 'open_port', family: 'service',
    finalStatus: 'surface', technicalStatus: 'surface', finalSeverity: 'low', severity: 'low',
    parameter: null, affected_url: 'demo.testfire.net:443', evidence: 'Puerto TCP 443 abierto con servicio HTTPS.'
  });
  const portResult = await enriquecerFindingIndividual('demo.testfire.net', 'ports', port, null, {
    generateJson: async () => JSON.stringify({
      impact: 'El puerto 443 de demo.testfire.net esta abierto y expone el servicio HTTPS principal. No es una vulnerabilidad por si mismo, sino parte de la superficie publica.',
      recommendation: 'Mantener HTTPS y TLS actualizados, revisar las cabeceras de seguridad y confirmar que solo se exponen servicios necesarios en demo.testfire.net:443.'
    })
  });
  assert.strictEqual(portResult.aiProcessed, true);
  assert.strictEqual(portResult.finalStatus, 'surface');
  assert.strictEqual(portResult.realVulnerabilityProbabilityPercent, null);
  assert.strictEqual(portResult.isVulnerability, false);
}

async function testGfXssRemainsCandidate() {
  const original = finding({
    id: 'gf-xss', family: 'xss', vulnerability_type: 'xss', baseSeverity: 'medium', finalSeverity: 'medium', severity: 'medium',
    evidence: 'GF detecto un patron XSS en el parametro q sin ejecutar ningun payload.'
  });
  const processed = await enriquecerFindingIndividual('https://example.test', 'gf', original, null, {
    generateJson: async () => JSON.stringify({
      impact: 'GF detecto en /survey_questions.jsp el parametro step con patron XSS, pero no existe payload ejecutado ni JavaScript confirmado en el navegador.',
      recommendation: 'Validar step con un payload inocuo y aplicar escape contextual segun HTML, atributo o JavaScript antes de reflejar cualquier entrada.'
    })
  });
  assert.strictEqual(processed.finalStatus, 'candidate');
  assert.ok(['medium', 'high'].includes(processed.finalSeverity));
  assert.ok(processed.realVulnerabilityProbabilityPercent >= 10 && processed.realVulnerabilityProbabilityPercent <= 30);
  assert.strictEqual(processed.aiProcessed, true);
}

async function testLog95FeroxbusterSurfaceRetriesInSpanish() {
  const original = finding({
    id: 'feroxbuster-surface-1', tool: 'feroxbuster', type: 'attack_surface', family: 'attack_surface',
    finalStatus: 'surface', technicalStatus: 'surface', baseSeverity: 'low', finalSeverity: 'low', severity: 'low',
    parameter: null, affected_url: 'https://demo.testfire.net/swagger/index.html',
    evidence: 'URL: https://demo.testfire.net/swagger/index.html; Status: 200; Content-Length: 1488'
  });
  const prompts = [];
  let calls = 0;
  const processed = await enriquecerFindingIndividual('https://demo.testfire.net', 'feroxbuster', original, null, {
    generateJson: async prompt => {
      prompts.push(prompt);
      calls += 1;
      if (calls === 1) return JSON.stringify({
        impact: 'The exposed attack surface may allow an attacker to access sensitive information or perform unauthorized actions.',
        recommendation: 'To mitigate this risk, the endpoint should be restricted to authorized users and reviewed regularly.'
      });
      return JSON.stringify({
        impact: 'Feroxbuster descubrio la ruta /swagger/index.html como parte de la superficie publica de demo.testfire.net. No confirma una vulnerabilidad, pero facilita reconocimiento de recursos accesibles.',
        recommendation: 'Verificar si la ruta detectada por Feroxbuster debe permanecer publica. Si no es necesaria, restringirla con autenticacion o filtrado de red, eliminar el recurso y documentar si es una ruta esperada.'
      });
    }
  });
  assert.strictEqual(calls, 2);
  assert.match(prompts[1], /Para Feroxbuster/i);
  assert.strictEqual(processed.aiProcessed, true);
  assert.strictEqual(processed.finalStatus, 'surface');
  assert.strictEqual(processed.realVulnerabilityProbabilityPercent, null);
  assert.strictEqual(processed.impactSource, 'ai');
}

async function testLog95GfSsrfUsesSpecificRetryAndProbability() {
  const original = finding({
    id: 'gf-ssrf-5', family: 'ssrf', vulnerability_type: 'ssrf', baseSeverity: 'high', finalSeverity: 'high', severity: 'high',
    parameter: null, affected_url: 'https://demo.testfire.net/disclaimer.htm?url=http://www.netscape.com',
    evidence: 'Patron GF: ssrf; no existe callback externo ni request server-side confirmado.'
  });
  const prompts = [];
  let calls = 0;
  const processed = await enriquecerFindingIndividual('https://demo.testfire.net', 'gf', original, null, {
    generateJson: async prompt => {
      prompts.push(prompt);
      calls += 1;
      if (calls === 1) return JSON.stringify({
        impact: 'GF marco el endpoint /disclaimer.htm y el parametro url como candidato SSRF, pero no existe request server-side ni acceso interno confirmado.',
        recommendation: 'Realizar un analisis de codigo exhaustivo para identificar y corregir la vulnerabilidad.'
      });
      return JSON.stringify({
        impact: 'GF marco el parametro url de /disclaimer.htm como candidato SSRF; no hay callback externo, peticion server-side ni acceso a red interna confirmado. Si se confirma, podria alcanzar recursos internos.',
        recommendation: 'Validar url con un dominio controlado y, si genera peticiones salientes, aplicar allowlist de destinos, bloquear localhost, IP privadas y metadata cloud, rechazar esquemas no permitidos y limitar redirecciones.'
      });
    }
  });
  assert.strictEqual(calls, 2);
  assert.match(prompts[1], /Para SSRF/i);
  assert.strictEqual(processed.aiProcessed, true);
  assert.strictEqual(processed.finalStatus, 'candidate');
  assert.strictEqual(processed.finalSeverity, 'high');
  assert.ok(processed.realVulnerabilityProbabilityPercent >= 5 && processed.realVulnerabilityProbabilityPercent <= 25);
}

async function testLog95GfLfiCandidatesUseSpecificRetry() {
  const cases = [
    ['gf-lfi-7', 'https://demo.testfire.net/disclaimer.htm?url=http://www.netscape.com'],
    ['gf-lfi-9', 'https://demo.testfire.net/default.jsp?content=security.htm'],
    ['gf-lfi-11', 'https://demo.testfire.net/Privacypolicy.jsp?sec=Careers&template=US']
  ];
  for (const [id, endpoint] of cases) {
    const original = finding({
      id, family: 'lfi', vulnerability_type: 'lfi', baseSeverity: 'high', finalSeverity: 'high', severity: 'high',
      parameter: null, affected_url: endpoint, evidence: `Patron GF: lfi; URL: ${endpoint}; no existe lectura de archivos confirmada.`
    });
    const prompts = [];
    let calls = 0;
    const processed = await enriquecerFindingIndividual('https://demo.testfire.net', 'gf', original, null, {
      generateJson: async prompt => {
        prompts.push(prompt);
        calls += 1;
        if (calls === 1) return JSON.stringify({
          impact: `GF marco ${endpoint} como candidato LFI, sin lectura de archivos confirmada ni explotacion demostrada.`,
          recommendation: 'Realizar un analisis de codigo exhaustivo y aplicar medidas de autenticacion.'
        });
        return JSON.stringify({
          impact: `GF marco el parametro de ${endpoint} como candidato LFI; no hay lectura de archivos internos confirmada. Si resolviera rutas directamente, el impacto potencial seria alto.`,
          recommendation: 'Comprobar si el parametro resuelve archivos, sustituir rutas por identificadores logicos y una allowlist, normalizar la ruta y bloquear rutas absolutas, doble codificacion y secuencias ../ mediante pruebas controladas.'
        });
      }
    });
    assert.strictEqual(calls, 2, id);
    assert.match(prompts[1], /Para LFI/i);
    assert.strictEqual(processed.aiProcessed, true, id);
    assert.strictEqual(processed.finalStatus, 'candidate');
    assert.strictEqual(processed.finalSeverity, 'high');
    assert.ok(processed.realVulnerabilityProbabilityPercent >= 8 && processed.realVulnerabilityProbabilityPercent <= 25);
  }
}

async function testLanguageValidationRetriesAndCanRemainPending() {
  const original = finding({ id: 'language-retry' });
  const english = {
    impact: 'The discovery of this endpoint may allow an attacker to obtain sensitive information through unauthorized access.',
    recommendation: 'To mitigate this risk, it is recommended to restrict access and validate all input.'
  };
  assert.strictEqual(validateAITextLanguage(english).ok, false);
  let calls = 0;
  const recovered = await enriquecerFindingIndividual('https://example.test', 'gf', original, null, {
    generateJson: async () => {
      calls += 1;
      return calls === 1 ? JSON.stringify(english) : JSON.stringify({
        impact: 'GF marco el parametro step en /survey_questions.jsp como candidato RCE, aunque no existe ejecucion de comandos confirmada.',
        recommendation: 'Validar step con una prueba controlada y aplicar una allowlist estricta antes de permitir llamadas al sistema.'
      });
    }
  });
  assert.strictEqual(recovered.aiProcessed, true);
  assert.strictEqual(calls, 2);

  const pending = await enriquecerFindingIndividual('https://example.test', 'gf', { ...original, id: 'language-pending' }, null, {
    generateJson: async () => JSON.stringify(english)
  });
  assert.strictEqual(pending.aiProcessed, false);
  assert.match(pending.aiError, /language_not_spanish/);
}

function testSwaggerGauUsesCoherentToolMetadataAndSpanishEvidence() {
  const extracted = extraerFindingsDeterministas('gau', {
    parsed: [{
      url: 'https://demo.testfire.net/swagger/index.html', hasParams: false,
      source: 'gau:otx', sourceTool: 'gau'
    }]
  }, 'demo.testfire.net');
  assert.strictEqual(extracted.length, 1);
  assert.match(extracted[0].evidence, /descubiert[oa] por Gau/i);
  assert.doesNotMatch(extracted[0].evidence, /Katana/i);
  const normalized = normalizeFindingsForReporting(extracted)[0];
  assert.strictEqual(normalized.displayTool, 'Gau');
  assert.deepStrictEqual(normalized.sourceTools, ['gau']);

  const multi = normalizeFindingsForReporting([{
    ...extracted[0], id: 'multi-source', sourceTools: ['katana', 'gau'], displayTool: ''
  }])[0];
  assert.strictEqual(multi.displayTool, 'Katana/Gau');
}

function testRepairSupportsRiskAndSolutionLabels() {
  const original = finding({ id: 'risk-solution-repair' });
  const repaired = repairAITextResponse(
    'Riesgo: GF marco step en /survey_questions.jsp como candidato RCE, pero no hay ejecucion de comandos confirmada con la evidencia actual.\nSolucion: Validar step de forma controlada y aplicar una allowlist estricta antes de cualquier llamada al sistema.',
    original
  );
  assert.ok(repaired);
  assert.strictEqual(validateMinimalAIEnrichment(repaired, original).ok, true);
}

function aiResultFor(f) {
  const status = f.finalStatus;
  const severity = f.finalSeverity;
  const response = {
    status,
    severity,
    probability: ['hardening', 'surface', 'informational'].includes(status) ? null : 20,
    impact: `${f.tool} evaluo ${f.affected_url} y el parametro id para la familia ${f.family || f.vulnerability_type}; el estado es ${status} y no se asume evidencia adicional.`,
    recommendation: `En ${f.affected_url}, aplicar una allowlist al parametro id para ${f.family || f.vulnerability_type} y verificar el resultado con ${f.tool}.`,
    confidence: status === 'confirmed' ? 'high' : 'low'
  };
  const normalized = normalizeMinimalAIResponse(response, f);
  const validation = validateMinimalAIEnrichment(normalized, f);
  assert.strictEqual(validation.ok, true, `${f.id}: ${validation.reason}`);
  return {
    ...aplicarImpactosIA([f], [normalized])[0],
    aiProcessed: true,
    aiEnrichmentId: `ai-${f.id}`,
    aiModel: 'test-model',
    aiRawResponse: JSON.stringify(response),
    aiStatus: 'success',
    impactSource: 'ai',
    recommendationSource: 'ai',
    severitySource: 'ai_validated',
    probabilitySource: 'ai_validated',
    templateUsed: false,
    fallbackUsed: false
  };
}

async function testThirtyFiveMinimalResponsesReachFullCoverageAndPdf() {
  const statuses = ['confirmed', 'possible', 'candidate', 'hardening', 'surface', 'informational'];
  const findings = Array.from({ length: 35 }, (_, index) => {
    const status = statuses[index % statuses.length];
    const severity = status === 'confirmed' || status === 'possible' ? 'high' : status === 'surface' || status === 'informational' ? 'low' : 'medium';
    return finding({
      id: `minimal-${index}`, tool: status === 'candidate' ? 'gf' : status === 'hardening' ? 'headers' : status === 'surface' ? 'katana' : 'nuclei',
      type: status, family: status === 'candidate' ? 'xss' : 'configuration', vulnerability_type: status === 'candidate' ? 'xss' : 'configuration',
      finalStatus: status, technicalStatus: status, finalSeverity: severity, severity, baseSeverity: severity,
      affected_url: `https://example.test/path-${index}?id=1`, parameter: 'id'
    });
  });
  let calls = 0;
  const result = await enrichAllReportableFindingsWithAI(findings, {
    enrichFinding: async f => { calls += 1; return aiResultFor(f); }
  });
  const coverage = validateAIEnrichmentCoverage(result.findings);
  assert.strictEqual(calls, 35);
  assert.strictEqual(result.stats.aiCallsMade, 35);
  assert.strictEqual(coverage.aiProcessed, 35);
  assert.strictEqual(coverage.aiPersonalizedImpacts, 35);
  assert.strictEqual(coverage.aiPersonalizedRecommendations, 35);
  assert.strictEqual(coverage.templateUsedFinal, 0);
  assert.strictEqual(coverage.coveragePercent, 100);

  await new Promise((resolve, reject) => {
    const output = new PassThrough();
    output.setHeader = () => {};
    output.on('data', () => {});
    output.on('finish', resolve);
    output.on('error', reject);
    try {
      generarPdfAuditoria(output, 'example.test', result.findings, {
        risk_score: 75, risk_level: 'alto', risk_grade: 'D',
        finalScoreSource: 'ai_global_review', aiFinalScore100: 75,
        aiStats: result.stats, toolResults: {}, toolCounters: {}, correlations: [], pipelineTimeline: []
      });
    } catch (error) {
      reject(error);
    }
  });
}

async function testGlobalPromptUsesCompactMinimalSchema() {
  const xssFinding = finding({
    id: 'xss-confirmed', tool: 'dalfox', family: 'xss', vulnerability_type: 'xss',
    title: 'XSS confirmado', finalStatus: 'confirmed', technicalStatus: 'confirmed',
    finalSeverity: 'high', severity: 'high', baseSeverity: 'high'
  });
  const possibleFinding = finding({
    id: 'sqli-possible', tool: 'sqlmap', family: 'sqli', vulnerability_type: 'sqli',
    title: 'SQLi posible', finalStatus: 'possible', technicalStatus: 'possible',
    finalSeverity: 'high', severity: 'high', baseSeverity: 'high'
  });
  const candidateFinding = finding({ id: 'rce-candidate' });
  const enriched = [xssFinding, possibleFinding, candidateFinding].map(aiResultFor);
  const prompt = buildFinalRiskPrompt(enriched);
  assert.match(prompt, /"score":0/);
  assert.match(prompt, /"impactSummary"/);
  assert.doesNotMatch(prompt, /cvssVectorApprox|confirmedRiskSummary|manualValidationPriorities/);

  const risk = await computeFinalRiskScoreWithAI(enriched, {
    coverage: validateAIEnrichmentCoverage(enriched),
    generateJson: async () => JSON.stringify({
      score: 80,
      riskLevel: 'high',
      reason: 'El XSS confirmado domina el riesgo; SQLi y RCE aun requieren validacion.',
      mainDrivers: ['XSS confirmado'],
      whyNotHigher: 'No existe impacto critico confirmado.',
      whyNotLower: 'Existe una vulnerabilidad high confirmada.'
    })
  });
  assert.strictEqual(risk.risk_score, 80);
  assert.strictEqual(risk.aiFinalRiskLevel, 'high');
  assert.strictEqual(risk.finalScoreSource, 'ai_global_review');

  let languageCalls = 0;
  const translatedRisk = await computeFinalRiskScoreWithAI(enriched, {
    coverage: validateAIEnrichmentCoverage(enriched),
    generateJson: async () => {
      languageCalls += 1;
      return JSON.stringify(languageCalls === 1 ? {
        score: 80, riskLevel: 'high', reason: 'The discovery of these findings may allow an attacker to obtain unauthorized access.',
        mainDrivers: ['Confirmed XSS'], whyNotHigher: 'No critical issue.', whyNotLower: 'There is confirmed risk.'
      } : {
        score: 80, riskLevel: 'high', reason: 'El XSS confirmado domina el riesgo y los candidatos requieren validacion.',
        mainDrivers: ['XSS confirmado'], whyNotHigher: 'No existe impacto critico confirmado.', whyNotLower: 'Existe una vulnerabilidad alta confirmada.'
      });
    }
  });
  assert.strictEqual(languageCalls, 2);
  assert.strictEqual(translatedRisk.aiFinalScoreStatus, 'success');
  assert.match(translatedRisk.aiFinalScoreReason, /XSS confirmado/);
}

async function testThirtyOfThirtyFiveKeepsGlobalScorePending() {
  const findings = Array.from({ length: 35 }, (_, index) => finding({
    id: `partial-${index}`, family: 'xss', vulnerability_type: 'xss',
    baseSeverity: 'medium', finalSeverity: 'medium', severity: 'medium'
  }));
  const enriched = findings.map((item, index) => index < 30 ? aiResultFor(item) : {
    ...item,
    aiProcessed: false,
    aiStatus: 'failed',
    aiEnrichmentPending: true,
    impact: '', recommendation: '',
    impactSource: 'pending_ai', recommendationSource: 'pending_ai'
  });
  const coverage = validateAIEnrichmentCoverage(enriched);
  assert.strictEqual(coverage.aiProcessed, 30);
  assert.strictEqual(coverage.aiFailed, 5);
  assert.strictEqual(coverage.coveragePercent, 86);
  let globalCalls = 0;
  const risk = await computeFinalRiskScoreWithAI(enriched, {
    coverage,
    generateJson: async () => { globalCalls += 1; return '{}'; }
  });
  assert.strictEqual(globalCalls, 0);
  assert.strictEqual(risk.aiFinalScoreStatus, 'partial');
  assert.strictEqual(risk.finalScoreSource, 'pending_ai_global_review');
}

async function main() {
  await testMinimalResponseIsEnough();
  testAliasesAndCompactFinding();
  testHardeningAllowsNullProbability();
  await testMissingImpactTriggersRetryContract();
  await testImpactAndRecommendationAreTheOnlyRequiredAiFields();
  await testPlainTextResponseIsRepaired();
  await testRetryCanRecoverMissingImpactAndRecommendation();
  testPromptPrioritizesLongFieldsAndAddsTypeGuidance();
  await testInformationalBannerAndSurfacePortStayObservations();
  await testGfXssRemainsCandidate();
  await testLog95FeroxbusterSurfaceRetriesInSpanish();
  await testLog95GfSsrfUsesSpecificRetryAndProbability();
  await testLog95GfLfiCandidatesUseSpecificRetry();
  await testLanguageValidationRetriesAndCanRemainPending();
  testSwaggerGauUsesCoherentToolMetadataAndSpanishEvidence();
  testRepairSupportsRiskAndSolutionLabels();
  await testThirtyFiveMinimalResponsesReachFullCoverageAndPdf();
  await testGlobalPromptUsesCompactMinimalSchema();
  await testThirtyOfThirtyFiveKeepsGlobalScorePending();
  console.log('minimal AI contract tests passed');
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
