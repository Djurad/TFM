require('dotenv').config();

// Endpoint local de Ollama. El host se lee desde backend/.env.
const OLLAMA_URL = `http://${process.env.OLLAMA_HOST}:11434/api/generate`;

// Modelo usado para valorar los endpoints desde la IA local.
const MODEL = 'llama3';

// Decide si un endpoint merece una revisión adicional por IA.
// Se priorizan vulnerabilidades confirmadas, hallazgos de herramientas,
// endpoints parametrizados y rutas funcionalmente sensibles.
function debeRevisarIA(endpoint) {
  if (endpoint.evidencias?.sqli?.confirmado) return true;
  if (endpoint.evidencias?.xss?.confirmado) return true;
  if ((endpoint.evidencias?.nuclei || []).length > 0) return true;

  if (endpoint.tieneParametros) return true;

  if (['login', 'admin', 'formulario', 'api-docs'].includes(endpoint.categoria)) {
    return true;
  }

  return false;
}

// Reduce la lista total de endpoints a los que tienen más interés de seguridad.
function filtrarEndpointsParaIA(endpoints) {
  return endpoints.filter(debeRevisarIA);
}

// Crea una clave estable para agrupar endpoints con la misma ruta y parámetros.
function clavePatron(endpoint) {
  const path = endpoint.path || '';
  const params = endpoint.parametros || [];

  // Si no hay parámetros, el patrón queda representado solo por el path.
  if (params.length === 0) return path;

  // Ordenar los parámetros evita duplicados cuando aparecen en distinto orden.
  return `${path}?${params.sort().join('&')}`;
}

// Agrupa endpoints equivalentes para enviar a la IA un único ejemplo por patrón.
function agruparEndpoints(endpoints) {
  const mapa = new Map();

  endpoints.forEach(e => {
    const clave = clavePatron(e);

    // Solo se guarda el primer endpoint de cada patrón como ejemplo representativo.
    if (!mapa.has(clave)) {
      mapa.set(clave, {
        patron: clave,
        ejemplo: e.url,
        categoria: e.categoria,
        parametros: e.parametros,
        evidencias: e.evidencias
      });
    }
  });

  return Array.from(mapa.values());
}

// Envía un prompt a Ollama y devuelve la respuesta textual generada por el modelo.
const generarRespuestaIA = async (prompt) => {
  try {
    const response = await fetch(OLLAMA_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: MODEL,
        prompt,
        stream: false,
        system: `
        Eres un generador de informes técnicos de ciberseguridad.
        Redactas informes claros, profesionales y suficientemente detallados.
        Respondes siempre en español.
        Tu salida debe ser un informe profesional, no una explicación del JSON recibido.
        No uses tono conversacional.
        No menciones que eres una IA.
        `,
        options: {
          temperature: 0.1,
          num_predict: 1400,
          num_ctx: 5000,
          num_thread: 4
        }
      })
    });

    if (!response.ok) throw new Error(`Error de Ollama: ${response.status}`);

    const data = await response.json();
    return data.response || '';
  } catch (error) {
    throw new Error(`Fallo al conectar con la IA: ${error.message}`);
  }
};

// Prepara los endpoints agrupados, pide a la IA que los valore y parsea el JSON devuelto.
const analizarEndpointsIA = async (datosAnalisis) => {
  try {
    const prompt = `
Genera un informe profesional de análisis de seguridad web a partir de los datos técnicos proporcionados.

La respuesta debe estar completamente en ESPAÑOL.

IMPORTANTE:
- No describas el JSON.
- No expliques la estructura de los datos.
- No digas frases como:
  "la información proporcionada es..."
  "como pentester"
  "he analizado"
  "he identificado"
  "parece"
  "podría"
- No hables en primera persona.
- No uses tono conversacional.
- No menciones IA, modelo o proceso automático.
- No devuelvas JSON.
- No inventes vulnerabilidades confirmadas sin evidencias reales.

Tu tarea es transformar los datos técnicos en un informe narrativo profesional de auditoría ofensiva.

El informe debe tener formato profesional y una redacción extensa y desarrollada.

REQUISITOS DE REDACCIÓN:
- El informe debe ser detallado y técnico.
- Cada sección debe desarrollarse ampliamente.
- Cada apartado debe contener varios párrafos explicativos.
- No resumir hallazgos en una sola frase.
- Explicar el contexto técnico de cada vulnerabilidad o riesgo.
- Desarrollar el impacto potencial de explotación.
- Explicar técnicamente las mitigaciones.
- Mantener estilo formal de auditoría profesional.
- El contenido debe parecer un informe real de pentesting ofensivo.
- Evitar respuestas genéricas o demasiado cortas.
- No enumerar simplemente endpoints.
- Transformar los datos en análisis técnicos reales.

LONGITUD MÍNIMA:
- Resumen ejecutivo: mínimo 2 párrafos.
- Superficie de ataque: mínimo 3 párrafos.
- Vulnerabilidades y riesgos: desarrollar cada hallazgo individualmente.
- Mitigaciones: explicar técnicamente cada recomendación.
- Conclusión: mínimo 2 párrafos.

El informe debe seguir EXACTAMENTE esta estructura:

# Informe de análisis de seguridad web

## 1. Resumen ejecutivo
Explicar el estado general de seguridad del objetivo.
Indicar si existen vulnerabilidades confirmadas o principalmente riesgos potenciales.
Desarrollar una valoración global del nivel de exposición observado.

## 2. Superficie de ataque identificada
Explicar la superficie de ataque detectada:
- endpoints dinámicos
- formularios
- login
- documentación Swagger/API
- endpoints administrativos
- parámetros sensibles
- recursos accesibles públicamente

No mencionar categorías internas del sistema como "dinamico".

## 3. Vulnerabilidades confirmadas
Incluir únicamente vulnerabilidades con evidencia confirmada.

Para cada vulnerabilidad incluir:
- descripción técnica
- riesgo asociado
- impacto potencial
- endpoints afectados
- criticidad
- mitigación recomendada

Si no existen vulnerabilidades confirmadas, indicarlo claramente.

## 4. Riesgos potenciales identificados
Analizar riesgos potenciales relacionados con:
- parámetros content
- template
- file
- sec
- url
- job
- formularios
- login
- Swagger
- rutas administrativas
- exposición API
- manipulación de parámetros
- posibles LFI
- posibles Open Redirect
- exposición de información

Para cada riesgo incluir:
- explicación técnica
- posible vector de explotación
- impacto potencial
- endpoints relacionados
- criticidad estimada

## 5. Impacto potencial de explotación
Explicar consecuencias posibles:
- robo de sesión
- ejecución de JavaScript
- acceso no autorizado
- exposición de información sensible
- enumeración de APIs
- manipulación de rutas
- abuso de formularios
- ataques sobre autenticación
- movimientos laterales
- incremento de superficie de ataque

Relacionar siempre el impacto con los hallazgos encontrados.

## 6. Recomendaciones técnicas de mitigación
Desarrollar recomendaciones técnicas concretas:
- validación de entrada
- sanitización
- codificación de salida
- protección XSS
- control de acceso
- protección CSRF
- listas blancas
- endurecimiento de Swagger
- restricción de documentación API
- validación de parámetros
- logging
- monitorización
- segmentación
- revisión manual de endpoints sensibles

Cada mitigación debe explicarse técnicamente.

## 7. Priorización de riesgos
Clasificar hallazgos según:
- Crítico
- Alto
- Medio
- Bajo
- Informativo

Justificar brevemente la prioridad asignada.

## 8. Conclusión final
Redactar una conclusión profesional y extensa.
Explicar el estado general de exposición observado.
Indicar qué elementos requieren revisión prioritaria.
Mantener tono técnico y profesional de auditoría ofensiva.

REGLAS TÉCNICAS IMPORTANTES:
- Si xss.confirmado es true, tratarlo como vulnerabilidad confirmada de criticidad alta.
- Si sqli.confirmado es true, tratarlo como vulnerabilidad confirmada crítica o alta.
- Si existen hallazgos Nuclei, utilizar su severidad para priorizar riesgos.
- Si todos los indicadores están en false, NO afirmar que existen vulnerabilidades confirmadas.
- Diferenciar SIEMPRE entre:
  - vulnerabilidad confirmada
  - riesgo potencial
- No inventar explotación exitosa sin evidencias.
- Redactar siempre de forma técnica y profesional.

Datos técnicos del análisis:
${JSON.stringify(datosAnalisis, null, 2)}
`;


    const respuesta = await generarRespuestaIA(prompt);

    return respuesta.trim();

  } catch (error) {
    return `Error al generar el análisis IA: ${error.message}`;
  }
};

// Exporta las funciones usadas por el servidor y por el pipeline de análisis.
module.exports = {
  generarRespuestaIA,
  analizarEndpointsIA,
  filtrarEndpointsParaIA,
  agruparEndpoints
};
