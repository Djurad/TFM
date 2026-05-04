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
Eres un pentester profesional.

Analiza endpoints web y determina su criticidad de forma REALISTA.

REGLAS:
- NO inventes vulnerabilidades
- SOLO evalúa riesgo potencial o confirmado
- Sé preciso y conservador
- Responde SOLO en JSON válido
- No añadas texto fuera del JSON

ESCALA:
0 informativo
2 bajo
4 medio
7 alto
9 crítico

CRITERIOS:
- Estático → informativo
- Parámetros → bajo/medio
- content/template/file → posible LFI → medio
- url/redirect → posible open redirect → medio
- login → medio
- admin → medio/alto
- swagger → bajo/medio
- XSS confirmada → alto
- SQLi confirmada → crítico
`,
        options: {
          // Temperatura baja para obtener respuestas más estables y conservadoras.
          temperature: 0.1,

          // Límite aproximado de tokens generados por Ollama.
          num_predict: 800
        }
      })
    });

    // Si Ollama responde con error HTTP, se convierte en una excepción controlada.
    if (!response.ok) throw new Error(`Error de Ollama: ${response.status}`);

    const data = await response.json();

    // Ollama devuelve el texto generado dentro de la propiedad "response".
    return data.response || '';
  } catch (error) {
    throw new Error(`Fallo al conectar con la IA: ${error.message}`);
  }
};


// Prepara los endpoints agrupados, pide a la IA que los valore y parsea el JSON devuelto.
const analizarEndpointsIA = async (endpoints) => {
  try {
    // Se envía a la IA solo la información necesaria para valorar riesgo.
    const input = endpoints.map(e => ({
      patron: e.patron,
      categoria: e.categoria,
      parametros: e.parametros,
      tieneParametros: e.parametros?.length > 0,
      evidencias: {
        sqli: e.evidencias?.sqli?.confirmado || false,
        xss: e.evidencias?.xss?.confirmado || false,
        nuclei: (e.evidencias?.nuclei || []).map(n => n.severidad)
      }
    }));

    // Prompt específico: obliga a devolver un array JSON estructurado.
    const prompt = `
Analiza estos endpoints y devuelve un array JSON.

Para cada endpoint devuelve:
- patron
- criticidad (número)
- nivel ("informativo","bajo","medio","alto","critico")
- relevante (true/false)
- motivo (breve)

Endpoints:
${JSON.stringify(input, null, 2)}
`;

    const respuesta = await generarRespuestaIA(prompt);

    try {
      // Si la IA respeta el formato, se devuelve JSON listo para consumir.
      return JSON.parse(respuesta);
    } catch {
      // Si no devuelve JSON válido, se conserva la respuesta cruda para depuración.
      return {
        error: 'La IA no devolvió JSON válido',
        raw: respuesta
      };
    }
  } catch (error) {
    return {
      error: error.message
    };
  }
};

// Exporta las funciones usadas por el servidor y por el pipeline de análisis.
module.exports = {
  generarRespuestaIA,
  analizarEndpointsIA,
  filtrarEndpointsParaIA,
  agruparEndpoints
};
