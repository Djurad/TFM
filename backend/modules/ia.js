require('dotenv').config();
const OLLAMA_URL = `http://${process.env.OLLAMA_HOST}:11434/api/generate`;
const MODEL = 'llama3';

// Envía un prompt al modelo de IA (Ollama) y devuelve la respuesta generada.
// Configura parámetros como temperatura y limita la longitud de la salida.
const generarRespuestaIA = async (prompt) => {
  try {
    const response = await fetch(OLLAMA_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: MODEL,
        prompt,
        stream: false,
        system: 'Eres un asistente conciso. Responde siempre en español, de forma breve y directa. Sin explicaciones innecesarias, sin inventar información.',
        options: {
          temperature: 0.1,
          num_predict: 300
        }
      })
    });
    if (!response.ok) throw new Error(`Error de Ollama: ${response.status}`);
    const data = await response.json();
    return data.response || 'No se recibió respuesta del modelo.';
  } catch (error) {
    throw new Error(`Fallo al conectar con la IA: ${error.message}`);
  }
};

module.exports = { generarRespuestaIA };