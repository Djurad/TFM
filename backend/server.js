const express = require('express');
const cors = require('cors');
const path = require('path');
const { generarPdfRespuesta } = require('./utils/pdf');
const { ejecutarReconocimiento } = require('./modules/reconocimiento');
const { procesarResultados } = require('./modules/procesamiento');
const { aplicarScoring } = require('./modules/scoring');
const {
  analizarEndpointsIA,
  filtrarEndpointsParaIA,
  agruparEndpoints
} = require('./modules/ia');

const app = express();
const PORT = 3000;

// Permite que el frontend pueda hacer peticiones al backend aunque estén en distinto origen.
app.use(cors());

// Evita que el navegador reutilice respuestas antiguas durante los análisis.
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// Permite leer cuerpos JSON enviados desde el frontend.
app.use(express.json());

// Sirve los archivos HTML, CSS y JS del frontend desde Express.
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// Carga la pantalla principal cuando se accede a la raíz del servidor.
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

// RECONOCIMIENTO WEB
// Recibe una URL o dominio, ejecuta el reconocimiento, procesa los datos,
// calcula criticidad y pide a la IA un análisis de los endpoints relevantes.
app.post('/analizar', async (req, res) => {
  try {
    // Acepta tanto "prompt" como "target" para ser compatible con distintas llamadas.
    const entrada = req.body.prompt || req.body.target;

    if (!entrada) {
      return res.status(400).json({
        error: 'No se recibió ningún dominio o URL.'
      });
    }

    // 1. Ejecuta herramientas externas de reconocimiento sobre el dominio.
    const reconocimiento = await ejecutarReconocimiento(entrada.trim());

    // 2. Convierte la salida cruda en una estructura más fácil de consumir.
    const procesado = procesarResultados(reconocimiento);

    // 3. Añade criticidad, riesgo global, resumen y distribuciones.
    const resultado = aplicarScoring(procesado);

    // 4. Reduce la cantidad de endpoints enviados a IA para analizar solo los relevantes.
    const filtrados = filtrarEndpointsParaIA(resultado.endpoints);

    // 5. Agrupa endpoints similares para no repetir patrones equivalentes.
    const agrupados = agruparEndpoints(filtrados);

    // 6. Pide a la IA una valoración adicional de los patrones agrupados.
    const analisisIA = await analizarEndpointsIA(agrupados);

    // Devuelve el análisis técnico completo, los endpoints enviados a IA y la respuesta IA.
    res.json({
      resultado,
      endpointsIA: agrupados,
      analisisIA
    });

  } catch (error) {
    // Cualquier fallo del pipeline se devuelve como error 500 al cliente.
    res.status(500).json({ error: error.message });
  }
});

// PDF
// Recibe el dominio/prompt y el resultado generado para devolver un PDF descargable.
app.post('/descargar', async (req, res) => {
  try {
    const { prompt, respuesta } = req.body;

    // Valida que el prompt exista y sea texto útil antes de crear el PDF.
    if (!prompt || typeof prompt !== 'string' || !prompt.trim()) {
      return res.status(400).json({ error: 'Debes enviar un prompt válido.' });
    }

    // Valida que exista contenido que escribir dentro del PDF.
    if (!respuesta || typeof respuesta !== 'string' || !respuesta.trim()) {
      return res.status(400).json({ error: 'Debes enviar una respuesta válida.' });
    }

    // La función escribe directamente el PDF en la respuesta HTTP.
    generarPdfRespuesta(res, prompt, respuesta);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Arranca el servidor y deja Express escuchando peticiones en el puerto definido.
app.listen(PORT, () => {
  console.log(`Servidor en http://localhost:${PORT}`);
});

/*
const express = require('express');
const cors = require('cors');
const path = require('path');
const { generarRespuestaIA } = require('./modules/ia');
const { generarPdfRespuesta } = require('./utils/pdf');

const app = express();
const PORT = 3000;

app.use(cors());

app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

app.use(express.json());


app.use(express.static(path.join(__dirname, '..', 'frontend')));

// Sirve el archivo principal index.html cuando se accede a la raíz.
// Permite cargar la interfaz del frontend desde el navegador.
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

// IA
// Recibe un prompt del cliente, lo valida y genera una respuesta usando IA.
// Devuelve el resultado en formato JSON o un error si ocurre algún problema.
app.post('/analizar', async (req, res) => {
  try {
    const { prompt } = req.body;

    if (!prompt || typeof prompt !== 'string' || !prompt.trim()) {
      return res.status(400).json({ error: 'Debes enviar un prompt válido.' });
    }

    const respuesta = await generarRespuestaIA(prompt);
    res.json({ resultado: respuesta });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PDF
// Recibe un prompt y su respuesta, los valida y genera un PDF descargable.
// Envía el PDF directamente en la respuesta HTTP al cliente.
app.post('/descargar', async (req, res) => {
  try {
    const { prompt, respuesta } = req.body;

    if (!prompt || typeof prompt !== 'string' || !prompt.trim()) {
      return res.status(400).json({ error: 'Debes enviar un prompt válido.' });
    }

    if (!respuesta || typeof respuesta !== 'string' || !respuesta.trim()) {
      return res.status(400).json({ error: 'Debes enviar una respuesta válida.' });
    }

    generarPdfRespuesta(res, prompt, respuesta);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Inicia el servidor en el puerto definido (3000) y queda escuchando peticiones.
// Muestra en consola la URL local para acceder al backend.
app.listen(PORT, () => {
  console.log(`Servidor en http://localhost:${PORT}`);
});

*/
