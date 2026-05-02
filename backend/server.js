const express = require('express');
const cors = require('cors');
const path = require('path');
const { generarPdfRespuesta } = require('./utils/pdf');
const { ejecutarReconocimiento } = require('./modules/reconocimiento');
const { procesarResultados } = require('./modules/procesamiento');
const { aplicarScoring } = require('./modules/scoring');

const app = express();
const PORT = 3000;

app.use(cors());

app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

app.use(express.json());

app.use(express.static(path.join(__dirname, '..', 'frontend')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

// RECONOCIMIENTO WEB
// Recibe una URL o dominio, ejecuta el reconocimiento y devuelve el JSON obtenido.
// De momento NO se manda nada a la IA.
app.post('/analizar', async (req, res) => {
  try {
    const { prompt } = req.body;

    if (!prompt || typeof prompt !== 'string' || !prompt.trim()) {
      return res.status(400).json({ error: 'Debes enviar una URL o dominio válido.' });
    }

    const reconocimiento = await ejecutarReconocimiento(prompt.trim());
    const procesado = procesarResultados(reconocimiento);
    const resultadoFinal = aplicarScoring(procesado);

    res.json({
      resultado: resultadoFinal
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PDF
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