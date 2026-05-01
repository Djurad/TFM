const btnAnalizar = document.getElementById('btnAnalizar');
const btnDescargar = document.getElementById('btnDescargar');
const promptInput = document.getElementById('prompt');
const resultado = document.getElementById('resultado');

let ultimaRespuesta = null;

// BOTÓN ANALIZAR
// Envía la URL/dominio al backend, ejecuta el reconocimiento
// y muestra el JSON formateado en pantalla.
btnAnalizar.addEventListener('click', async () => {
  const prompt = promptInput.value.trim();

  if (!prompt) {
    resultado.textContent = 'Escribe una URL o dominio.';
    return;
  }

  resultado.textContent = 'Ejecutando reconocimiento...';
  ultimaRespuesta = null;

  try {
    const response = await fetch('http://localhost:3000/analizar', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Error desconocido');
    }

    // Guardamos el JSON formateado
    ultimaRespuesta = JSON.stringify(data.resultado, null, 2);

    // Mostramos en pantalla
    resultado.textContent = ultimaRespuesta;

  } catch (error) {
    resultado.textContent = `Error: ${error.message}`;
  }
});


// BOTÓN DESCARGAR
// Envía el JSON generado al backend para crear un PDF descargable.
btnDescargar.addEventListener('click', async () => {
  const prompt = promptInput.value.trim();

  if (!prompt) {
    alert('Introduce una URL o dominio primero');
    return;
  }

  if (!ultimaRespuesta) {
    alert('Primero pulsa Analizar para generar el reconocimiento');
    return;
  }

  try {
    const response = await fetch('http://localhost:3000/descargar', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        prompt,
        respuesta: ultimaRespuesta
      })
    });

    if (!response.ok) {
      const errorData = await response.json();
      alert('Error del servidor: ' + errorData.error);
      return;
    }

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = 'resultado.pdf';
    a.click();

  } catch (error) {
    alert('Error: ' + error.message);
  }
});

/*const btnAnalizar = document.getElementById('btnAnalizar');
const btnDescargar = document.getElementById('btnDescargar');
const promptInput = document.getElementById('prompt');
const resultado = document.getElementById('resultado');

let ultimaRespuesta = null;

// Envía el prompt al servidor para analizarlo y muestra el resultado en pantalla.
// Guarda la última respuesta para poder reutilizarla posteriormente.
btnAnalizar.addEventListener('click', async () => {
  const prompt = promptInput.value.trim();
  if (!prompt) {
    resultado.textContent = 'Escribe un prompt.';
    return;
  }
  resultado.textContent = 'Cargando...';
  ultimaRespuesta = null;

  try {
    const response = await fetch('http://localhost:3000/analizar', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Error desconocido');
    ultimaRespuesta = data.resultado;
    resultado.textContent = ultimaRespuesta;
  } catch (error) {
    resultado.textContent = `Error: ${error.message}`;
  }
});

// Envía el prompt y la respuesta al servidor para generar y descargar un PDF.
// Crea un enlace temporal para descargar automáticamente el archivo generado.
btnDescargar.addEventListener('click', async () => {
  const prompt = promptInput.value.trim();
  if (!prompt) {
    alert('Escribe un prompt primero');
    return;
  }
  if (!ultimaRespuesta) {
    alert('Primero pulsa Analizar para generar una respuesta');
    return;
  }

  try {
    const response = await fetch('http://localhost:3000/descargar', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt, respuesta: ultimaRespuesta })
    });

    if (!response.ok) {
      const errorData = await response.json();
      alert('Error del servidor: ' + errorData.error);
      return;
    }

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'resultado.pdf';
    a.click();
  } catch (error) {
    alert('Error: ' + error.message);
  }
});*/