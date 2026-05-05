// Referencias a los elementos principales de la interfaz.
const btnAnalizar = document.getElementById('btnAnalizar');
const btnDescargar = document.getElementById('btnDescargar');
const promptInput = document.getElementById('prompt');
const resultado = document.getElementById('resultado');

// Guarda el último resultado generado para poder enviarlo después al PDF.
let ultimaRespuesta = null;

// BOTÓN ANALIZAR
// Envía la URL/dominio al backend, ejecuta el reconocimiento
// y muestra el JSON formateado en pantalla.
btnAnalizar.addEventListener('click', async () => {
  // Elimina espacios sobrantes antes de validar o enviar el valor.
  const prompt = promptInput.value.trim();

  // No se lanza el análisis si el usuario no ha escrito nada.
  if (!prompt) {
    resultado.textContent = 'Escribe una URL o dominio.';
    return;
  }

  // Mensaje de estado mientras el backend ejecuta herramientas de reconocimiento.
  resultado.textContent = 'Ejecutando reconocimiento...';

  // Limpia la respuesta anterior para evitar descargar resultados antiguos.
  ultimaRespuesta = null;

  try {
    // Envía el dominio al backend para iniciar el pipeline de análisis.
    const response = await fetch('http://localhost:3000/analizar', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt })
    });

    const data = await response.json();

    // Si Express devuelve error, se muestra el mensaje recibido del backend.
    if (!response.ok) {
      throw new Error(data.error || 'Error desconocido');
    }

    // Guardamos el JSON formateado para mostrarlo y reutilizarlo en la descarga.
    ultimaRespuesta = JSON.stringify(data, null, 2);

    // Mostramos en pantalla el resultado principal del reconocimiento.
    resultado.textContent = ultimaRespuesta;

  } catch (error) {
    // Muestra errores de red, validación o ejecución del backend.
    resultado.textContent = `Error: ${error.message}`;
  }
});


// BOTÓN DESCARGAR
// Envía el JSON generado al backend para crear un PDF descargable.
btnDescargar.addEventListener('click', async () => {
  // Se vuelve a leer el input para incluir el dominio/prompt en el PDF.
  const prompt = promptInput.value.trim();

  // El PDF necesita saber qué dominio se analizó.
  if (!prompt) {
    alert('Introduce una URL o dominio primero');
    return;
  }

  // Evita descargar un PDF vacío si todavía no se ha ejecutado el análisis.
  if (!ultimaRespuesta) {
    alert('Primero pulsa Analizar para generar el reconocimiento');
    return;
  }

  try {
    // Envía al backend el dominio y el resultado para que pdfkit genere el archivo.
    const response = await fetch('http://localhost:3000/descargar', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        prompt,
        respuesta: ultimaRespuesta
      })
    });

    // Si el backend no pudo crear el PDF, muestra el error devuelto.
    if (!response.ok) {
      const errorData = await response.json();
      alert('Error del servidor: ' + errorData.error);
      return;
    }

    // Convierte la respuesta binaria en un objeto descargable por el navegador.
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);

    // Crea un enlace temporal y simula un clic para iniciar la descarga.
    const a = document.createElement('a');
    a.href = url;
    a.download = 'resultado.pdf';
    a.click();

  } catch (error) {
    // Captura errores de red o problemas inesperados durante la descarga.
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
