const PDFDocument = require('pdfkit');

// Genera un documento PDF con el prompt y la respuesta, y lo envía como descarga.
// Configura cabeceras HTTP y estructura el contenido con formato básico.
const generarPdfRespuesta = (res, prompt, respuesta) => {
  const doc = new PDFDocument({
    margin: 50,
    size: 'A4'
  });

  // Cabeceras HTTP
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename=resultado.pdf');

  doc.pipe(res);

  // Título
  doc
    .fontSize(18)
    .text('Resultado del análisis', {
      align: 'center',
      underline: true
    });

  doc.moveDown(2);

  // Prompt
  doc
    .fontSize(13)
    .text('Prompt:', { bold: true });

  doc
    .moveDown(0.5)
    .fontSize(11)
    .text(prompt, { align: 'justify' });

  doc.moveDown(1.5);

  // Respuesta
  doc
    .fontSize(13)
    .text('Respuesta IA:', { bold: true });

  doc
    .moveDown(0.5)
    .fontSize(11)
    .text(respuesta, { align: 'justify' });

  doc.end();
};

module.exports = { generarPdfRespuesta };