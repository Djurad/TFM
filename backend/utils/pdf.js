const PDFDocument = require('pdfkit');

function escribirTexto(doc, texto) {
  String(texto || '')
    .split('\n')
    .forEach(linea => {
      if (linea.startsWith('# ')) {
        doc.moveDown(0.8).fontSize(18).text(linea.replace(/^#\s+/, ''), {
          underline: true
        });
      } else if (linea.startsWith('## ')) {
        doc.moveDown(0.7).fontSize(14).text(linea.replace(/^##\s+/, ''), {
          underline: true
        });
      } else {
        doc.fontSize(10).text(linea || ' ', {
          align: 'justify'
        });
      }
    });
}

function generarPdfDesdeInforme(res, target, informe) {
  const doc = new PDFDocument({
    margin: 50,
    size: 'A4'
  });

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename=informe-seguridad.pdf');

  doc.pipe(res);

  doc
    .fontSize(18)
    .text('Informe de analisis de seguridad', {
      align: 'center',
      underline: true
    });

  doc.moveDown(1);
  doc.fontSize(11).text(`Objetivo: ${target}`, { align: 'left' });
  doc.moveDown(1);

  escribirTexto(doc, informe);

  doc.end();
}

// Compatibilidad con el endpoint antiguo /descargar.
function generarPdfRespuesta(res, prompt, respuesta) {
  generarPdfDesdeInforme(res, prompt, respuesta);
}

module.exports = {
  generarPdfRespuesta,
  generarPdfDesdeInforme
};
