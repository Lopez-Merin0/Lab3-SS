const express = require('express');
const fs = require('fs');

function createScanRouter({ uploadedFiles, scanJobs, validateFileIdParam, genId, runScanJob, safeUnlink }) {
  const router = express.Router();

  // ---------------------------------------------------------------------------
  // POST /api/scan/:fileId
  // Inicia escaneo con ClamAV, retorna scanId para seguimiento
  // y ejecuta el proceso de forma asincrona.
  // ---------------------------------------------------------------------------
  router.post('/scan/:fileId', validateFileIdParam, (req, res) => {
    const { fileId } = req.params;
    const fileMeta = uploadedFiles.get(fileId);

    // Verificar que el fileId exista en memoria
    if (!fileMeta) {
      return res.status(404).json({ error: 'fileId no encontrado' });
    }

    // Verificar que el archivo fisico siga en disco (pudo haberse limpiado)
    if (!fs.existsSync(fileMeta.currentPath)) {
      return res.status(404).json({ error: 'Archivo temporal no existe' });
    }

    // Evitar escaneos duplicados sobre el mismo archivo
    if (fileMeta.state === 'scanning') {
      return res.status(409).json({ error: 'El archivo ya se esta escaneando' });
    }

    // Crear el job de escaneo con estado inicial 'pending'
    const scanId = genId('scan');
    const job = {
      scanId,
      fileId,
      status: 'pending',       // pending → scanning → completed | error
      createdAt: new Date().toISOString(),
      startedAt: null,         // Se rellena cuando runScanJob comienza el analisis
      finishedAt: null,        // Se rellena al terminar (exito o error)
      result: null,            // Objeto resultado completo (solo si completed)
      error: null              // Mensaje de error (solo si status = error)
    };

    scanJobs.set(scanId, job);

    // Lanzar el escaneo de forma asincrona con setImmediate para no bloquear
    // la respuesta HTTP. runScanJob actualiza el job en memoria cuando termina.
    setImmediate(() => {
      runScanJob(scanId).catch((err) => {
        const target = scanJobs.get(scanId);
        if (!target) return;
        target.status = 'error';
        target.error = err.message;
        target.finishedAt = new Date().toISOString();
      });
    });

    // Responder 202 Accepted: el escaneo fue aceptado pero aun no ha terminado.
    // El cliente debe hacer polling a GET /api/status/:scanId para ver el progreso.
    res.status(202).json({ scanId, fileId, status: 'pending' });
  });

  router.delete('/cleanup/:fileId', validateFileIdParam, (req, res) => {
    const { fileId } = req.params;
    const fileMeta = uploadedFiles.get(fileId);

    if (!fileMeta) {
      return res.status(404).json({ error: 'fileId no encontrado' });
    }

    if (fileMeta.state === 'scanning') {
      return res.status(409).json({ error: 'No se puede limpiar un archivo en escaneo' });
    }

    safeUnlink(fileMeta.currentPath);

    const deletedScans = [];
    for (const [scanId, job] of scanJobs.entries()) {
      if (job.fileId === fileId) {
        scanJobs.delete(scanId);
        deletedScans.push(scanId);
      }
    }

    uploadedFiles.delete(fileId);

    res.json({
      cleaned: true,
      fileId,
      deletedScans,
      message: 'Archivos temporales limpiados correctamente'
    });
  });

  return router;
}

module.exports = createScanRouter;
