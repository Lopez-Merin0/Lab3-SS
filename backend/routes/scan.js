const express = require('express');
const fs = require('fs');

function createScanRouter({ uploadedFiles, scanJobs, validateFileIdParam, genId, runScanJob, safeUnlink }) {
  const router = express.Router();

  router.post('/scan/:fileId', validateFileIdParam, (req, res) => {
    const { fileId } = req.params;
    const fileMeta = uploadedFiles.get(fileId);

    if (!fileMeta) {
      return res.status(404).json({ error: 'fileId no encontrado' });
    }

    if (!fs.existsSync(fileMeta.currentPath)) {
      return res.status(404).json({ error: 'Archivo temporal no existe' });
    }

    if (fileMeta.state === 'scanning') {
      return res.status(409).json({ error: 'El archivo ya se esta escaneando' });
    }

    const scanId = genId('scan');
    const job = {
      scanId,
      fileId,
      status: 'pending',
      createdAt: new Date().toISOString(),
      startedAt: null,
      finishedAt: null,
      result: null,
      error: null
    };

    scanJobs.set(scanId, job);

    setImmediate(() => {
      runScanJob(scanId).catch((err) => {
        const target = scanJobs.get(scanId);
        if (!target) return;
        target.status = 'error';
        target.error = err.message;
        target.finishedAt = new Date().toISOString();
      });
    });

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
