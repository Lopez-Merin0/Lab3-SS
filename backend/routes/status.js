const express = require('express');

function createStatusRouter({ scanJobs, validateScanIdParam }) {
  const router = express.Router();

  // GET /api/status/:scanId
  // Retorna estado actual del escaneo.
  // Estados: pending, scanning, completed, error.
  router.get('/status/:scanId', validateScanIdParam, (req, res) => {
    const job = scanJobs.get(req.params.scanId);
    if (!job) {
      return res.status(404).json({ error: 'scanId no encontrado' });
    }

    res.json({
      scanId: job.scanId,
      fileId: job.fileId,
      status: job.status,
      createdAt: job.createdAt,
      startedAt: job.startedAt,
      finishedAt: job.finishedAt,
      error: job.error
    });
  });

  // GET /api/result/:scanId
  // Retorna resultado final del escaneo con metadatos del archivo.
  // Status final esperado: clean, infected, error.
  router.get('/result/:scanId', validateScanIdParam, (req, res) => {
    const job = scanJobs.get(req.params.scanId);
    if (!job) {
      return res.status(404).json({ error: 'scanId no encontrado' });
    }

    if (job.status === 'pending' || job.status === 'scanning') {
      return res.status(202).json({
        scanId: job.scanId,
        status: job.status,
        message: 'Escaneo en proceso'
      });
    }

    // 500 — Error tecnico: clamd caido, archivo no encontrado en disco, etc.
    if (job.status === 'error') {
      return res.status(500).json({
        scanId: job.scanId,
        status: 'error',
        error: job.error,
        message: 'Error tecnico durante el escaneo'
      });
    }

    // 422 — Archivo infectado: amenaza detectada, detalles de los virus incluidos.
    // Se usa 422 Unprocessable Content porque el archivo fue procesado correctamente
    // pero su contenido no es aceptable (contiene malware).
    if (job.result.status === 'infected') {
      return res.status(422).json({
        ...job.result,
        message: `Amenaza detectada: ${job.result.threats.join(', ')}`
      });
    }

    // 200 — Archivo limpio: el escaneo completo sin amenazas.
    res.status(200).json({
      ...job.result,
      message: 'Archivo analizado correctamente, no se detectaron amenazas'
    });
  });

  return router;
}

module.exports = createStatusRouter;
