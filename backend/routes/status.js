const express = require('express');

function createStatusRouter({ scanJobs, validateScanIdParam }) {
  const router = express.Router();

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

    if (job.status === 'error') {
      return res.status(500).json({
        scanId: job.scanId,
        status: 'error',
        error: job.error
      });
    }

    res.json(job.result);
  });

  return router;
}

module.exports = createStatusRouter;
