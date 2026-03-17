const express = require('express');

function createUploadRouter({ uploadedFiles, withUpload, genId }) {
  const router = express.Router();

  // POST /api/upload
  // Recibe archivo multipart, valida tipo/tamano via middleware,
  // guarda en directorio temporal y retorna fileId unico.
  router.post('/upload', withUpload, (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: 'No se recibio ningun archivo' });
    }

    const fileId = genId('file');
    const metadata = {
      fileId,
      originalname: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size,
      uploadedAt: new Date().toISOString(),
      location: 'uploads',
      state: 'uploaded',
      currentPath: req.file.path,
      lastScanId: null
    };

    uploadedFiles.set(fileId, metadata);

    res.status(201).json({
      fileId,
      filename: metadata.originalname,
      mimetype: metadata.mimetype,
      size: metadata.size,
      uploadedAt: metadata.uploadedAt,
      status: metadata.state
    });
  });

  return router;
}

module.exports = createUploadRouter;
