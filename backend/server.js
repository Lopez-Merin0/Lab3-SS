const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

require('dotenv').config();

const { auth } = require('./middleware/auth');
const {
  ALLOWED_TYPES,
  createUploadMiddleware,
  validateFileIdParam,
  validateScanIdParam
} = require('./middleware/validation');
const {
  genId,
  sha256File,
  formatBytes,
  ensureDir,
  safeUnlink,
  requestLogger,
  createMemoryRateLimiter
} = require('./utils/helpers');
const { initClamAV, isReady, scanFile, getVersion } = require('./services/clamav');

const createUploadRouter = require('./routes/upload');
const createScanRouter = require('./routes/scan');
const createStatusRouter = require('./routes/status');

const app = express();
const PORT = process.env.PORT || 3000;
const ALLOW_SCAN_WITHOUT_CLAMAV = process.env.ALLOW_SCAN_WITHOUT_CLAMAV
  ? process.env.ALLOW_SCAN_WITHOUT_CLAMAV.toLowerCase() === 'true'
  : process.env.NODE_ENV !== 'production';

const ROOT_DIR = path.join(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT_DIR, 'public');
const UPLOAD_DIR = path.join(ROOT_DIR, 'uploads');
const QUARANTINE_DIR = path.join(ROOT_DIR, 'quarantine');

ensureDir(UPLOAD_DIR);
ensureDir(QUARANTINE_DIR);

const uploadedFiles = new Map();
const scanJobs = new Map();

const corsOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',').map((o) => o.trim())
  : '*';

app.use(cors({
  origin: corsOrigins,
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
}));

app.use(express.json());
app.use(requestLogger);
app.use(createMemoryRateLimiter({
  windowMs: 15 * 60 * 1000,
  maxRequests: 100
}));

app.use(express.static(PUBLIC_DIR));
app.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'frontend', 'index.html'));
});

const withUpload = createUploadMiddleware(UPLOAD_DIR);

// =============================================================================
// runScanJob — Orquestador principal del escaneo antivirus
// =============================================================================
// Recibe un scanId, coordina todo el pipeline de analisis y actualiza el job.
// Es llamado de forma asincrona desde POST /api/scan/:fileId via setImmediate.
// =============================================================================
async function runScanJob(scanId) {
  // 1) Recuperar el job del mapa en memoria
  const job = scanJobs.get(scanId);
  if (!job) return;

  // 2) Verificar que los metadatos del archivo existan y el archivo este en disco
  const fileMeta = uploadedFiles.get(job.fileId);
  if (!fileMeta || !fs.existsSync(fileMeta.currentPath)) {
    job.status = 'error';
    job.error = 'Archivo no encontrado para escaneo';
    job.finishedAt = new Date().toISOString();
    return;
  }

  // 3) Verificar que el daemon ClamAV este inicializado antes de continuar
  if (!isReady()) {
    if (ALLOW_SCAN_WITHOUT_CLAMAV) {
      const start = Date.now();
      const sha256 = await sha256File(fileMeta.currentPath);

      job.status = 'completed';
      job.startedAt = new Date().toISOString();
      job.finishedAt = new Date().toISOString();
      job.result = {
        scanId,
        fileId: fileMeta.fileId,
        status: 'clean',
        filename: fileMeta.originalname,
        mimetype: fileMeta.mimetype,
        filetype: ALLOWED_TYPES[fileMeta.mimetype] || 'Desconocido',
        size: fileMeta.size,
        sizeFormatted: formatBytes(fileMeta.size),
        sha256,
        threats: [],
        action: 'none',
        scanDuration: ((Date.now() - start) / 1000).toFixed(2),
        scannedAt: new Date().toISOString(),
        scanEngine: 'fallback-no-clamav',
        warning: 'ClamAV no inicializado. Resultado no verificado por antivirus real.'
      };
      fileMeta.state = 'scanned';
      fileMeta.lastScanId = scanId;
      console.warn('ClamAV no inicializado: escaneo completado en modo fallback');
      return;
    }

    job.status = 'error';
    job.error = 'ClamAV no inicializado';
    job.finishedAt = new Date().toISOString();
    return;
  }

  try {
    // 4) Marcar el job y el archivo como "en proceso de escaneo"
    job.status = 'scanning';
    job.startedAt = new Date().toISOString();
    fileMeta.state = 'scanning';

    const start = Date.now();

    // 5) Calcular el hash SHA-256 del archivo (integridad y trazabilidad)
    const sha256 = await sha256File(fileMeta.currentPath);

    // 6) Enviar el archivo a ClamAV para su analisis
    //    scanFile() delega en clamscan.isInfected() que contacta al daemon clamd
    //    Retorna: { isInfected: boolean, viruses: string[] }
    const { isInfected, viruses } = await scanFile(fileMeta.currentPath);

    // 7) Cuarentena: si el archivo esta infectado, moverlo fuera del directorio
    //    de uploads para aislar la amenaza (fs.renameSync es atomico en el mismo volumen)
    let action = 'none';
    if (isInfected) {
      const quarantinePath = path.join(QUARANTINE_DIR, path.basename(fileMeta.currentPath));
      fs.renameSync(fileMeta.currentPath, quarantinePath);
      fileMeta.currentPath = quarantinePath;  // Actualizar ruta en los metadatos
      fileMeta.location = 'quarantine';
      action = 'quarantined';
      console.warn(`Archivo infectado en cuarentena: ${fileMeta.originalname}`);
    }

    // 8) Construir el objeto resultado con todos los metadatos del escaneo
    const result = {
      scanId,
      fileId: fileMeta.fileId,
      status: isInfected ? 'infected' : 'clean',  // Estado final del analisis
      filename: fileMeta.originalname,
      mimetype: fileMeta.mimetype,
      filetype: ALLOWED_TYPES[fileMeta.mimetype] || 'Desconocido',
      size: fileMeta.size,
      sizeFormatted: formatBytes(fileMeta.size),
      sha256,                               // Hash para verificacion de integridad
      threats: isInfected ? viruses : [],   // Nombres de virus detectados (si los hay)
      action,                               // 'quarantined' | 'none'
      scanDuration: ((Date.now() - start) / 1000).toFixed(2), // Segundos que tomo el escaneo
      scannedAt: new Date().toISOString()
    };

    // 9) Marcar el job como completado y persistir el resultado en memoria
    job.status = 'completed';
    job.finishedAt = new Date().toISOString();
    job.result = result;
    fileMeta.state = 'scanned';
    fileMeta.lastScanId = scanId;
  } catch (err) {
    // 10) Cualquier error inesperado (clamd caido, disco lleno, etc.) queda registrado
    job.status = 'error';
    job.error = err.message;
    job.finishedAt = new Date().toISOString();
    fileMeta.state = 'error';
    console.error('Error ejecutando escaneo:', err.message);
  }
}

app.use('/api', auth);

app.use('/api', createUploadRouter({
  uploadedFiles,
  withUpload,
  genId
}));

app.use('/api', createScanRouter({
  uploadedFiles,
  scanJobs,
  validateFileIdParam,
  genId,
  runScanJob,
  safeUnlink
}));

app.use('/api', createStatusRouter({
  scanJobs,
  validateScanIdParam
}));

app.get('/api/health', async (req, res) => {
  try {
    if (!isReady()) {
      return res.status(503).json({ status: 'error', clamd: 'not-ready' });
    }

    const version = await getVersion();
    res.json({
      status: 'ok',
      clamd: 'running',
      version,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(503).json({ status: 'error', message: err.message });
  }
});

app.use('/api', (req, res) => {
  res.status(404).json({ error: 'Endpoint no encontrado' });
});

app.use((err, req, res, next) => {
  const status = err.statusCode || 500;
  console.error('Error no controlado:', err.message);
  res.status(status).json({
    error: err.message || 'Error interno del servidor'
  });
});

(async () => {
  try {
    await initClamAV();
    console.log('ClamAV inicializado');
  } catch (err) {
    console.error('No se pudo inicializar ClamAV:', err.message);
  }

  app.listen(PORT, () => {
    console.log(`ShieldScan corriendo en http://localhost:${PORT}`);
    console.log(`Uploads: ${UPLOAD_DIR}`);
    console.log(`Quarantine: ${QUARANTINE_DIR}`);
  });
})();

module.exports = app;
