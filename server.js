// =====================================================
// ShieldScan - Backend API con ClamAV
// Node.js + Express + Multer + clamscan
// =====================================================

const express = require('express');
const multer = require('multer');
const NodeClam = require('clamscan');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const UPLOAD_DIR = path.join(__dirname, 'uploads');
const QUARANTINE_DIR = path.join(__dirname, 'quarantine');
[UPLOAD_DIR, QUARANTINE_DIR].forEach((d) => fs.mkdirSync(d, { recursive: true }));

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 100;

const ALLOWED_EXTENSIONS = [
  '.pdf', '.doc', '.docx', '.xls', '.xlsx',
  '.txt', '.jpg', '.jpeg', '.png', '.gif',
  '.zip', '.rar', '.7z', '.exe'
];

const ALLOWED_TYPES = {
  'application/pdf': 'PDF',
  'application/msword': 'Word',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'Word',
  'application/vnd.ms-excel': 'Excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'Excel',
  'text/plain': 'Texto',
  'image/jpeg': 'JPEG',
  'image/png': 'PNG',
  'image/gif': 'GIF',
  'application/zip': 'ZIP',
  'application/x-rar-compressed': 'RAR',
  'application/x-7z-compressed': '7-Zip',
  'application/x-msdownload': 'EXE'
};

// Almacen temporal en memoria (demo)
const uploadedFiles = new Map(); // fileId -> metadata
const scanJobs = new Map(); // scanId -> status/result

// ==========================
// Middleware transversal
// ==========================

const corsOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',').map((o) => o.trim())
  : '*';

app.use(cors({
  origin: corsOrigins,
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.static('public'));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'frontend', 'index.html'));
});

// Logging simple por request
app.use((req, res, next) => {
  const startedAt = Date.now();
  res.on('finish', () => {
    const ms = Date.now() - startedAt;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} -> ${res.statusCode} (${ms}ms)`);
  });
  next();
});

// Rate limiting in-memory por IP
const ipBuckets = new Map();
app.use((req, res, next) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const bucket = ipBuckets.get(ip) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };

  if (now > bucket.resetAt) {
    bucket.count = 0;
    bucket.resetAt = now + RATE_LIMIT_WINDOW_MS;
  }

  bucket.count += 1;
  ipBuckets.set(ip, bucket);

  const remaining = Math.max(0, RATE_LIMIT_MAX_REQUESTS - bucket.count);
  res.setHeader('X-RateLimit-Limit', String(RATE_LIMIT_MAX_REQUESTS));
  res.setHeader('X-RateLimit-Remaining', String(remaining));
  res.setHeader('X-RateLimit-Reset', String(Math.ceil(bucket.resetAt / 1000)));

  if (bucket.count > RATE_LIMIT_MAX_REQUESTS) {
    return res.status(429).json({
      error: 'Demasiadas solicitudes',
      retryAfterSeconds: Math.ceil((bucket.resetAt - now) / 1000)
    });
  }

  next();
});

// ==========================
// Multer + validacion upload
// ==========================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname));
  }
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname.toLowerCase());

    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      return cb(new Error(`Extension no permitida: ${ext || 'sin extension'}`));
    }

    if (!ALLOWED_TYPES[file.mimetype]) {
      return cb(new Error(`MIME type no permitido: ${file.mimetype}`));
    }

    cb(null, true);
  }
});

function withUpload(req, res, next) {
  upload.single('file')(req, res, (err) => {
    if (!err) return next();
    if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
      return next(Object.assign(new Error('Archivo demasiado grande. Maximo permitido: 10MB'), { statusCode: 413 }));
    }
    return next(Object.assign(err, { statusCode: 400 }));
  });
}

function validateFileIdParam(req, res, next) {
  const { fileId } = req.params;
  if (!/^file_[a-zA-Z0-9]+$/.test(fileId)) {
    return res.status(400).json({ error: 'fileId invalido' });
  }
  next();
}

function validateScanIdParam(req, res, next) {
  const { scanId } = req.params;
  if (!/^scan_[a-zA-Z0-9]+$/.test(scanId)) {
    return res.status(400).json({ error: 'scanId invalido' });
  }
  next();
}

// ==========================
// ClamAV init
// ==========================
let clamscan;
(async () => {
  try {
    clamscan = await new NodeClam().init({
      removeInfected: false,
      quarantineInfected: false,
      scanRecursively: false,
      clamdscan: {
        socket: false,
        host: process.env.CLAMD_HOST || '127.0.0.1',
        port: Number(process.env.CLAMD_PORT || 3310),
        active: true
      },
      preference: 'clamdscan'
    });
    console.log('ClamAV inicializado');
  } catch (err) {
    console.error('No se pudo inicializar ClamAV:', err.message);
  }
})();

// ==========================
// Utilidades
// ==========================
function genId(prefix) {
  return `${prefix}_${Date.now().toString(36)}${crypto.randomBytes(4).toString('hex')}`;
}

function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (d) => hash.update(d));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(2)} MB`;
}

async function runScanJob(scanId) {
  const job = scanJobs.get(scanId);
  if (!job) return;

  const fileMeta = uploadedFiles.get(job.fileId);
  if (!fileMeta || !fs.existsSync(fileMeta.currentPath)) {
    job.status = 'error';
    job.error = 'Archivo no encontrado para escaneo';
    job.finishedAt = new Date().toISOString();
    return;
  }

  if (!clamscan) {
    job.status = 'error';
    job.error = 'ClamAV no inicializado';
    job.finishedAt = new Date().toISOString();
    return;
  }

  try {
    job.status = 'scanning';
    job.startedAt = new Date().toISOString();
    fileMeta.state = 'scanning';

    const start = Date.now();
    const sha256 = await sha256File(fileMeta.currentPath);
    const { isInfected, viruses } = await clamscan.isInfected(fileMeta.currentPath);

    let action = 'none';
    if (isInfected) {
      const quarantinePath = path.join(QUARANTINE_DIR, path.basename(fileMeta.currentPath));
      fs.renameSync(fileMeta.currentPath, quarantinePath);
      fileMeta.currentPath = quarantinePath;
      fileMeta.location = 'quarantine';
      action = 'quarantined';
      console.warn(`Archivo infectado en cuarentena: ${fileMeta.originalname}`);
    }

    const result = {
      scanId,
      fileId: fileMeta.fileId,
      status: isInfected ? 'infected' : 'clean',
      filename: fileMeta.originalname,
      mimetype: fileMeta.mimetype,
      filetype: ALLOWED_TYPES[fileMeta.mimetype] || 'Desconocido',
      size: fileMeta.size,
      sizeFormatted: formatBytes(fileMeta.size),
      sha256,
      threats: isInfected ? viruses : [],
      action,
      scanDuration: ((Date.now() - start) / 1000).toFixed(2),
      scannedAt: new Date().toISOString()
    };

    job.status = 'done';
    job.finishedAt = new Date().toISOString();
    job.result = result;
    fileMeta.state = 'scanned';
    fileMeta.lastScanId = scanId;
  } catch (err) {
    job.status = 'error';
    job.error = err.message;
    job.finishedAt = new Date().toISOString();
    fileMeta.state = 'error';
    console.error('Error ejecutando escaneo:', err.message);
  }
}

// ==========================
// Endpoints solicitados
// ==========================

app.post('/api/upload', withUpload, (req, res) => {
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

app.post('/api/scan/:fileId', validateFileIdParam, (req, res) => {
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

  // Ejecuta escaneo en background y responde inmediatamente.
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

app.get('/api/status/:scanId', validateScanIdParam, (req, res) => {
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

app.get('/api/result/:scanId', validateScanIdParam, (req, res) => {
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

app.delete('/api/cleanup/:fileId', validateFileIdParam, (req, res) => {
  const { fileId } = req.params;
  const fileMeta = uploadedFiles.get(fileId);

  if (!fileMeta) {
    return res.status(404).json({ error: 'fileId no encontrado' });
  }

  if (fileMeta.state === 'scanning') {
    return res.status(409).json({ error: 'No se puede limpiar un archivo en escaneo' });
  }

  if (fileMeta.currentPath && fs.existsSync(fileMeta.currentPath)) {
    fs.unlinkSync(fileMeta.currentPath);
  }

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

// Endpoint de salud (util para monitoreo)
app.get('/api/health', async (req, res) => {
  try {
    if (!clamscan) {
      return res.status(503).json({ status: 'error', clamd: 'not-ready' });
    }

    const version = await clamscan.getVersion();
    res.json({
      status: 'ok',
      clamd: 'running',
      version: version.trim(),
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(503).json({ status: 'error', message: err.message });
  }
});

// 404 para rutas API no encontradas
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'Endpoint no encontrado' });
});

// Manejador global de errores
app.use((err, req, res, next) => {
  const status = err.statusCode || 500;
  console.error('Error no controlado:', err.message);
  res.status(status).json({
    error: err.message || 'Error interno del servidor'
  });
});

app.listen(PORT, () => {
  console.log(`ShieldScan corriendo en http://localhost:${PORT}`);
  console.log(`Uploads: ${UPLOAD_DIR}`);
  console.log(`Quarantine: ${QUARANTINE_DIR}`);
});

module.exports = app;
