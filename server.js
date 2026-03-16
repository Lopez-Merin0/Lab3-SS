// =====================================================
//  ShieldScan — Backend API con ClamAV
//  Node.js + Express + Multer + clamscan
// =====================================================
//  INSTALACIÓN:
//    npm install express multer clamscan crypto-js cors dotenv
//    sudo apt install clamav clamav-daemon   (Linux)
//    sudo freshclam                           (actualizar definiciones)
//    sudo systemctl start clamav-daemon
// =====================================================

const express    = require('express');
const multer     = require('multer');
const NodeClam   = require('clamscan');
const crypto     = require('crypto');
const path       = require('path');
const fs         = require('fs');
const cors       = require('cors');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Middlewares ──────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static('public'));   // sirve index.html

// ── Directorios ──────────────────────────────────────
const UPLOAD_DIR     = path.join(__dirname, 'uploads');
const QUARANTINE_DIR = path.join(__dirname, 'quarantine');
[UPLOAD_DIR, QUARANTINE_DIR].forEach(d => fs.mkdirSync(d, { recursive: true }));

// ── Multer (almacenamiento de archivos) ──────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename:    (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname));
  }
});

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

const ALLOWED_EXTENSIONS = [
  '.pdf', '.doc', '.docx', '.xls', '.xlsx',
  '.txt', '.jpg', '.jpeg', '.png', '.gif',
  '.zip', '.rar', '.7z', '.exe'
];

const ALLOWED_TYPES = {
  'application/pdf':            '📄 PDF',
  'application/msword':         '📝 Word',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '📝 Word',
  'application/vnd.ms-excel':   '📊 Excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '📊 Excel',
  'text/plain':                 '📃 Texto',
  'image/jpeg':                 '🖼 JPEG',
  'image/png':                  '🖼 PNG',
  'image/gif':                  '🖼 GIF',
  'application/zip':            '🗜 ZIP',
  'application/x-rar-compressed': '🗜 RAR',
  'application/x-7z-compressed':  '🗜 7-Zip',
  'application/x-msdownload':   '⚙ EXE',
};

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (req, file, cb) => {
    const name = file.originalname.toLowerCase();
    const ext  = path.extname(name);

    // Validar extensión
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      return cb(new Error(`Extensión no permitida: ${ext || 'sin extensión'}`));
    }

    // Validar MIME type
    if (!ALLOWED_TYPES[file.mimetype]) {
      return cb(new Error(`Tipo de archivo no permitido: ${file.mimetype}`));
    }

    cb(null, true);
  }
});


// ── Inicializar ClamAV ───────────────────────────────
let clamscan;
(async () => {
  clamscan = await new NodeClam().init({
    removeInfected: false,          // nosotros gestionamos la cuarentena
    quarantineInfected: false,
    scanRecursively: false,
    clamdscan: {
      socket: false,
      host: '127.0.0.1',
      port: 3310,
      active: true,
    },
    preference: 'clamdscan',        // usa el daemon para mayor velocidad
  });
  console.log('✅ ClamAV inicializado');
})();

// ── Utilidades ───────────────────────────────────────
function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash   = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', d => hash.update(d));
    stream.on('end',  ()  => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(2) + ' MB';
}

// ── Almacén en memoria de escaneos (demo) ────────────
// En producción usar Redis o PostgreSQL
const scanResults = new Map();

// ═══════════════════════════════════════════════════
//  RUTAS API
// ═══════════════════════════════════════════════════

// ── GET /api/health ───────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    const version = await clamscan.getVersion();
    res.json({
      status:    'ok',
      clamd:     'running',
      version:   version.trim(),
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(503).json({ status: 'error', message: err.message });
  }
});

// ── POST /api/scan ─────────────────────────────────
app.post('/api/scan', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No se recibió ningún archivo' });
  }

  const filePath  = req.file.path;
  const scanId    = 'scan_' + Date.now();
  const startTime = Date.now();

  try {
    // 1. Calcular hash
    const sha256 = await sha256File(filePath);

    // 2. Escanear con ClamAV
    const { isInfected, viruses } = await clamscan.isInfected(filePath);

    const duration   = ((Date.now() - startTime) / 1000).toFixed(2);
    const scannedAt  = new Date().toISOString();

    let action = 'none';

    if (isInfected) {
      // Mover a cuarentena
      const quarPath = path.join(QUARANTINE_DIR, path.basename(filePath));
      fs.renameSync(filePath, quarPath);
      action = 'quarantined';
      console.warn(`🚨 INFECTADO: ${req.file.originalname} → ${viruses}`);
    } else {
      // Eliminar archivo limpio después del escaneo
      fs.unlinkSync(filePath);
      console.log(`✅ LIMPIO: ${req.file.originalname}`);
    }

    const result = {
      id:           scanId,
      status:       isInfected ? 'infected' : 'clean',
      filetype:     ALLOWED_TYPES[req.file.mimetype] || 'Desconocido',
      filename:     req.file.originalname,
      size:         req.file.size,
      sizeFormatted: formatBytes(req.file.size),
      mimetype:     req.file.mimetype,
      sha256,
      threats:      isInfected ? viruses : [],
      action,
      scanDuration: duration,
      scannedAt,
    };

    scanResults.set(scanId, result);
    res.json(result);

  } catch (err) {
    // Limpiar archivo en caso de error
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    console.error('Error de escaneo:', err);
    res.status(500).json({ error: 'Error al escanear el archivo', detail: err.message });
  }
});

// ── GET /api/scan/:id ──────────────────────────────
app.get('/api/scan/:id', (req, res) => {
  const result = scanResults.get(req.params.id);
  if (!result) {
    return res.status(404).json({ error: 'Escaneo no encontrado' });
  }
  res.json(result);
});

// ── GET /api/scans ─────────────────────────────────
app.get('/api/scans', (req, res) => {
  const list = Array.from(scanResults.values())
    .sort((a, b) => new Date(b.scannedAt) - new Date(a.scannedAt))
    .slice(0, 50); // últimos 50
  res.json({ total: list.length, scans: list });
});

// ── DELETE /api/file/:id ───────────────────────────
app.delete('/api/file/:id', (req, res) => {
  const result = scanResults.get(req.params.id);
  if (!result) return res.status(404).json({ error: 'No encontrado' });

  // Si está en cuarentena, eliminar permanentemente
  if (result.action === 'quarantined') {
    const quarPath = path.join(QUARANTINE_DIR, result.id);
    if (fs.existsSync(quarPath)) fs.unlinkSync(quarPath);
  }

  scanResults.delete(req.params.id);
  res.json({ deleted: true, id: req.params.id });
});

// ── Manejo de errores de Multer ────────────────────
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ 
      error: `Archivo demasiado grande. Máximo permitido: 10MB` 
    });
  }
  res.status(400).json({ error: err.message });
});

// ── Iniciar servidor ───────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 ShieldScan corriendo en http://localhost:${PORT}`);
  console.log(`   Directorio de uploads:    ${UPLOAD_DIR}`);
  console.log(`   Directorio de cuarentena: ${QUARANTINE_DIR}`);
});

module.exports = app;
