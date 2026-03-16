const multer = require('multer');
const path = require('path');

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

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

function createUploadMiddleware(uploadDir) {
  const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
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

  return function withUpload(req, res, next) {
    upload.single('file')(req, res, (err) => {
      if (!err) return next();
      if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
        return next(Object.assign(new Error('Archivo demasiado grande. Maximo permitido: 10MB'), { statusCode: 413 }));
      }
      return next(Object.assign(err, { statusCode: 400 }));
    });
  };
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

module.exports = {
  MAX_FILE_SIZE,
  ALLOWED_EXTENSIONS,
  ALLOWED_TYPES,
  createUploadMiddleware,
  validateFileIdParam,
  validateScanIdParam
};
