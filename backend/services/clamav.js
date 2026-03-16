const NodeClam = require('clamscan');

// Instancia singleton de NodeClam. Permanece null hasta que
// initClamAV() se ejecuta correctamente al arrancar el servidor.
let clamscan = null;

// ---------------------------------------------------------------------------
// initClamAV
// Conecta con el daemon clamd y configura NodeClam.
// Debe llamarse UNA sola vez al inicio del servidor antes de aceptar escaneos.
// ---------------------------------------------------------------------------
async function initClamAV() {
  clamscan = await new NodeClam().init({
    removeInfected: false,      // NO eliminar el archivo infectado automaticamente
    quarantineInfected: false,  // La cuarentena la gestiona runScanJob en server.js
    scanRecursively: false,     // Solo escanear el archivo indicado, sin subdirectorios
    clamdscan: {
      socket: false,                               // Usar TCP en lugar de socket Unix
      host: process.env.CLAMD_HOST || '127.0.0.1', // Host del daemon (configurable por env)
      port: Number(process.env.CLAMD_PORT || 3310), // Puerto del daemon (default: 3310)
      active: true                                 // Habilitar el modo clamdscan
    },
    preference: 'clamdscan'  // Usar el daemon en lugar del binario clamscan
  });

  return clamscan;
}

// ---------------------------------------------------------------------------
// isReady
// Indica si el daemon ya fue inicializado. Se usa como guarda en runScanJob
// para rechazar escaneos si clamd no esta disponible.
// ---------------------------------------------------------------------------
function isReady() {
  return Boolean(clamscan);
}

// ---------------------------------------------------------------------------
// scanFile
// Envia el archivo al daemon clamd para su analisis.
// Retorna: { isInfected: boolean, viruses: string[] }
//   - isInfected: true si se detecto alguna amenaza
//   - viruses:    lista de nombres de virus detectados (vacia si esta limpio)
// ---------------------------------------------------------------------------
async function scanFile(filePath) {
  if (!clamscan) {
    throw new Error('ClamAV no inicializado');
  }

  // clamscan.isInfected() envia el archivo a clamd por TCP y retorna el resultado
  return clamscan.isInfected(filePath);
}

// ---------------------------------------------------------------------------
// getVersion
// Consulta la version del daemon clamd. Se expone en GET /api/health
// para verificar que el servicio esta operativo.
// ---------------------------------------------------------------------------
async function getVersion() {
  if (!clamscan) {
    throw new Error('ClamAV no inicializado');
  }

  const version = await clamscan.getVersion();
  return version.trim();
}

module.exports = {
  initClamAV,
  isReady,
  scanFile,
  getVersion
};
